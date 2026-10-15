// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Interface access control: "ip access-group NAME in|out".
 *
 * The entries of the extended access-list become tc flower filters on the
 * ingress or egress hook of a clsact qdisc: "permit" entries accept the
 * packet (gact pass), "deny" entries drop it (gact drop), the first
 * matching entry decides.  Like a Cisco IPv4 (ip access-group) and IPv6
 * (ipv6 traffic-filter) access-list, the list ends with an implicit deny
 * of the IP families it has entries for; other traffic not matched by
 * any entry is accepted.
 *
 * Layout per direction, so that a changed access-list replaces the old
 * one atomically:
 *
 *   chain 0, pref 1 (handle 0xbeef):  protocol all, goto chain A|B
 *   chain A or B:                     the entries, then the implicit denies
 *
 * A new version is written to the unused chain, then the chain 0 filter
 * is replaced to jump to it and the old chain is flushed: packets always
 * see either the complete old or the complete new rules.
 *
 * The clsact qdisc itself is never removed, other tools may use it too.
 *
 * Copyright (C) 2026 FRRouting
 */

#include <zebra.h>

#include <netinet/if_ether.h>
#include <linux/pkt_cls.h>

#include "command.h"
#include "if.h"
#include "json.h"
#include "linklist.h"
#include "memory.h"
#include "tc.h"
#include "vrf.h"

#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_acl_ext.h"
#include "zebra/zebra_acl_flower.h"
#include "zebra/zebra_acl_group.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_qos.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_tc.h"

#include "zebra/zebra_acl_group_clippy.c"

DEFINE_MTYPE_STATIC(ZEBRA, ACL_GROUP_HW, "Access-group kernel state");

/* clsact qdisc and its two filter hooks */
#define ACLG_CLSACT_HANDLE 0xffff0000u
#define ACLG_CLSACT_PARENT 0xfffffff1u
static const uint32_t aclg_parent[ACLG_DIRS] = {
	[ACLG_IN] = 0xfffffff2u,
	[ACLG_OUT] = 0xfffffff3u,
};

/* chains holding the rules; must fit the 28 bits of "goto chain" */
#define ACLG_CHAIN_A 0x0bee0001u
#define ACLG_CHAIN_B 0x0bee0002u

/* the chain 0 filter jumping to the active chain */
#define ACLG_DISPATCH_PRIO   1
#define ACLG_DISPATCH_HANDLE 0xbeef

/* filter preferences available in a chain */
#define ACLG_MAX_FILTERS 0xfff0

#define ACLG_MATCH_LEN (ACLX_TEXT_MAX + 128)

static const char *const aclg_dir_name[ACLG_DIRS] = {
	[ACLG_IN] = "in",
	[ACLG_OUT] = "out",
};

/* What produced a filter, for show output */
struct aclg_finfo {
	/* 0 for the implicit denies */
	uint32_t seq;
	bool permit;
	char match[ACLG_MATCH_LEN];
};

/* One version of the filters of an access-group (interface and direction) */
struct aclg_hw {
	ifindex_t ifindex;
	enum aclg_dir dir;
	char acl[QOS_ACL_NAME_LEN];

	/*
	 * Chain and filter handle used in the kernel.  The filters below
	 * have chain and handle 0, so that versions can be compared.  The
	 * handle differs between attempts, to recognize the results of an
	 * attempt that was abandoned.
	 */
	uint32_t chain;
	uint32_t handle;

	struct tc_filter *filters;
	struct aclg_finfo *finfo;
	unsigned int nfilters;
	unsigned int size;

	/* while being installed: results still expected, first refused filter */
	unsigned int outstanding;
	unsigned int failed_pref;
};

/* Per interface and direction */
struct aclg_state {
	/* in force: the dispatch filter jumps to its chain */
	struct aclg_hw *active;
	/* phase 1: written to the other chain, waiting for the kernel's answers */
	struct aclg_hw *pending;
	/* phase 2: all filters accepted, the dispatch filter is being switched */
	struct aclg_hw *switching;
	/* the last version the kernel refused, for show */
	struct aclg_hw *rejected;

	/*
	 * Filters a previous zebra left: stale is set when the interface had
	 * a clsact qdisc at startup, stale_chain is the chain they are in (0
	 * if there are none).  They stay in force until they are replaced,
	 * or the access-group is found not configured after the startup hold
	 * time.  stale_unknown: the chain in force could not be determined.
	 */
	bool stale;
	bool stale_unknown;
	uint32_t stale_chain;

	/* the configuration changed while switching, apply again afterwards */
	bool reapply;

	uint32_t next_handle;

	/* why the access-group is not (completely) in force, empty if it is */
	char reason[ACLG_MATCH_LEN + 320];
	/* the configured access-list cannot be installed, empty if it can */
	char config_error[320];
};

enum aclg_build_result {
	/* nothing to install: no access-group, or nothing to filter */
	ACLG_BUILD_NONE,
	/* the access-list cannot be installed, keep what is there */
	ACLG_BUILD_ERROR,
	ACLG_BUILD_OK,
};

/* interfaces with a clsact qdisc at startup, not looked at yet */
static struct {
	ifindex_t *ifindex;
	unsigned int n, size;
} aclg_stale;

/*
 * The configuration reaches zebra from mgmtd some time after startup:
 * filters of a previous run are only removed from interfaces without an
 * access-group once this hold time is over.
 */
#define ACLG_STALE_HOLD_SECONDS 60
static bool aclg_hold = true;
static struct event *aclg_t_hold;

static void aclg_hw_free(struct aclg_hw **hw)
{
	if (!*hw)
		return;

	XFREE(MTYPE_ACL_GROUP_HW, (*hw)->filters);
	XFREE(MTYPE_ACL_GROUP_HW, (*hw)->finfo);
	XFREE(MTYPE_ACL_GROUP_HW, *hw);
}

static struct aclg_state *aclg_state_get(struct zebra_if_qos *qos, enum aclg_dir dir)
{
	if (!qos->acl_state[dir]) {
		qos->acl_state[dir] = XCALLOC(MTYPE_ACL_GROUP_HW, sizeof(struct aclg_state));
		qos->acl_state[dir]->next_handle = 1;
	}

	return qos->acl_state[dir];
}

/* Forget everything, the kernel state is gone */
static void aclg_state_reset(struct aclg_state *st)
{
	aclg_hw_free(&st->active);
	aclg_hw_free(&st->pending);
	aclg_hw_free(&st->switching);
	aclg_hw_free(&st->rejected);
	st->stale = false;
	st->stale_unknown = false;
	st->stale_chain = 0;
	st->reapply = false;
}

static void aclg_state_free(struct aclg_state **st)
{
	if (!*st)
		return;

	aclg_state_reset(*st);
	XFREE(MTYPE_ACL_GROUP_HW, *st);
}

/* A new rule filter at the end of the list, NULL when the chain is full */
static struct tc_filter *aclg_filter_new(struct aclg_hw *hw, uint32_t seq, bool permit,
					 uint16_t proto, const char *match)
{
	struct tc_filter *f;
	struct aclg_finfo *fi;

	if (hw->nfilters >= ACLG_MAX_FILTERS)
		return NULL;

	if (hw->nfilters == hw->size) {
		hw->size = hw->size ? hw->size * 2 : 16;
		hw->filters = XREALLOC(MTYPE_ACL_GROUP_HW, hw->filters,
				       hw->size * sizeof(*hw->filters));
		hw->finfo = XREALLOC(MTYPE_ACL_GROUP_HW, hw->finfo, hw->size * sizeof(*hw->finfo));
	}

	f = &hw->filters[hw->nfilters];
	fi = &hw->finfo[hw->nfilters];
	hw->nfilters++;

	/* zeroed so that whole structures can be compared with memcmp */
	memset(f, 0, sizeof(*f));
	memset(fi, 0, sizeof(*fi));

	f->ifindex = hw->ifindex;
	f->parent = aclg_parent[hw->dir];
	f->priority = hw->nfilters;
	f->protocol = proto;
	f->kind = TC_FILTER_FLOWER;
	f->u.flower.filter_bm = permit ? TC_FLOWER_ACT_PASS : TC_FLOWER_ACT_DROP;

	fi->seq = seq;
	fi->permit = permit;
	strlcpy(fi->match, match, sizeof(fi->match));

	return f;
}

static enum aclg_build_result aclg_build(struct interface *ifp, struct zebra_if_qos *qos,
					 enum aclg_dir dir, struct aclg_hw **out, char *reason,
					 size_t reason_len)
{
	static struct aclx_flower fl[ACLX_FLOWER_MAX_FILTERS];
	const char *name = qos->access_group[dir];
	const struct qos_acl_ext *acl;
	const struct qos_acl_ext_entry *entry;
	struct listnode *node;
	struct aclg_hw *hw;
	bool v4 = false, v6 = false;
	char err[128];

	*out = NULL;
	reason[0] = '\0';

	if (!name[0])
		return ACLG_BUILD_NONE;

	if (ifp->ifindex == IFINDEX_INTERNAL) {
		strlcpy(reason, "interface does not exist", reason_len);
		return ACLG_BUILD_NONE;
	}

	/* like Cisco, an undefined or empty access-list permits everything */
	acl = zebra_qos_acl_ext_lookup(name);
	if (!acl) {
		snprintf(reason, reason_len,
			 "ip access-list extended %s is not configured, everything is permitted",
			 name);
		return ACLG_BUILD_NONE;
	}

	hw = XCALLOC(MTYPE_ACL_GROUP_HW, sizeof(*hw));
	hw->ifindex = ifp->ifindex;
	hw->dir = dir;
	strlcpy(hw->acl, name, sizeof(hw->acl));

	for (ALL_LIST_ELEMENTS_RO(acl->entries, node, entry)) {
		int n;

		if (!entry->rule || !(entry->permit || entry->deny))
			continue;

		if (aclx_rule_is_ip(entry->rule)) {
			if (aclx_rule_inner_ethertype(entry->rule) == ACLX_ETH_P_IPV6)
				v6 = true;
			else
				v4 = true;
		}

		n = aclx_flower_encode(entry->rule, 0, 0, fl, array_size(fl), err, sizeof(err));
		if (n < 0) {
			snprintf(reason, reason_len, "ip access-list extended %s seq %u: %s", name,
				 entry->seq, err);
			aclg_hw_free(&hw);
			return ACLG_BUILD_ERROR;
		}

		for (int i = 0; i < n; i++) {
			char match[ACLG_MATCH_LEN];
			struct tc_filter *f;

			if (fl[i].desc[0])
				snprintf(match, sizeof(match), "%s {%s}", entry->match, fl[i].desc);
			else
				strlcpy(match, entry->match, sizeof(match));

			f = aclg_filter_new(hw, entry->seq, entry->permit, fl[i].eth_proto, match);
			if (!f) {
				snprintf(reason, reason_len,
					 "ip access-list extended %s needs more than %u filters",
					 name, ACLG_MAX_FILTERS);
				aclg_hw_free(&hw);
				return ACLG_BUILD_ERROR;
			}
			SET_FLAG(f->u.flower.filter_bm, TC_FLOWER_RAW_KEYS);
			f->u.flower.raw_len = fl[i].len;
			memcpy(f->u.flower.raw, fl[i].raw, fl[i].len);
		}
	}

	if (!hw->nfilters) {
		snprintf(reason, reason_len,
			 "ip access-list extended %s has no entries, everything is permitted",
			 name);
		aclg_hw_free(&hw);
		return ACLG_BUILD_NONE;
	}

	/* implicit deny of the IP families the access-list is about */
	if ((v4 && !aclg_filter_new(hw, 0, false, ETH_P_IP, "implicit deny ip")) ||
	    (v6 && !aclg_filter_new(hw, 0, false, ETH_P_IPV6, "implicit deny ipv6"))) {
		snprintf(reason, reason_len,
			 "ip access-list extended %s needs more than %u filters", name,
			 ACLG_MAX_FILTERS);
		aclg_hw_free(&hw);
		return ACLG_BUILD_ERROR;
	}

	*out = hw;
	return ACLG_BUILD_OK;
}

static bool aclg_hw_equal(const struct aclg_hw *a, const struct aclg_hw *b)
{
	if (a->ifindex != b->ifindex || a->dir != b->dir || a->nfilters != b->nfilters ||
	    strcmp(a->acl, b->acl))
		return false;

	for (unsigned int i = 0; i < a->nfilters; i++) {
		if (memcmp(&a->filters[i], &b->filters[i], sizeof(a->filters[i])) ||
		    a->finfo[i].seq != b->finfo[i].seq ||
		    strcmp(a->finfo[i].match, b->finfo[i].match))
			return false;
	}

	return true;
}

/*
 * ----------------------------------------------------------------------
 * Kernel programming
 * ----------------------------------------------------------------------
 */

static void aclg_clsact_ensure(ifindex_t ifindex)
{
	struct zebra_tc_qdisc qdisc = {};

	qdisc.qdisc.ifindex = ifindex;
	qdisc.qdisc.kind = TC_QDISC_CLSACT;
	qdisc.qdisc.handle = ACLG_CLSACT_HANDLE;
	qdisc.qdisc.parent = ACLG_CLSACT_PARENT;
	(void)dplane_tc_qdisc_install(&qdisc);
}

/* Delete every filter of a chain (pref, protocol and handle 0) */
static void aclg_chain_flush(ifindex_t ifindex, enum aclg_dir dir, uint32_t chain)
{
	struct zebra_tc_filter zf = {};

	zf.filter.ifindex = ifindex;
	zf.filter.parent = aclg_parent[dir];
	zf.filter.chain = chain;
	zf.filter.kind = TC_FILTER_FLOWER;
	(void)dplane_tc_filter_delete(&zf);
}

static void aclg_dispatch_fill(struct zebra_tc_filter *zf, ifindex_t ifindex, enum aclg_dir dir)
{
	memset(zf, 0, sizeof(*zf));
	zf->filter.ifindex = ifindex;
	zf->filter.parent = aclg_parent[dir];
	zf->filter.chain = 0;
	zf->filter.priority = ACLG_DISPATCH_PRIO;
	zf->filter.handle = ACLG_DISPATCH_HANDLE;
	zf->filter.protocol = ETH_P_ALL;
	zf->filter.kind = TC_FILTER_FLOWER;
}

/* Point the chain 0 filter at @chain, replacing it if it exists */
static void aclg_dispatch_set(ifindex_t ifindex, enum aclg_dir dir, uint32_t chain)
{
	struct zebra_tc_filter zf;

	aclg_dispatch_fill(&zf, ifindex, dir);
	zf.filter.u.flower.filter_bm = TC_FLOWER_ACT_GOTO_CHAIN;
	zf.filter.u.flower.goto_chain = chain;
	/*
	 * NEWTFILTER without NLM_F_EXCL changes an existing filter in place
	 * (dplane "update" would delete and re-add it, briefly letting
	 * everything through).
	 */
	(void)dplane_tc_filter_add(&zf);
}

static void aclg_dispatch_del(ifindex_t ifindex, enum aclg_dir dir)
{
	struct zebra_tc_filter zf;

	aclg_dispatch_fill(&zf, ifindex, dir);
	(void)dplane_tc_filter_delete(&zf);
}

/* Remove everything zebra may have on this hook */
static void aclg_remove_all(ifindex_t ifindex, enum aclg_dir dir)
{
	aclg_dispatch_del(ifindex, dir);
	aclg_chain_flush(ifindex, dir, ACLG_CHAIN_A);
	aclg_chain_flush(ifindex, dir, ACLG_CHAIN_B);
}

static const char *aclg_keeping(const struct aclg_state *st)
{
	if (st->active)
		return "still using the previous version";
	if (st->stale)
		return "still using the filters of the previous zebra run";
	return "the access-list is not in force";
}

/* Phase 1: write the rules to the chain not in use, results are counted */
static void aclg_start(struct aclg_state *st, struct aclg_hw *hw)
{
	uint32_t in_use = st->active ? st->active->chain : st->stale_chain;

	hw->chain = in_use == ACLG_CHAIN_A ? ACLG_CHAIN_B : ACLG_CHAIN_A;
	hw->handle = st->next_handle++;
	if (!st->next_handle || st->next_handle == ACLG_DISPATCH_HANDLE)
		st->next_handle = ACLG_DISPATCH_HANDLE + 1;
	hw->outstanding = hw->nfilters;
	hw->failed_pref = 0;

	if (IS_ZEBRA_DEBUG_TC)
		zlog_debug("%s: ifindex %d %s: access-list %s, %u filters to chain 0x%x", __func__,
			   hw->ifindex, aclg_dir_name[hw->dir], hw->acl, hw->nfilters, hw->chain);

	aclg_clsact_ensure(hw->ifindex);
	aclg_chain_flush(hw->ifindex, hw->dir, hw->chain);

	for (unsigned int i = 0; i < hw->nfilters; i++) {
		struct zebra_tc_filter zf = {};

		zf.filter = hw->filters[i];
		zf.filter.chain = hw->chain;
		zf.filter.handle = hw->handle;
		(void)dplane_tc_filter_add(&zf);
	}

	st->pending = hw;
}

static void aclg_refused(struct aclg_state *st, struct aclg_hw *hw, const char *what)
{
	snprintf(st->reason, sizeof(st->reason), "the kernel refused %s of %s, %s", what, hw->acl,
		 aclg_keeping(st));
	zlog_warn("ifindex %d %s: %s", hw->ifindex, aclg_dir_name[hw->dir], st->reason);
	aclg_chain_flush(hw->ifindex, hw->dir, hw->chain);
	aclg_hw_free(&st->rejected);
	st->rejected = hw;
}

static void aclg_reapply_if_needed(struct aclg_state *st)
{
	if (st->reapply) {
		st->reapply = false;
		zebra_qos_config_changed();
	}
}

/* Phase 1 done, all filters answered: switch the dispatch filter, or discard */
static void aclg_rules_done(struct aclg_state *st)
{
	struct aclg_hw *hw = st->pending;

	st->pending = NULL;

	if (hw->failed_pref) {
		const struct aclg_finfo *fi = &hw->finfo[hw->failed_pref - 1];
		char what[ACLG_MATCH_LEN + 64], seq[16];

		if (fi->seq)
			snprintf(seq, sizeof(seq), "seq %u ", fi->seq);
		else
			seq[0] = '\0';
		snprintf(what, sizeof(what), "filter %u (%s%s %s)", hw->failed_pref, seq,
			 fi->permit ? "permit" : "deny", fi->match);
		aclg_refused(st, hw, what);
		return;
	}

	if (IS_ZEBRA_DEBUG_TC)
		zlog_debug("%s: ifindex %d %s: switching to access-list %s (chain 0x%x)", __func__,
			   hw->ifindex, aclg_dir_name[hw->dir], hw->acl, hw->chain);

	/* the old rules stay until the kernel confirmed the switch */
	aclg_dispatch_set(hw->ifindex, hw->dir, hw->chain);
	st->switching = hw;
}

/* Phase 2 done: the dispatch filter jumps to the new chain, or not */
static void aclg_switch_done(struct aclg_state *st, bool ok)
{
	struct aclg_hw *hw = st->switching;

	st->switching = NULL;

	if (!ok) {
		/* e.g. a filter of another tool with a different protocol at pref 1 */
		aclg_refused(st, hw, "the chain 0 dispatch filter");
		aclg_reapply_if_needed(st);
		return;
	}

	if (IS_ZEBRA_DEBUG_TC)
		zlog_debug("%s: ifindex %d %s: access-list %s in force (chain 0x%x)", __func__,
			   hw->ifindex, aclg_dir_name[hw->dir], hw->acl, hw->chain);

	if (st->active) {
		aclg_chain_flush(hw->ifindex, hw->dir, st->active->chain);
		aclg_hw_free(&st->active);
	} else if (st->stale) {
		aclg_chain_flush(hw->ifindex, hw->dir,
				 hw->chain == ACLG_CHAIN_A ? ACLG_CHAIN_B : ACLG_CHAIN_A);
		st->stale = false;
		st->stale_unknown = false;
		st->stale_chain = 0;
	}

	st->active = hw;
	st->reason[0] = '\0';
	aclg_hw_free(&st->rejected);
	aclg_reapply_if_needed(st);
}

/* Give up a version being written, its results will be ignored */
static void aclg_abandon(struct aclg_state *st)
{
	if (!st->pending)
		return;

	aclg_chain_flush(st->pending->ifindex, st->pending->dir, st->pending->chain);
	aclg_hw_free(&st->pending);
}

struct aclg_dispatch_find {
	bool found;
	bool target_known;
	uint32_t chain;
	unsigned int in_a, in_b;
};

static void aclg_dispatch_find_cb(const struct zebra_tc_filter_stats *st, void *arg)
{
	struct aclg_dispatch_find *df = arg;

	if (st->chain == ACLG_CHAIN_A)
		df->in_a++;
	else if (st->chain == ACLG_CHAIN_B)
		df->in_b++;

	if (st->chain != 0 || st->priority != ACLG_DISPATCH_PRIO ||
	    st->handle != ACLG_DISPATCH_HANDLE)
		return;

	df->found = true;
	if (st->gact_valid && TC_ACT_EXT_CMP(st->gact_action, TC_ACT_GOTO_CHAIN)) {
		df->chain = st->gact_action & TC_ACT_EXT_VAL_MASK;
		df->target_known = true;
	}
}

static bool aclg_stale_take(ifindex_t ifindex)
{
	for (unsigned int i = 0; i < aclg_stale.n; i++) {
		if (aclg_stale.ifindex[i] == ifindex) {
			aclg_stale.ifindex[i] = aclg_stale.ifindex[--aclg_stale.n];
			return true;
		}
	}

	return false;
}

/*
 * Which chain the filters of a previous run are in, so that a new version
 * does not overwrite them while they are in force.
 */
static void aclg_stale_locate(struct aclg_state *st, ifindex_t ifindex, enum aclg_dir dir)
{
	struct aclg_dispatch_find df = {};

	st->stale_unknown = false;
	st->stale_chain = 0;

	if (kernel_tc_filter_stats(ifindex, aclg_parent[dir], aclg_dispatch_find_cb, &df)) {
		st->stale_unknown = true;
		return;
	}

	if (df.found && df.target_known)
		st->stale_chain = df.chain;
	else if (df.in_a && !df.in_b)
		st->stale_chain = ACLG_CHAIN_A;
	else if (df.in_b && !df.in_a)
		st->stale_chain = ACLG_CHAIN_B;
	else if (df.in_a && df.in_b)
		st->stale_unknown = true;
	/* else: no rules, nothing to protect */
}

/* Take over what a previous zebra left on this interface */
static void aclg_adopt_stale(struct zebra_if_qos *qos, ifindex_t ifindex)
{
	for (int dir = 0; dir < ACLG_DIRS; dir++) {
		struct aclg_state *st = aclg_state_get(qos, dir);

		st->stale = true;
		aclg_stale_locate(st, ifindex, dir);
	}
}

static void aclg_if_apply_dir(struct interface *ifp, struct zebra_if_qos *qos, enum aclg_dir dir)
{
	struct aclg_state *st = aclg_state_get(qos, dir);
	struct aclg_hw *hw;
	char kind[16];

	/* the interface was re-created, the kernel state went with the old one */
	if ((st->active && st->active->ifindex != ifp->ifindex) ||
	    (st->pending && st->pending->ifindex != ifp->ifindex) ||
	    (st->switching && st->switching->ifindex != ifp->ifindex) ||
	    (st->rejected && st->rejected->ifindex != ifp->ifindex))
		aclg_state_reset(st);

	st->config_error[0] = '\0';

	switch (aclg_build(ifp, qos, dir, &hw, st->config_error, sizeof(st->config_error))) {
	case ACLG_BUILD_NONE:
		/* nothing to install: the note says why (or nothing is configured) */
		strlcpy(st->reason, st->config_error, sizeof(st->reason));
		st->config_error[0] = '\0';

		if (st->switching) {
			/* undo once the switch completed */
			st->reapply = true;
			return;
		}
		aclg_abandon(st);
		if (st->active) {
			if (IS_ZEBRA_DEBUG_TC)
				zlog_debug("%s: ifindex %d %s: removing access-list %s", __func__,
					   st->active->ifindex, aclg_dir_name[dir],
					   st->active->acl);
			aclg_dispatch_del(st->active->ifindex, dir);
			aclg_chain_flush(st->active->ifindex, dir, st->active->chain);
		} else if (st->stale) {
			/* the configuration may not have arrived yet */
			if (aclg_hold) {
				snprintf(st->reason, sizeof(st->reason),
					 "filters of the previous zebra run kept until the configuration is complete");
				return;
			}
			if (ifp->ifindex != IFINDEX_INTERNAL)
				aclg_remove_all(ifp->ifindex, dir);
		}
		aclg_state_reset(st);
		return;

	case ACLG_BUILD_ERROR:
		/* fail safe: keep filtering with the rules in place */
		return;

	case ACLG_BUILD_OK:
		break;
	}

	if (st->switching) {
		/* both chains are in use: apply again once the switch is done */
		if (!aclg_hw_equal(st->switching, hw))
			st->reapply = true;
		aclg_hw_free(&hw);
		return;
	}

	if (st->pending) {
		if (aclg_hw_equal(st->pending, hw)) {
			aclg_hw_free(&hw);
			return;
		}
		aclg_abandon(st);
	} else if (st->active && aclg_hw_equal(st->active, hw)) {
		aclg_hw_free(&hw);
		aclg_hw_free(&st->rejected);
		st->reason[0] = '\0';
		return;
	}

	/* do not retry a version the kernel refused, until it changes */
	if (st->rejected && aclg_hw_equal(st->rejected, hw)) {
		aclg_hw_free(&hw);
		return;
	}

	/* never overwrite the chain the filters of a previous run are in */
	if (!st->active && st->stale && st->stale_unknown) {
		aclg_stale_locate(st, ifp->ifindex, dir);
		if (st->stale_unknown) {
			snprintf(st->reason, sizeof(st->reason),
				 "cannot tell which chain the filters of the previous zebra run are in, %s",
				 aclg_keeping(st));
			aclg_hw_free(&hw);
			return;
		}
	}

	/*
	 * An ingress qdisc has the same handle as clsact: zebra cannot add
	 * clsact, and filters for either hook would end up on it.
	 */
	if (kernel_tc_qdisc_kind(ifp->ifindex, ACLG_CLSACT_HANDLE, kind, sizeof(kind)) == 0 &&
	    strcmp(kind, "clsact")) {
		snprintf(st->reason, sizeof(st->reason),
			 "the interface has an \"%s\" qdisc (ffff:), access-groups need clsact, %s",
			 kind, aclg_keeping(st));
		aclg_hw_free(&hw);
		return;
	}

	/* the outcome is known when the kernel answered */
	st->reason[0] = '\0';
	aclg_start(st, hw);
}

void zebra_acl_group_if_apply(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_if_qos *qos;

	if (!zif || !zif->qos) {
		/* no configuration: zebra_acl_group_apply_done() removes stale filters */
		return;
	}
	qos = zif->qos;

	/* the startup state must be known, and stale filters adopted first */
	if (!zebra_qos_started()) {
		for (int dir = 0; dir < ACLG_DIRS; dir++)
			if (qos->access_group[dir][0])
				strlcpy(aclg_state_get(qos, dir)->reason,
					"waiting for zebra startup to complete",
					sizeof(qos->acl_state[dir]->reason));
		return;
	}

	if (ifp->ifindex != IFINDEX_INTERNAL && aclg_stale_take(ifp->ifindex))
		aclg_adopt_stale(qos, ifp->ifindex);

	for (int dir = 0; dir < ACLG_DIRS; dir++)
		aclg_if_apply_dir(ifp, qos, dir);
}

void zebra_acl_group_apply_done(void)
{
	if (!zebra_qos_started() || aclg_hold)
		return;

	/* clsact qdiscs of interfaces zebra has no QoS configuration for */
	for (unsigned int i = 0; i < aclg_stale.n; i++) {
		if (IS_ZEBRA_DEBUG_TC)
			zlog_debug("%s: ifindex %d: removing stale access-group filters", __func__,
				   aclg_stale.ifindex[i]);
		for (int dir = 0; dir < ACLG_DIRS; dir++)
			aclg_remove_all(aclg_stale.ifindex[i], dir);
	}
	aclg_stale.n = 0;
}

static void aclg_hold_expired(struct event *t)
{
	aclg_hold = false;
	zebra_qos_config_changed();
}

void zebra_acl_group_startup_done(void)
{
	event_add_timer(zrouter.master, aclg_hold_expired, NULL, ACLG_STALE_HOLD_SECONDS,
			&aclg_t_hold);
}

void zebra_acl_group_if_removed(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	if (!zif || !zif->qos)
		return;

	for (int dir = 0; dir < ACLG_DIRS; dir++)
		if (zif->qos->acl_state[dir])
			aclg_state_reset(zif->qos->acl_state[dir]);
}

void zebra_acl_group_if_fini(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	if (!zif || !zif->qos)
		return;

	for (int dir = 0; dir < ACLG_DIRS; dir++)
		aclg_state_free(&zif->qos->acl_state[dir]);
}

void zebra_acl_group_startup_clsact(ifindex_t ifindex)
{
	if (aclg_stale.n == aclg_stale.size) {
		aclg_stale.size = aclg_stale.size ? aclg_stale.size * 2 : 16;
		aclg_stale.ifindex = XREALLOC(MTYPE_ACL_GROUP_HW, aclg_stale.ifindex,
					      aclg_stale.size * sizeof(*aclg_stale.ifindex));
	}
	aclg_stale.ifindex[aclg_stale.n++] = ifindex;
}

static struct aclg_state *aclg_state_lookup(ifindex_t ifindex, enum aclg_dir dir)
{
	struct interface *ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT), ifindex);
	struct zebra_if *zif = ifp ? ifp->info : NULL;

	if (!zif || !zif->qos)
		return NULL;

	return zif->qos->acl_state[dir];
}

void zebra_acl_group_clsact_deleted(ifindex_t ifindex)
{
	bool had = false;

	for (int dir = 0; dir < ACLG_DIRS; dir++) {
		struct aclg_state *st = aclg_state_lookup(ifindex, dir);

		if (st && (st->active || st->pending || st->switching)) {
			aclg_state_reset(st);
			had = true;
		}
	}

	/* someone removed it under our feet: install again */
	if (had) {
		zlog_warn("%s: ifindex %d: clsact qdisc deleted, re-installing access-groups",
			  __func__, ifindex);
		zebra_qos_config_changed();
	}
}

void zebra_acl_group_dplane_result(struct zebra_dplane_ctx *ctx)
{
	uint32_t parent = dplane_ctx_tc_filter_get_parent(ctx);
	uint32_t chain = dplane_ctx_tc_filter_get_chain(ctx);
	uint32_t handle = dplane_ctx_tc_filter_get_handle(ctx);
	uint32_t prio = dplane_ctx_tc_filter_get_priority(ctx);
	bool ok = dplane_ctx_get_status(ctx) == ZEBRA_DPLANE_REQUEST_SUCCESS;
	struct aclg_state *st;
	struct aclg_hw *hw;
	enum aclg_dir dir;

	if (dplane_ctx_get_op(ctx) != DPLANE_OP_TC_FILTER_ADD)
		return;

	if (parent == aclg_parent[ACLG_IN])
		dir = ACLG_IN;
	else if (parent == aclg_parent[ACLG_OUT])
		dir = ACLG_OUT;
	else
		return;

	st = aclg_state_lookup(dplane_ctx_get_ifindex(ctx), dir);
	if (!st)
		return;

	if (chain == 0 && prio == ACLG_DISPATCH_PRIO && handle == ACLG_DISPATCH_HANDLE) {
		if (st->switching &&
		    dplane_ctx_tc_filter_get_goto_chain(ctx) == st->switching->chain)
			aclg_switch_done(st, ok);
		return;
	}

	hw = st->pending;
	if (!hw || chain != hw->chain || handle != hw->handle || !hw->outstanding)
		return;

	if (!ok && !hw->failed_pref)
		hw->failed_pref = prio;

	if (--hw->outstanding == 0)
		aclg_rules_done(st);
}

/*
 * ----------------------------------------------------------------------
 * Show
 * ----------------------------------------------------------------------
 */

struct aclg_show_stats {
	const struct aclg_hw *hw;
	struct zebra_tc_filter_stats *stats;
	bool *valid;
	bool *found;
	bool dispatch_found;
	uint32_t dispatch_chain;
};

static void aclg_stats_cb(const struct zebra_tc_filter_stats *st, void *arg)
{
	struct aclg_show_stats *ss = arg;
	const struct aclg_hw *hw = ss->hw;

	if (st->chain == 0 && st->priority == ACLG_DISPATCH_PRIO &&
	    st->handle == ACLG_DISPATCH_HANDLE) {
		ss->dispatch_found = true;
		if (st->gact_valid && TC_ACT_EXT_CMP(st->gact_action, TC_ACT_GOTO_CHAIN))
			ss->dispatch_chain = st->gact_action & TC_ACT_EXT_VAL_MASK;
		return;
	}

	if (st->chain != hw->chain || st->handle != hw->handle || !st->priority ||
	    st->priority > hw->nfilters)
		return;

	ss->stats[st->priority - 1] = *st;
	ss->valid[st->priority - 1] = st->stats_valid;
	ss->found[st->priority - 1] = true;
}

static const char *aclg_proto2str(uint16_t proto, char *buf, size_t len)
{
	switch (proto) {
	case ETH_P_IP:
		return "ipv4";
	case ETH_P_IPV6:
		return "ipv6";
	case ETH_P_ALL:
		return "all";
	case ETH_P_ARP:
		return "arp";
	case ETH_P_RARP:
		return "rarp";
	case ETH_P_8021Q:
		return "802.1Q";
	case ETH_P_8021AD:
		return "802.1ad";
	case ETH_P_MPLS_UC:
		return "mpls";
	case ETH_P_MPLS_MC:
		return "mpls-mc";
	case ETH_P_PPP_SES:
		return "pppoe";
	}

	snprintf(buf, len, "0x%04x", proto);
	return buf;
}

/*
 * The filters of one version.  With @ss (the active version) the kernel
 * counters are shown, @refused marks the filter the kernel refused.
 */
static void aclg_show_filters(struct vty *vty, const struct aclg_hw *hw,
			      const struct aclg_show_stats *ss, bool have_stats,
			      unsigned int refused, json_object *jfilters, unsigned int *missing)
{
	if (!jfilters)
		vty_out(vty, "      %-6s %-4s %-7s %-7s %-44s %-10s %s\n", "Seq", "Pref", "Action",
			"Proto", "Match", "Packets", "Bytes");

	for (unsigned int i = 0; i < hw->nfilters; i++) {
		const struct tc_filter *f = &hw->filters[i];
		const struct aclg_finfo *fi = &hw->finfo[i];
		char seq[16], pkts[24], bytes[24], pbuf[8];
		const char *action = fi->permit ? "permit" : "deny";
		const char *proto = aclg_proto2str(f->protocol, pbuf, sizeof(pbuf));
		bool valid = ss && ss->valid[i];

		if (jfilters) {
			json_object *jf = json_object_new_object();

			json_object_array_add(jfilters, jf);
			if (fi->seq)
				json_object_int_add(jf, "sequence", fi->seq);
			else
				json_object_boolean_add(jf, "implicit", true);
			json_object_int_add(jf, "pref", f->priority);
			json_object_string_add(jf, "action", action);
			json_object_string_add(jf, "protocol", proto);
			json_object_string_add(jf, "match", fi->match);
			if (ss && have_stats)
				json_object_boolean_add(jf, "inKernel", ss->found[i]);
			if (valid) {
				json_object_int_add(jf, "packets", ss->stats[i].packets);
				json_object_int_add(jf, "bytes", ss->stats[i].bytes);
			}
			if (refused == i + 1)
				json_object_boolean_add(jf, "refused", true);
			continue;
		}

		if (fi->seq)
			snprintf(seq, sizeof(seq), "%u", fi->seq);
		else
			snprintf(seq, sizeof(seq), "-");

		if (valid) {
			snprintf(pkts, sizeof(pkts), "%" PRIu64, ss->stats[i].packets);
			snprintf(bytes, sizeof(bytes), "%" PRIu64, ss->stats[i].bytes);
		} else if (refused == i + 1) {
			snprintf(pkts, sizeof(pkts), "refused");
			snprintf(bytes, sizeof(bytes), "-");
		} else if (ss && have_stats && !ss->found[i]) {
			snprintf(pkts, sizeof(pkts), "missing");
			snprintf(bytes, sizeof(bytes), "-");
			(*missing)++;
		} else {
			snprintf(pkts, sizeof(pkts), "-");
			snprintf(bytes, sizeof(bytes), "-");
		}

		vty_out(vty, "      %-6s %-4u %-7s %-7s %-44s %-10s %s\n", seq, f->priority,
			action, proto, fi->match, pkts, bytes);
	}
}

static void aclg_show_dir(struct vty *vty, struct zebra_if_qos *qos, enum aclg_dir dir,
			  json_object *json_if)
{
	const char *dirstr = dir == ACLG_IN ? "inbound" : "outbound";
	const struct aclg_state *st = qos->acl_state[dir];
	const struct aclg_hw *hw = st ? st->active : NULL;
	const char *state;
	struct aclg_show_stats ss = {};
	json_object *jd = NULL, *jfilters = NULL;
	bool have_stats = false;
	unsigned int missing = 0;

	if (hw)
		state = st->pending || st->switching ? "installed, new version being installed"
						     : "installed";
	else if (st && (st->pending || st->switching))
		state = "being installed";
	else if (st && st->stale)
		state = "filters of the previous zebra run in place";
	else
		state = "not installed";

	if (json_if) {
		jd = json_object_new_object();
		json_object_object_add(json_if, dirstr, jd);
		if (qos->access_group[dir][0])
			json_object_string_add(jd, "accessList", qos->access_group[dir]);
		json_object_boolean_add(jd, "installed", !!hw);
		json_object_string_add(jd, "state", state);
		if (st && st->reason[0])
			json_object_string_add(jd, "reason", st->reason);
		if (st && st->config_error[0])
			json_object_string_add(jd, "configError", st->config_error);
	} else {
		if (!qos->access_group[dir][0]) {
			vty_out(vty, "  %s%s access-list: not set\n", dir == ACLG_IN ? "I" : "O",
				dirstr + 1);
			return;
		}
		vty_out(vty, "  %s%s access-list %s: %s\n", dir == ACLG_IN ? "I" : "O", dirstr + 1,
			qos->access_group[dir], state);
		if (st && st->config_error[0])
			vty_out(vty, "    Note: the configured version cannot be installed: %s\n",
				st->config_error);
		if (st && st->reason[0])
			vty_out(vty, "    Note: %s\n", st->reason);
	}

	if (hw) {
		ss.hw = hw;
		ss.stats = XCALLOC(MTYPE_TMP, hw->nfilters * sizeof(*ss.stats));
		ss.valid = XCALLOC(MTYPE_TMP, hw->nfilters * sizeof(*ss.valid));
		ss.found = XCALLOC(MTYPE_TMP, hw->nfilters * sizeof(*ss.found));
		have_stats = kernel_tc_filter_stats(hw->ifindex, aclg_parent[dir], aclg_stats_cb,
						    &ss) == 0;

		if (jd) {
			json_object_int_add(jd, "chain", hw->chain);
			json_object_boolean_add(jd, "filterStatistics", have_stats);
			if (have_stats)
				json_object_boolean_add(jd, "dispatchInKernel",
							ss.dispatch_found &&
								ss.dispatch_chain == hw->chain);
			jfilters = json_object_new_array();
			json_object_object_add(jd, "filters", jfilters);
		} else {
			vty_out(vty,
				"    clsact %s hook, chain 0x%x, %u filters, in evaluation order:\n",
				dir == ACLG_IN ? "ingress" : "egress", hw->chain, hw->nfilters);
		}
		aclg_show_filters(vty, hw, &ss, have_stats, 0, jfilters, &missing);

		if (!jd) {
			if (!have_stats)
				vty_out(vty, "    Filter statistics not available\n");
			else if (missing || !ss.dispatch_found || ss.dispatch_chain != hw->chain)
				vty_out(vty,
					"    Warning: %u of %u filters%s missing from the kernel,\n"
					"    the access-list is not (fully) in force.\n",
					missing, hw->nfilters,
					ss.dispatch_found && ss.dispatch_chain == hw->chain
						? " are"
						: " and the chain 0 dispatch filter are");
		}

		XFREE(MTYPE_TMP, ss.stats);
		XFREE(MTYPE_TMP, ss.valid);
		XFREE(MTYPE_TMP, ss.found);
	}

	if (st && st->rejected) {
		if (jd) {
			json_object *jr = json_object_new_object();

			json_object_object_add(jd, "refused", jr);
			json_object_int_add(jr, "refusedPref", st->rejected->failed_pref);
			jfilters = json_object_new_array();
			json_object_object_add(jr, "filters", jfilters);
		} else {
			vty_out(vty, "    Version refused by the kernel (%u filters):\n",
				st->rejected->nfilters);
			jfilters = NULL;
		}
		aclg_show_filters(vty, st->rejected, NULL, false, st->rejected->failed_pref,
				  jfilters, &missing);
	}
}

static void aclg_show_interface(struct vty *vty, struct interface *ifp, json_object *json)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_if_qos *qos = zif ? zif->qos : NULL;
	json_object *json_if = NULL;

	if (!qos || (!qos->access_group[ACLG_IN][0] && !qos->access_group[ACLG_OUT][0]))
		return;

	if (json) {
		json_if = json_object_new_object();
		json_object_object_add(json, ifp->name, json_if);
	} else {
		vty_out(vty, "Interface %s\n", ifp->name);
	}

	for (int dir = 0; dir < ACLG_DIRS; dir++)
		aclg_show_dir(vty, qos, dir, json_if);

	if (!json)
		vty_out(vty, "\n");
}

DEFPY (show_ip_access_group,
       show_ip_access_group_cmd,
       "show ip access-group [interface IFNAME$ifname] [json$json]",
       SHOW_STR
       IP_STR
       "Interface access control with extended access-lists\n"
       INTERFACE_STR
       "Interface name\n"
       JSON_STR)
{
	struct vrf *vrf;
	struct interface *ifp;
	json_object *json_out = json ? json_object_new_object() : NULL;
	bool found = false;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (ifname && strcmp(ifname, ifp->name))
				continue;
			aclg_show_interface(vty, ifp, json_out);
			found = true;
		}
	}

	if (json_out) {
		vty_json(vty, json_out);
	} else if (ifname && !found) {
		vty_out(vty, "%% Interface %s not found\n", ifname);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

void zebra_acl_group_init(void)
{
	install_element(VIEW_NODE, &show_ip_access_group_cmd);
}

void zebra_acl_group_terminate(void)
{
	event_cancel(&aclg_t_hold);
	XFREE(MTYPE_ACL_GROUP_HW, aclg_stale.ifindex);
	aclg_stale.n = aclg_stale.size = 0;
}
