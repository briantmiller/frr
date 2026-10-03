// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra class based QoS (CBWFQ style) on top of HTB.
 *
 * Copyright (C) 2026 FRRouting
 *
 * The configuration (class-maps, policy-maps and the interface "qos
 * bandwidth" / "service-policy output") is translated into a Linux HTB
 * hierarchy:
 *
 *   beef:      htb root qdisc, default class = top level class-default
 *   beef:1     root class, rate = ceil = interface QoS bandwidth
 *   beef:N     one class per policy-map class, children of beef:1.  A
 *              class with a child service-policy becomes an inner class
 *              whose children are the classes of the child policy.
 *   M:         optional pfifo below a leaf class implementing queue-limit
 *
 * Classification uses flower filters.  Every class (policy level) owns
 * a set of filter chains attached to its parent (the root qdisc for the
 * top level policy, the inner class for a child policy).  Each match
 * statement of a class-map becomes a "segment" living in its own chain:
 *
 *   - access-list permit entries select the class,
 *   - access-list deny entries jump to the next segment (first match
 *     semantics of access-lists),
 *   - a trailing catch-all filter jumps to the next segment,
 *
 * so the classes of a policy are evaluated strictly in configuration
 * order, match-any class-maps are an OR of their segments and match-all
 * class-maps fold the DSCP values into the access-list entries.  The
 * last chain of a level holds a catch-all filter selecting
 * class-default.
 *
 * Whenever something changes the complete kernel state of an interface
 * is recomputed and compared with what has been installed.  If only
 * rates, ceilings or priorities differ (e.g. "qos bandwidth" changed)
 * the existing classes are updated in place, otherwise the qdisc is
 * deleted and the whole hierarchy is installed again.
 */

#include <zebra.h>

#include <netinet/if_ether.h>

#include "command.h"
#include "filter.h"
#include "if.h"
#include "linklist.h"
#include "memory.h"
#include "prefix.h"
#include "vrf.h"
#include "tc.h"

#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_qos.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_tc.h"

#include "zebra/zebra_qos_clippy.c"

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

/* same as the kernel's TC_H_MAKE() */
#define QOS_TC_HANDLE(maj, min) (((maj) & 0xffff0000u) | ((min) & 0x0000ffffu))

DEFINE_MTYPE_STATIC(ZEBRA, QOS_CLASS_MAP, "QoS class-map");
DEFINE_MTYPE_STATIC(ZEBRA, QOS_POLICY_MAP, "QoS policy-map");
DEFINE_MTYPE_STATIC(ZEBRA, QOS_POLICY_CLASS, "QoS policy-map class");
DEFINE_MTYPE_STATIC(ZEBRA, QOS_ACL_NAME, "QoS access-group name");
DEFINE_MTYPE_STATIC(ZEBRA, QOS_IF, "QoS interface");
DEFINE_MTYPE_STATIC(ZEBRA, QOS_HW, "QoS kernel state");

/* minor number of the HTB root class */
#define QOS_ROOT_MINOR 1
/* first minor number handed out to policy classes */
#define QOS_FIRST_MINOR 2
/* upper bound on the number of classes per interface */
#define QOS_MAX_CLASSES 4000
/* major number of the fifo below leaf class N is QOS_FIFO_MAJOR_BASE + N */
#define QOS_FIFO_MAJOR_BASE 0x1000
/* smallest rate handed to HTB, bits/sec */
#define QOS_MIN_RATE 8000
/* HTB supports 8 levels, one of them is the root class */
#define QOS_MAX_DEPTH 7
/* HTB priority of classes without "priority" (lowest) */
#define QOS_DEFAULT_PRIO 7
/* filter priorities available per chain */
#define QOS_MAX_FILTER_PRIO 0xfff0

/* One HTB class as it is (to be) programmed */
struct qos_hw_class {
	uint32_t minor;
	uint32_t parent;
	/* bits per second */
	uint64_t rate;
	uint64_t ceil;
	uint32_t prio;
	/* pfifo limit below the class, 0 when none */
	uint32_t queue_limit;
	bool leaf;
	char name[2 * QOS_NAME_LEN + 1];
};

/* Complete kernel state of one interface */
struct qos_hw {
	ifindex_t ifindex;
	uint32_t mtu;
	uint64_t bandwidth;
	uint32_t defcls;

	struct qos_hw_class *classes;
	unsigned int nclasses;
	unsigned int classes_size;

	struct tc_filter *filters;
	unsigned int nfilters;
	unsigned int filters_size;
};

static struct {
	/* struct qos_class_map */
	struct list *class_maps;
	/* struct qos_policy_map */
	struct list *policy_maps;

	struct event *t_apply;

	/* initial kernel state has been read */
	bool startup_done;
} qos_g;

/*
 * ----------------------------------------------------------------------
 * Configuration objects
 * ----------------------------------------------------------------------
 */

static struct qos_class_map *qos_class_map_lookup(const char *name)
{
	struct qos_class_map *cmap;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(qos_g.class_maps, node, cmap))
		if (strcmp(cmap->name, name) == 0)
			return cmap;

	return NULL;
}

static void qos_acl_name_free(void *arg)
{
	XFREE(MTYPE_QOS_ACL_NAME, arg);
}

struct qos_class_map *zebra_qos_class_map_get(const char *name)
{
	struct qos_class_map *cmap;

	cmap = qos_class_map_lookup(name);
	if (cmap)
		return cmap;

	cmap = XCALLOC(MTYPE_QOS_CLASS_MAP, sizeof(*cmap));
	strlcpy(cmap->name, name, sizeof(cmap->name));
	cmap->acls = list_new();
	cmap->acls->del = qos_acl_name_free;
	listnode_add(qos_g.class_maps, cmap);

	return cmap;
}

void zebra_qos_class_map_del(struct qos_class_map *cmap)
{
	listnode_delete(qos_g.class_maps, cmap);
	list_delete(&cmap->acls);
	XFREE(MTYPE_QOS_CLASS_MAP, cmap);
}

void zebra_qos_class_map_acl_add(struct qos_class_map *cmap, const char *name)
{
	listnode_add(cmap->acls, XSTRDUP(MTYPE_QOS_ACL_NAME, name));
}

void zebra_qos_class_map_acl_del(struct qos_class_map *cmap, const char *name)
{
	struct listnode *node;
	char *acl;

	for (ALL_LIST_ELEMENTS_RO(cmap->acls, node, acl)) {
		if (strcmp(acl, name) == 0) {
			list_delete_node(cmap->acls, node);
			XFREE(MTYPE_QOS_ACL_NAME, acl);
			return;
		}
	}
}

static struct qos_policy_map *qos_policy_map_lookup(const char *name)
{
	struct qos_policy_map *pmap;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(qos_g.policy_maps, node, pmap))
		if (strcmp(pmap->name, name) == 0)
			return pmap;

	return NULL;
}

static void qos_policy_class_free(void *arg)
{
	XFREE(MTYPE_QOS_POLICY_CLASS, arg);
}

struct qos_policy_map *zebra_qos_policy_map_get(const char *name)
{
	struct qos_policy_map *pmap;

	pmap = qos_policy_map_lookup(name);
	if (pmap)
		return pmap;

	pmap = XCALLOC(MTYPE_QOS_POLICY_MAP, sizeof(*pmap));
	strlcpy(pmap->name, name, sizeof(pmap->name));
	pmap->classes = list_new();
	pmap->classes->del = qos_policy_class_free;
	listnode_add(qos_g.policy_maps, pmap);

	return pmap;
}

void zebra_qos_policy_map_del(struct qos_policy_map *pmap)
{
	listnode_delete(qos_g.policy_maps, pmap);
	list_delete(&pmap->classes);
	XFREE(MTYPE_QOS_POLICY_MAP, pmap);
}

/* Insert @pclass right after @after, or at the head when @after is NULL */
static void qos_policy_class_link(struct qos_policy_class *pclass, struct qos_policy_class *after)
{
	struct list *classes = pclass->pmap->classes;
	struct listnode *node;

	if (after) {
		node = listnode_lookup(classes, after);
		if (node) {
			listnode_add_after(classes, node, pclass);
			return;
		}
	}

	listnode_add_head(classes, pclass);
}

struct qos_policy_class *zebra_qos_policy_class_add(struct qos_policy_map *pmap, const char *name,
						    struct qos_policy_class *after)
{
	struct qos_policy_class *pclass;

	pclass = XCALLOC(MTYPE_QOS_POLICY_CLASS, sizeof(*pclass));
	pclass->pmap = pmap;
	strlcpy(pclass->name, name, sizeof(pclass->name));
	pclass->priority = -1;

	qos_policy_class_link(pclass, after);

	return pclass;
}

void zebra_qos_policy_class_move(struct qos_policy_class *pclass, struct qos_policy_class *after)
{
	listnode_delete(pclass->pmap->classes, pclass);
	qos_policy_class_link(pclass, after);
}

void zebra_qos_policy_class_del(struct qos_policy_class *pclass)
{
	listnode_delete(pclass->pmap->classes, pclass);
	XFREE(MTYPE_QOS_POLICY_CLASS, pclass);
}

struct zebra_if_qos *zebra_qos_if_get(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	if (!zif)
		return NULL;

	if (!zif->qos)
		zif->qos = XCALLOC(MTYPE_QOS_IF, sizeof(*zif->qos));

	return zif->qos;
}

/*
 * ----------------------------------------------------------------------
 * Building the kernel representation
 * ----------------------------------------------------------------------
 */

static void qos_hw_free(struct qos_hw **hw)
{
	if (!*hw)
		return;

	XFREE(MTYPE_QOS_HW, (*hw)->classes);
	XFREE(MTYPE_QOS_HW, (*hw)->filters);
	XFREE(MTYPE_QOS_HW, *hw);
}

static struct qos_hw_class *qos_hw_class_add(struct qos_hw *hw)
{
	if (hw->nclasses == hw->classes_size) {
		hw->classes_size = hw->classes_size ? hw->classes_size * 2 : 16;
		hw->classes = XREALLOC(MTYPE_QOS_HW, hw->classes,
				       hw->classes_size * sizeof(*hw->classes));
	}

	memset(&hw->classes[hw->nclasses], 0, sizeof(hw->classes[0]));

	return &hw->classes[hw->nclasses++];
}

/* Builder state for one interface */
struct qos_build {
	struct qos_hw *hw;
	/* interface QoS bandwidth, bits/sec */
	uint64_t if_bw;
	uint32_t next_minor;
	/* policy-maps currently being expanded, to break loops */
	const struct qos_policy_map *stack[QOS_MAX_DEPTH + 1];
	unsigned int depth;
	/* resource limits exceeded, refuse to install */
	bool overflow;
};

/* Filter placement state for one policy level */
struct qos_level {
	/* minor of the class the filters attach to, 0 is the root qdisc */
	uint32_t parent;
	/* current chain and the next free filter priority in it */
	uint32_t chain;
	uint32_t prio;
};

static struct tc_filter *qos_filter_new(struct qos_build *b, struct qos_level *lvl, uint16_t proto)
{
	struct qos_hw *hw = b->hw;
	struct tc_filter *f;

	if (lvl->prio > QOS_MAX_FILTER_PRIO) {
		b->overflow = true;
		return NULL;
	}

	if (hw->nfilters == hw->filters_size) {
		hw->filters_size = hw->filters_size ? hw->filters_size * 2 : 32;
		hw->filters = XREALLOC(MTYPE_QOS_HW, hw->filters,
				       hw->filters_size * sizeof(*hw->filters));
	}

	f = &hw->filters[hw->nfilters++];
	/* zeroed so that whole structures can be compared with memcmp */
	memset(f, 0, sizeof(*f));

	f->ifindex = hw->ifindex;
	f->parent = lvl->parent;
	f->chain = lvl->chain;
	f->priority = lvl->prio++;
	f->handle = 1;
	f->protocol = proto;
	f->kind = TC_FILTER_FLOWER;

	return f;
}

static void qos_filter_classify(struct tc_filter *f, uint32_t minor)
{
	if (f)
		f->u.flower.classid = minor;
}

static void qos_filter_goto(struct tc_filter *f, uint32_t chain)
{
	if (!f)
		return;

	f->u.flower.filter_bm |= TC_FLOWER_ACT_GOTO_CHAIN;
	f->u.flower.goto_chain = chain;
}

static void qos_filter_dscp(struct tc_filter *f, uint8_t dscp)
{
	if (!f)
		return;

	f->u.flower.filter_bm |= TC_FLOWER_DSFIELD;
	f->u.flower.dsfield = dscp << 2;
	f->u.flower.dsfield_mask = 0xfc;
}

/* Close the current segment: anything not matched so far moves on. */
static void qos_segment_end(struct qos_build *b, struct qos_level *lvl)
{
	struct tc_filter *f;

	f = qos_filter_new(b, lvl, ETH_P_ALL);
	qos_filter_goto(f, lvl->chain + 1);

	lvl->chain++;
	lvl->prio = 1;
}

/* An access-list entry turned into flower keys */
struct qos_rule {
	uint16_t proto;
	bool permit;

	bool has_src;
	struct prefix src;
	uint8_t src_mask[16];

	bool has_dst;
	struct prefix dst;
	uint8_t dst_mask[16];
};

static bool qos_mask_is_zero(const uint8_t *mask, size_t len)
{
	for (size_t i = 0; i < len; i++)
		if (mask[i])
			return false;
	return true;
}

/*
 * Set a key from an address and a "care" mask (bits set are compared).
 * Returns whether the key is needed at all.
 */
static bool qos_rule_key(int family, const void *addr, const void *care, struct prefix *p,
			 uint8_t *mask)
{
	size_t len = family == AF_INET ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
	const uint8_t *a = addr, *m = care;

	memset(p, 0, sizeof(*p));
	p->family = family;
	p->prefixlen = family == AF_INET ? IPV4_MAX_BITLEN : IPV6_MAX_BITLEN;

	for (size_t i = 0; i < len; i++) {
		mask[i] = m[i];
		p->u.val[i] = a[i] & m[i];
	}

	return !qos_mask_is_zero(mask, len);
}

static void qos_wildcard_to_care4(struct in_addr wildcard, struct in_addr *care)
{
	care->s_addr = ~wildcard.s_addr;
}

static void qos_wildcard_to_care6(const struct in6_addr *wildcard, struct in6_addr *care)
{
	for (size_t i = 0; i < sizeof(care->s6_addr); i++)
		care->s6_addr[i] = ~wildcard->s6_addr[i];
}

/*
 * Translate one access-list entry.  Zebra style entries and Cisco
 * standard entries match the source address (like a Cisco standard
 * access-list), Cisco extended entries match source and destination.
 */
static bool qos_rule_from_filter(const struct filter *flt, struct qos_rule *r)
{
	memset(r, 0, sizeof(*r));

	switch (flt->type) {
	case FILTER_PERMIT:
		r->permit = true;
		break;
	case FILTER_DENY:
		r->permit = false;
		break;
	case FILTER_DYNAMIC:
		return false;
	}

	if (!flt->cisco) {
		const struct prefix *p = &flt->u.zfilter.prefix;
		struct in6_addr care = {};

		if (p->family == AF_INET) {
			r->proto = ETH_P_IP;
			masklen2ip(p->prefixlen, (struct in_addr *)&care);
		} else if (p->family == AF_INET6) {
			r->proto = ETH_P_IPV6;
			masklen2ip6(p->prefixlen, &care);
		} else {
			return false;
		}

		r->has_src = qos_rule_key(p->family, &p->u.prefix, &care, &r->src, r->src_mask);
		return true;
	}

	const struct filter_cisco *cf = &flt->u.cfilter;

	if (!cf->ipv6) {
		struct in_addr care;

		r->proto = ETH_P_IP;
		if (cf->extended) {
			qos_wildcard_to_care4(cf->sadr.src_mask, &care);
			r->has_src = qos_rule_key(AF_INET, &cf->sadr.src, &care, &r->src,
						  r->src_mask);
			qos_wildcard_to_care4(cf->sadr.dst_mask, &care);
			r->has_dst = qos_rule_key(AF_INET, &cf->sadr.dst, &care, &r->dst,
						  r->dst_mask);
		} else {
			qos_wildcard_to_care4(cf->addr_mask, &care);
			r->has_src = qos_rule_key(AF_INET, &cf->addr, &care, &r->src, r->src_mask);
		}
	} else {
		struct in6_addr care;

		r->proto = ETH_P_IPV6;
		qos_wildcard_to_care6(&cf->sadr6.src_mask, &care);
		r->has_src = qos_rule_key(AF_INET6, &cf->sadr6.src, &care, &r->src, r->src_mask);
		if (cf->extended) {
			qos_wildcard_to_care6(&cf->sadr6.dst_mask, &care);
			r->has_dst = qos_rule_key(AF_INET6, &cf->sadr6.dst, &care, &r->dst,
						  r->dst_mask);
		}
	}

	return true;
}

static struct tc_filter *qos_filter_from_rule(struct qos_build *b, struct qos_level *lvl,
					      const struct qos_rule *r)
{
	struct tc_filter *f;

	f = qos_filter_new(b, lvl, r->proto);
	if (!f)
		return NULL;

	if (r->has_src) {
		f->u.flower.filter_bm |= TC_FLOWER_SRC_IP | TC_FLOWER_SRC_IP_MASK;
		prefix_copy(&f->u.flower.src_ip, &r->src);
		memcpy(f->u.flower.src_mask, r->src_mask, sizeof(r->src_mask));
	}
	if (r->has_dst) {
		f->u.flower.filter_bm |= TC_FLOWER_DST_IP | TC_FLOWER_DST_IP_MASK;
		prefix_copy(&f->u.flower.dst_ip, &r->dst);
		memcpy(f->u.flower.dst_mask, r->dst_mask, sizeof(r->dst_mask));
	}

	return f;
}

/*
 * Emit the entries of the IPv4 and IPv6 access-lists called @name into
 * the current segment.  Deny entries leave the segment.  Permit entries
 * select @classid, if @dscp is non-zero only for packets carrying one of
 * those DSCP values (match-all).
 *
 * Returns false if no access-list of that name exists.
 */
static bool qos_segment_acl(struct qos_build *b, struct qos_level *lvl, const char *name,
			    uint64_t dscp, uint32_t classid)
{
	afi_t afis[] = { AFI_IP, AFI_IP6 };
	bool found = false;

	for (size_t i = 0; i < array_size(afis); i++) {
		struct access_list *acl = access_list_lookup(afis[i], name);
		struct filter *flt;

		if (!acl)
			continue;
		found = true;

		for (flt = acl->head; flt; flt = flt->next) {
			struct qos_rule rule;
			struct tc_filter *f;

			if (!qos_rule_from_filter(flt, &rule))
				continue;

			if (!rule.permit) {
				f = qos_filter_from_rule(b, lvl, &rule);
				qos_filter_goto(f, lvl->chain + 1);
				continue;
			}

			if (!dscp) {
				f = qos_filter_from_rule(b, lvl, &rule);
				qos_filter_classify(f, classid);
				continue;
			}

			for (uint8_t d = 0; d < 64; d++) {
				if (!CHECK_FLAG(dscp, (uint64_t)1 << d))
					continue;
				f = qos_filter_from_rule(b, lvl, &rule);
				qos_filter_dscp(f, d);
				qos_filter_classify(f, classid);
			}
		}
	}

	return found;
}

static void qos_segment_dscp(struct qos_build *b, struct qos_level *lvl, uint64_t dscp,
			     uint32_t classid)
{
	uint16_t protos[] = { ETH_P_IP, ETH_P_IPV6 };

	for (uint8_t d = 0; d < 64; d++) {
		if (!CHECK_FLAG(dscp, (uint64_t)1 << d))
			continue;

		for (size_t i = 0; i < array_size(protos); i++) {
			struct tc_filter *f = qos_filter_new(b, lvl, protos[i]);

			qos_filter_dscp(f, d);
			qos_filter_classify(f, classid);
		}
	}

	qos_segment_end(b, lvl);
}

static void qos_build_class_filters(struct qos_build *b, struct qos_level *lvl,
				    const struct qos_class_map *cmap, uint32_t classid)
{
	struct listnode *node;
	const char *name;

	if (!cmap)
		return;

	if (cmap->match_all_packets) {
		struct tc_filter *f = qos_filter_new(b, lvl, ETH_P_ALL);

		qos_filter_classify(f, classid);
		lvl->chain++;
		lvl->prio = 1;
		return;
	}

	if (!cmap->match_any) {
		/* match-all: at most one access-group, enforced by YANG */
		name = listnode_head(cmap->acls);
		if (name) {
			/* an undefined access-list matches nothing */
			if (qos_segment_acl(b, lvl, name, cmap->dscp, classid))
				qos_segment_end(b, lvl);
		} else if (cmap->dscp) {
			qos_segment_dscp(b, lvl, cmap->dscp, classid);
		}
		return;
	}

	/* match-any: OR of all match statements, in order */
	for (ALL_LIST_ELEMENTS_RO(cmap->acls, node, name)) {
		if (qos_segment_acl(b, lvl, name, 0, classid))
			qos_segment_end(b, lvl);
	}

	if (cmap->dscp)
		qos_segment_dscp(b, lvl, cmap->dscp, classid);
}

static uint64_t qos_rate_resolve(const struct qos_rate *rate, uint64_t ref)
{
	switch (rate->type) {
	case QOS_RATE_NONE:
		return 0;
	case QOS_RATE_PERCENT:
		return ref / 100 * rate->value + (ref % 100) * rate->value / 100;
	case QOS_RATE_BPS:
		return rate->value;
	}

	return 0;
}

static bool qos_on_stack(const struct qos_build *b, const struct qos_policy_map *pmap)
{
	for (unsigned int i = 0; i < b->depth; i++)
		if (b->stack[i] == pmap)
			return true;

	return false;
}

static void qos_build_level(struct qos_build *b, const struct qos_policy_map *pmap,
			    uint32_t parent_minor, uint64_t parent_rate)
{
	/*
	 * The top level policy attaches its filters to the root qdisc,
	 * child policies to the (inner) class they shape.
	 */
	struct qos_level lvl = {
		.parent = parent_minor == QOS_ROOT_MINOR ? 0 : parent_minor,
		.chain = 0,
		.prio = 1,
	};
	struct qos_policy_class implicit_default = {};
	const struct qos_policy_class *def = NULL, *pclass;
	const struct qos_policy_class **pcs;
	uint64_t *rates;
	uint64_t explicit = 0, share = 0;
	unsigned int n = 0, unset = 0, i;
	struct listnode *node;

	b->stack[b->depth++] = pmap;

	pcs = XCALLOC(MTYPE_TMP, (listcount(pmap->classes) + 1) * sizeof(*pcs));
	rates = XCALLOC(MTYPE_TMP, (listcount(pmap->classes) + 1) * sizeof(*rates));

	/* configured order, class-default always last */
	for (ALL_LIST_ELEMENTS_RO(pmap->classes, node, pclass)) {
		if (strcmp(pclass->name, QOS_CLASS_DEFAULT) == 0)
			def = pclass;
		else
			pcs[n++] = pclass;
	}
	if (!def) {
		strlcpy(implicit_default.name, QOS_CLASS_DEFAULT, sizeof(implicit_default.name));
		implicit_default.priority = -1;
		implicit_default.pmap = (struct qos_policy_map *)pmap;
		def = &implicit_default;
	}
	pcs[n++] = def;

	/* guaranteed rates; unconfigured classes share what is left */
	for (i = 0; i < n; i++) {
		rates[i] = qos_rate_resolve(&pcs[i]->bandwidth, parent_rate);
		if (rates[i])
			explicit += rates[i];
		else
			unset++;
	}

	if (explicit > parent_rate)
		zlog_warn("QoS policy-map %s: guaranteed bandwidth %" PRIu64
			  " bps exceeds the available %" PRIu64 " bps",
			  pmap->name, explicit, parent_rate);

	if (unset && parent_rate > explicit)
		share = (parent_rate - explicit) / unset;

	for (i = 0; i < n; i++) {
		struct qos_hw_class *hc;
		const struct qos_policy_map *child = NULL;
		uint32_t minor;

		pclass = pcs[i];

		if (!rates[i])
			rates[i] = share;
		rates[i] = MAX(rates[i], QOS_MIN_RATE);

		if (b->next_minor >= QOS_MAX_CLASSES) {
			b->overflow = true;
			break;
		}
		minor = b->next_minor++;

		if (pclass->service_policy[0]) {
			child = qos_policy_map_lookup(pclass->service_policy);
			if (child && (b->depth >= QOS_MAX_DEPTH || qos_on_stack(b, child))) {
				zlog_warn("QoS policy-map %s class %s: ignoring service-policy %s (loop or nesting too deep)",
					  pmap->name, pclass->name, child->name);
				child = NULL;
			}
		}

		hc = qos_hw_class_add(b->hw);
		hc->minor = minor;
		hc->parent = parent_minor;
		hc->rate = rates[i];
		hc->ceil = qos_rate_resolve(&pclass->max_bandwidth, b->if_bw);
		if (!hc->ceil)
			hc->ceil = b->if_bw;
		hc->ceil = MAX(hc->ceil, hc->rate);
		hc->prio = pclass->priority >= 0 ? (uint32_t)pclass->priority : QOS_DEFAULT_PRIO;
		hc->leaf = !child;
		hc->queue_limit = child ? 0 : pclass->queue_limit;
		snprintf(hc->name, sizeof(hc->name), "%s/%s", pmap->name, pclass->name);

		/* hc may move when the child level adds classes */
		if (child)
			qos_build_level(b, child, minor, rates[i]);

		if (pclass == def) {
			struct tc_filter *f = qos_filter_new(b, &lvl, ETH_P_ALL);

			qos_filter_classify(f, minor);
			if (lvl.parent == 0)
				b->hw->defcls = minor;
		} else {
			qos_build_class_filters(b, &lvl, qos_class_map_lookup(pclass->name), minor);
		}
	}

	XFREE(MTYPE_TMP, rates);
	XFREE(MTYPE_TMP, pcs);

	b->depth--;
}

static uint64_t qos_if_bandwidth(const struct interface *ifp, const struct zebra_if_qos *qos)
{
	if (qos->bandwidth)
		return qos->bandwidth;

	/* interface "bandwidth" (kbps), then the link speed (Mbps) */
	if (ifp->bandwidth)
		return (uint64_t)ifp->bandwidth * 1000;

	if (ifp->speed && ifp->speed != UINT32_MAX)
		return (uint64_t)ifp->speed * 1000000;

	return 0;
}

static struct qos_hw *qos_hw_build(struct interface *ifp, struct zebra_if_qos *qos,
				   const char **reason)
{
	const struct qos_policy_map *pmap;
	struct qos_build b = {};
	struct qos_hw_class *root;
	uint64_t bw;

	*reason = NULL;

	if (!qos->service_policy[0])
		return NULL;

	if (!qos_g.startup_done) {
		*reason = "waiting for zebra startup to complete";
		return NULL;
	}

	if (ifp->ifindex == IFINDEX_INTERNAL) {
		*reason = "interface does not exist";
		return NULL;
	}

	pmap = qos_policy_map_lookup(qos->service_policy);
	if (!pmap) {
		*reason = "policy-map is not configured";
		return NULL;
	}

	bw = qos_if_bandwidth(ifp, qos);
	if (!bw) {
		*reason = "interface bandwidth unknown, configure \"qos bandwidth\"";
		return NULL;
	}

	b.hw = XCALLOC(MTYPE_QOS_HW, sizeof(*b.hw));
	b.hw->ifindex = ifp->ifindex;
	b.hw->mtu = ifp->mtu;
	b.hw->bandwidth = bw;
	b.if_bw = bw;
	b.next_minor = QOS_FIRST_MINOR;

	root = qos_hw_class_add(b.hw);
	root->minor = QOS_ROOT_MINOR;
	root->parent = 0;
	root->rate = bw;
	root->ceil = bw;
	root->prio = 0;
	root->leaf = false;
	snprintf(root->name, sizeof(root->name), "%s", pmap->name);

	qos_build_level(&b, pmap, QOS_ROOT_MINOR, bw);

	if (b.overflow) {
		*reason = "policy is too large (classes or filters)";
		qos_hw_free(&b.hw);
		return NULL;
	}

	return b.hw;
}

/*
 * ----------------------------------------------------------------------
 * Talking to the dataplane
 * ----------------------------------------------------------------------
 */

static void qos_hw_uninstall(ifindex_t ifindex)
{
	struct zebra_tc_qdisc qdisc = {};

	if (IS_ZEBRA_DEBUG_TC)
		zlog_debug("%s: ifindex %d", __func__, ifindex);

	qdisc.qdisc.ifindex = ifindex;
	qdisc.qdisc.kind = TC_QDISC_HTB;
	(void)dplane_tc_qdisc_uninstall(&qdisc);
}

static void qos_tc_class_fill(struct zebra_tc_class *zc, const struct qos_hw *hw,
			      const struct qos_hw_class *hc)
{
	memset(zc, 0, sizeof(*zc));
	zc->class.ifindex = hw->ifindex;
	zc->class.handle = hc->minor;
	zc->class.parent = hc->parent;
	zc->class.kind = TC_QDISC_HTB;
	/* HTB wants bytes per second */
	zc->class.u.htb.rate = hc->rate / 8;
	zc->class.u.htb.ceil = hc->ceil / 8;
	zc->class.u.htb.prio = hc->prio;
	zc->class.u.htb.mtu = hw->mtu;
}

static void qos_hw_install(const struct qos_hw *hw)
{
	struct zebra_tc_qdisc qdisc = {};
	unsigned int i;

	if (IS_ZEBRA_DEBUG_TC)
		zlog_debug("%s: ifindex %d, %u classes, %u filters", __func__, hw->ifindex,
			   hw->nclasses, hw->nfilters);

	qdisc.qdisc.ifindex = hw->ifindex;
	qdisc.qdisc.kind = TC_QDISC_HTB;
	qdisc.qdisc.u.htb.defcls = hw->defcls;
	(void)dplane_tc_qdisc_install(&qdisc);

	/* parents always precede their children */
	for (i = 0; i < hw->nclasses; i++) {
		struct zebra_tc_class zc;

		qos_tc_class_fill(&zc, hw, &hw->classes[i]);
		(void)dplane_tc_class_add(&zc);
	}

	for (i = 0; i < hw->nclasses; i++) {
		const struct qos_hw_class *hc = &hw->classes[i];
		struct zebra_tc_qdisc fifo = {};

		if (!hc->leaf || !hc->queue_limit)
			continue;

		fifo.qdisc.ifindex = hw->ifindex;
		fifo.qdisc.kind = TC_QDISC_PFIFO;
		fifo.qdisc.handle = QOS_TC_HANDLE((QOS_FIFO_MAJOR_BASE + hc->minor) << 16, 0);
		fifo.qdisc.parent = QOS_TC_HANDLE(TC_QDISC_MAJOR_ZEBRA, hc->minor);
		fifo.qdisc.u.fifo.limit = hc->queue_limit;
		(void)dplane_tc_qdisc_install(&fifo);
	}

	for (i = 0; i < hw->nfilters; i++) {
		struct zebra_tc_filter zf = {};

		zf.filter = hw->filters[i];
		(void)dplane_tc_filter_add(&zf);
	}
}

/* Same classes, queues and filters; only rates/ceilings/priorities may differ */
static bool qos_hw_same_shape(const struct qos_hw *a, const struct qos_hw *b)
{
	unsigned int i;

	if (a->ifindex != b->ifindex || a->defcls != b->defcls || a->nclasses != b->nclasses ||
	    a->nfilters != b->nfilters)
		return false;

	for (i = 0; i < a->nclasses; i++) {
		const struct qos_hw_class *ca = &a->classes[i], *cb = &b->classes[i];

		if (ca->minor != cb->minor || ca->parent != cb->parent || ca->leaf != cb->leaf ||
		    ca->queue_limit != cb->queue_limit)
			return false;
	}

	if (a->nfilters && memcmp(a->filters, b->filters, a->nfilters * sizeof(a->filters[0])))
		return false;

	return true;
}

static void qos_hw_update_rates(const struct qos_hw *old, const struct qos_hw *new)
{
	unsigned int i, updated = 0;

	for (i = 0; i < new->nclasses; i++) {
		const struct qos_hw_class *co = &old->classes[i], *cn = &new->classes[i];
		struct zebra_tc_class zc;

		if (co->rate == cn->rate && co->ceil == cn->ceil && co->prio == cn->prio &&
		    old->mtu == new->mtu)
			continue;

		qos_tc_class_fill(&zc, new, cn);
		(void)dplane_tc_class_update(&zc);
		updated++;
	}

	if (IS_ZEBRA_DEBUG_TC)
		zlog_debug("%s: ifindex %d, updated %u classes in place", __func__, new->ifindex,
			   updated);
}

static void qos_if_apply(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_if_qos *qos;
	struct qos_hw *hw, *old;
	const char *reason;

	if (!zif || !zif->qos)
		return;

	qos = zif->qos;
	old = qos->installed;

	hw = qos_hw_build(ifp, qos, &reason);
	qos->reason = reason;

	if (!hw) {
		if (old) {
			if (IS_ZEBRA_DEBUG_TC)
				zlog_debug("%s: %s: removing service-policy (%s)", __func__,
					   ifp->name, reason ? reason : "unconfigured");
			if (old->ifindex == ifp->ifindex)
				qos_hw_uninstall(old->ifindex);
			qos_hw_free(&qos->installed);
		}
		return;
	}

	if (old && qos_hw_same_shape(old, hw)) {
		qos_hw_update_rates(old, hw);
	} else {
		if (IS_ZEBRA_DEBUG_TC)
			zlog_debug("%s: %s: (re)installing service-policy %s", __func__, ifp->name,
				   qos->service_policy);
		/* changing an existing HTB in place would keep stale state */
		if (old)
			qos_hw_uninstall(old->ifindex);
		qos_hw_install(hw);
	}

	qos_hw_free(&qos->installed);
	qos->installed = hw;
}

static void qos_apply_all(struct event *t)
{
	struct vrf *vrf;
	struct interface *ifp;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
		FOR_ALL_INTERFACES (vrf, ifp)
			qos_if_apply(ifp);
}

void zebra_qos_config_changed(void)
{
	event_add_event(zrouter.master, qos_apply_all, NULL, 0, &qos_g.t_apply);
}

void zebra_qos_startup_done(void)
{
	if (qos_g.startup_done)
		return;

	qos_g.startup_done = true;
	zebra_qos_config_changed();
}

/*
 * ----------------------------------------------------------------------
 * Hooks
 * ----------------------------------------------------------------------
 */

static void qos_acl_changed(struct access_list *acl)
{
	zebra_qos_config_changed();
}

void zebra_qos_if_added(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	if (zif && zif->qos)
		zebra_qos_config_changed();
}

void zebra_qos_if_removed(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	/* the kernel removed the qdisc together with the interface */
	if (zif && zif->qos) {
		qos_hw_free(&zif->qos->installed);
		/* refresh the state shown by "show qos interface" */
		zebra_qos_config_changed();
	}
}

void zebra_qos_if_fini(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	if (!zif || !zif->qos)
		return;

	qos_hw_free(&zif->qos->installed);
	XFREE(MTYPE_QOS_IF, zif->qos);
}

/*
 * ----------------------------------------------------------------------
 * Show
 * ----------------------------------------------------------------------
 */

static const char *qos_bps2str(uint64_t bps, char *buf, size_t len)
{
	if (bps >= 1000000000ULL && bps % 10000000ULL == 0)
		snprintf(buf, len, "%.2fGbps", bps / 1e9);
	else if (bps >= 1000000ULL && bps % 10000ULL == 0)
		snprintf(buf, len, "%.2fMbps", bps / 1e6);
	else if (bps >= 1000ULL && bps % 10ULL == 0)
		snprintf(buf, len, "%.2fkbps", bps / 1e3);
	else
		snprintf(buf, len, "%lubps", bps);

	return buf;
}

static void qos_show_interface(struct vty *vty, struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_if_qos *qos = zif ? zif->qos : NULL;
	const struct qos_hw *hw;
	char buf1[32], buf2[32], parent[16];
	unsigned int i;

	if (!qos || (!qos->service_policy[0] && !qos->bandwidth))
		return;

	vty_out(vty, "Interface %s\n", ifp->name);
	if (qos->bandwidth)
		vty_out(vty, "  QoS bandwidth: %s\n",
			qos_bps2str(qos->bandwidth, buf1, sizeof(buf1)));
	else
		vty_out(vty, "  QoS bandwidth: %s (derived)\n",
			qos_bps2str(qos_if_bandwidth(ifp, qos), buf1, sizeof(buf1)));
	vty_out(vty, "  Service policy (output): %s\n",
		qos->service_policy[0] ? qos->service_policy : "none");

	hw = qos->installed;
	if (!hw) {
		if (qos->service_policy[0])
			vty_out(vty, "  State: not installed%s%s%s\n", qos->reason ? " (" : "",
				qos->reason ? qos->reason : "", qos->reason ? ")" : "");
		vty_out(vty, "\n");
		return;
	}

	vty_out(vty, "  State: installed, %u classes, %u filters, default class %x:%x\n",
		hw->nclasses, hw->nfilters, TC_QDISC_MAJOR_ZEBRA >> 16, hw->defcls);
	vty_out(vty, "  %-10s %-10s %-12s %-12s %-4s %-7s %s\n", "Class", "Parent", "Rate", "Ceil",
		"Prio", "Queue", "Name");

	for (i = 0; i < hw->nclasses; i++) {
		const struct qos_hw_class *hc = &hw->classes[i];
		char classid[16], queue[16];

		snprintf(classid, sizeof(classid), "%x:%x", TC_QDISC_MAJOR_ZEBRA >> 16, hc->minor);
		if (hc->parent)
			snprintf(parent, sizeof(parent), "%x:%x", TC_QDISC_MAJOR_ZEBRA >> 16,
				 hc->parent);
		else
			snprintf(parent, sizeof(parent), "root");
		if (hc->queue_limit)
			snprintf(queue, sizeof(queue), "%u", hc->queue_limit);
		else
			snprintf(queue, sizeof(queue), "-");

		vty_out(vty, "  %-10s %-10s %-12s %-12s %-4u %-7s %s%s\n", classid, parent,
			qos_bps2str(hc->rate, buf1, sizeof(buf1)),
			qos_bps2str(hc->ceil, buf2, sizeof(buf2)), hc->prio, queue, hc->name,
			hc->leaf ? "" : " (parent)");
	}
	vty_out(vty, "\n");
}

DEFPY (show_qos_interface,
       show_qos_interface_cmd,
       "show qos interface [IFNAME$ifname]",
       SHOW_STR
       "Quality of Service\n"
       INTERFACE_STR
       "Interface name\n")
{
	struct vrf *vrf;
	struct interface *ifp;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (ifname && strcmp(ifname, ifp->name))
				continue;
			qos_show_interface(vty, ifp);
		}
	}

	return CMD_SUCCESS;
}

/*
 * ----------------------------------------------------------------------
 * Init
 * ----------------------------------------------------------------------
 */

void zebra_qos_init(void)
{
	qos_g.class_maps = list_new();
	qos_g.policy_maps = list_new();

	access_list_add_hook(qos_acl_changed);
	access_list_delete_hook(qos_acl_changed);

	install_element(VIEW_NODE, &show_qos_interface_cmd);
}

void zebra_qos_terminate(void)
{
	struct qos_class_map *cmap;
	struct qos_policy_map *pmap;

	event_cancel(&qos_g.t_apply);

	while ((cmap = listnode_head(qos_g.class_maps)))
		zebra_qos_class_map_del(cmap);
	while ((pmap = listnode_head(qos_g.policy_maps)))
		zebra_qos_policy_map_del(pmap);

	list_delete(&qos_g.class_maps);
	list_delete(&qos_g.policy_maps);
}
