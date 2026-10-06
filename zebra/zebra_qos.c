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
#include "json.h"
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
#include "zebra/zebra_acl_ext.h"
#include "zebra/zebra_acl_flower.h"

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
DEFINE_MTYPE_STATIC(ZEBRA, QOS_ACL_EXT, "QoS extended access-list");
DEFINE_MTYPE_STATIC(ZEBRA, QOS_ACL_EXT_ENTRY, "QoS extended access-list entry");
DEFINE_MTYPE_STATIC(ZEBRA, QOS_ACL_EXT_RULE, "QoS extended access-list rule");

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

/* HFSC service curve as programmed, bits/sec and usec, m2 == 0: not set */
struct qos_hw_curve {
	uint64_t m1;
	uint32_t d;
	uint64_t m2;
};

/* One HTB or HFSC class as it is (to be) programmed */
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
	/* HFSC: real-time, link-share and upper-limit curves */
	struct qos_hw_curve rt;
	struct qos_hw_curve ls;
	struct qos_hw_curve ul;
	char name[2 * QOS_NAME_LEN + 1];
	/* policy-map and class (class-map name or class-default) */
	char pmap[QOS_NAME_LEN];
	char cmap[QOS_NAME_LEN];
};

#define QOS_ORIGIN_LEN 192
#define QOS_MATCH_LEN  ACLX_TEXT_MAX

/* Bookkeeping kept next to each tc filter, for "show class-map interface" */
struct qos_hw_filter_info {
	/* minor of the class whose match statements produced the filter */
	uint32_t owner;
	/* what produced it, e.g. "access-list VOICE seq 5 deny" */
	char origin[QOS_ORIGIN_LEN];
	/* description of the match keys, when not derived from the filter */
	char match[QOS_MATCH_LEN];
};

/* Complete kernel state of one interface */
struct qos_hw {
	ifindex_t ifindex;
	/* HFSC instead of HTB */
	bool hfsc;
	uint32_t mtu;
	uint64_t bandwidth;
	uint32_t defcls;

	struct qos_hw_class *classes;
	unsigned int nclasses;
	unsigned int classes_size;

	struct tc_filter *filters;
	/* parallel to filters */
	struct qos_hw_filter_info *finfo;
	unsigned int nfilters;
	unsigned int filters_size;
};

static struct {
	/* struct qos_class_map */
	struct list *class_maps;
	/* struct qos_policy_map */
	struct list *policy_maps;
	/* struct qos_acl_ext */
	struct list *acl_exts;

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

/* ip access-list extended NAME */
static struct qos_acl_ext *qos_acl_ext_lookup(const char *name)
{
	struct qos_acl_ext *acl;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(qos_g.acl_exts, node, acl))
		if (strcmp(acl->name, name) == 0)
			return acl;

	return NULL;
}

struct qos_acl_ext *zebra_qos_acl_ext_get(const char *name)
{
	struct qos_acl_ext *acl;

	acl = qos_acl_ext_lookup(name);
	if (acl)
		return acl;

	acl = XCALLOC(MTYPE_QOS_ACL_EXT, sizeof(*acl));
	strlcpy(acl->name, name, sizeof(acl->name));
	acl->entries = list_new();
	listnode_add(qos_g.acl_exts, acl);

	return acl;
}

void zebra_qos_acl_ext_del(struct qos_acl_ext *acl)
{
	struct qos_acl_ext_entry *entry;

	while ((entry = listnode_head(acl->entries)))
		zebra_qos_acl_ext_entry_del(entry);
	list_delete(&acl->entries);
	listnode_delete(qos_g.acl_exts, acl);
	XFREE(MTYPE_QOS_ACL_EXT, acl);
}

struct qos_acl_ext_entry *zebra_qos_acl_ext_entry_add(struct qos_acl_ext *acl, uint32_t seq)
{
	struct qos_acl_ext_entry *entry, *cur;
	struct listnode *node;

	entry = XCALLOC(MTYPE_QOS_ACL_EXT_ENTRY, sizeof(*entry));
	entry->acl = acl;
	entry->seq = seq;

	/* keep the entries in sequence order */
	for (ALL_LIST_ELEMENTS_RO(acl->entries, node, cur)) {
		if (cur->seq > seq) {
			listnode_add_before(acl->entries, node, entry);
			return entry;
		}
	}
	listnode_add(acl->entries, entry);

	return entry;
}

void zebra_qos_acl_ext_entry_unset_match(struct qos_acl_ext_entry *entry)
{
	XFREE(MTYPE_QOS_ACL_EXT_RULE, entry->match);
	XFREE(MTYPE_QOS_ACL_EXT_RULE, entry->rule);
}

void zebra_qos_acl_ext_entry_del(struct qos_acl_ext_entry *entry)
{
	zebra_qos_acl_ext_entry_unset_match(entry);
	listnode_delete(entry->acl->entries, entry);
	XFREE(MTYPE_QOS_ACL_EXT_ENTRY, entry);
}

int zebra_qos_acl_ext_entry_set_match(struct qos_acl_ext_entry *entry, const char *text, char *err,
				      size_t errlen)
{
	struct aclx_rule *rule = XCALLOC(MTYPE_QOS_ACL_EXT_RULE, sizeof(*rule));
	char buf[ACLX_TEXT_MAX];
	const char *canon;

	if (aclx_rule_parse(text, rule, err, errlen) < 0) {
		XFREE(MTYPE_QOS_ACL_EXT_RULE, rule);
		return -1;
	}
	canon = aclx_rule_print(rule, buf, sizeof(buf));
	if (!canon) {
		snprintf(err, errlen, "entry too long in canonical form");
		XFREE(MTYPE_QOS_ACL_EXT_RULE, rule);
		return -1;
	}

	zebra_qos_acl_ext_entry_unset_match(entry);
	entry->rule = rule;
	entry->match = XSTRDUP(MTYPE_QOS_ACL_EXT_RULE, canon);

	return 0;
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
	XFREE(MTYPE_QOS_HW, (*hw)->finfo);
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
	/* class and description recorded for the next filters */
	uint32_t owner;
	char origin[QOS_ORIGIN_LEN];
	/* the policy cannot be installed, why */
	char error[320];
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
		hw->finfo = XREALLOC(MTYPE_QOS_HW, hw->finfo,
				     hw->filters_size * sizeof(*hw->finfo));
	}

	hw->finfo[hw->nfilters].owner = b->owner;
	strlcpy(hw->finfo[hw->nfilters].origin, b->origin, sizeof(hw->finfo[0].origin));
	hw->finfo[hw->nfilters].match[0] = '\0';

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
	if (!f)
		return;

	f->u.flower.classid = minor;
	/* gives the filter hit counters, see "show class-map interface" */
	f->u.flower.filter_bm |= TC_FLOWER_ACT_COUNT;
}

static void qos_filter_goto(struct tc_filter *f, uint32_t chain)
{
	if (!f)
		return;

	f->u.flower.filter_bm |= TC_FLOWER_ACT_GOTO_CHAIN;
	f->u.flower.goto_chain = chain;
}

static const char *qos_dscp_name(uint8_t dscp)
{
	static const char *const names[64] = {
		[0] = "default", [8] = "cs1",	[10] = "af11", [12] = "af12", [14] = "af13",
		[16] = "cs2",	 [18] = "af21", [20] = "af22", [22] = "af23", [24] = "cs3",
		[26] = "af31",	 [28] = "af32", [30] = "af33", [32] = "cs4",  [34] = "af41",
		[36] = "af42",	 [38] = "af43", [40] = "cs5",  [46] = "ef",   [48] = "cs6",
		[56] = "cs7",
	};
	static const char *const numbers[64] = {
		"0",  "1",  "2",  "3",	"4",  "5",  "6",  "7",	"8",  "9",  "10", "11", "12",
		"13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25",
		"26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38",
		"39", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "50", "51",
		"52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "62", "63",
	};

	dscp &= 63;
	return names[dscp] ? names[dscp] : numbers[dscp];
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

	snprintf(b->origin, sizeof(b->origin), "no match: next statement");
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

static void qos_segment_acl_ext(struct qos_build *b, struct qos_level *lvl,
				const struct qos_acl_ext *acl, uint64_t dscp, uint32_t classid);

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
	const struct qos_acl_ext *ext = qos_acl_ext_lookup(name);
	bool found = false;

	/* an extended access-list of that name takes precedence */
	if (ext) {
		qos_segment_acl_ext(b, lvl, ext, dscp, classid);
		return true;
	}

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

			snprintf(b->origin, sizeof(b->origin),
				 "%saccess-list %s seq %" PRId64 " %s",
				 afis[i] == AFI_IP6 ? "ipv6 " : "", name, flt->seq,
				 rule.permit ? "permit" : "deny");

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

/* A filter carrying ready made flower keys from an extended access-list entry */
static struct tc_filter *qos_filter_from_flower(struct qos_build *b, struct qos_level *lvl,
						const struct aclx_flower *fl, const char *match,
						const char *extra)
{
	struct tc_filter *f;
	char desc[sizeof(fl->desc) + 32];

	f = qos_filter_new(b, lvl, fl->eth_proto);
	if (!f)
		return NULL;

	f->u.flower.filter_bm |= TC_FLOWER_RAW_KEYS;
	f->u.flower.raw_len = fl->len;
	memcpy(f->u.flower.raw, fl->raw, fl->len);

	/* what this filter adds to the entry: expanded operators, class-map DSCP */
	snprintf(desc, sizeof(desc), "%s%s%s", fl->desc, fl->desc[0] && extra[0] ? " " : "", extra);
	if (desc[0])
		snprintf(b->hw->finfo[b->hw->nfilters - 1].match, QOS_MATCH_LEN, "%s {%s}", match,
			 desc);
	else
		strlcpy(b->hw->finfo[b->hw->nfilters - 1].match, match, QOS_MATCH_LEN);

	return f;
}

/*
 * Emit the entries of an extended access-list into the current segment,
 * like qos_segment_acl().  @dscp restricts permit entries to those DSCP
 * values (match-all): such entries only match IP packets.
 */
static void qos_segment_acl_ext(struct qos_build *b, struct qos_level *lvl,
				const struct qos_acl_ext *acl, uint64_t dscp, uint32_t classid)
{
	static struct aclx_flower fl[ACLX_FLOWER_MAX_FILTERS];
	const struct qos_acl_ext_entry *entry;
	struct listnode *node;
	char err[128];

	for (ALL_LIST_ELEMENTS_RO(acl->entries, node, entry)) {
		if (!entry->rule || !(entry->permit || entry->deny))
			continue;

		snprintf(b->origin, sizeof(b->origin), "ip access-list extended %s seq %u %s",
			 acl->name, entry->seq, entry->permit ? "permit" : "deny");

		for (int d = -1; d < 64; d++) {
			uint8_t tos = 0, tos_mask = 0;
			char extra[24] = "";
			int n;

			/* d == -1: no DSCP restriction, otherwise one pass per DSCP */
			if (entry->permit && dscp) {
				if (d < 0 || !CHECK_FLAG(dscp, (uint64_t)1 << d))
					continue;
				tos = d << 2;
				tos_mask = 0xfc;
				snprintf(extra, sizeof(extra), "dscp %s", qos_dscp_name(d));
			} else if (d >= 0) {
				break;
			}

			n = aclx_flower_encode(entry->rule, tos, tos_mask, fl, array_size(fl), err,
					       sizeof(err));
			if (n < 0) {
				/* skipping an entry would change what the list matches */
				if (!b->error[0])
					snprintf(b->error, sizeof(b->error),
						 "ip access-list extended %s seq %u: %s",
						 acl->name, entry->seq, err);
				return;
			}

			for (int i = 0; i < n; i++) {
				struct tc_filter *f = qos_filter_from_flower(b, lvl, &fl[i],
									     entry->match, extra);

				if (entry->permit)
					qos_filter_classify(f, classid);
				else
					qos_filter_goto(f, lvl->chain + 1);
			}
		}
	}
}

static void qos_segment_dscp(struct qos_build *b, struct qos_level *lvl, uint64_t dscp,
			     uint32_t classid)
{
	uint16_t protos[] = { ETH_P_IP, ETH_P_IPV6 };

	for (uint8_t d = 0; d < 64; d++) {
		if (!CHECK_FLAG(dscp, (uint64_t)1 << d))
			continue;

		for (size_t i = 0; i < array_size(protos); i++) {
			struct tc_filter *f;

			snprintf(b->origin, sizeof(b->origin), "match ip dscp %s",
				 qos_dscp_name(d));
			f = qos_filter_new(b, lvl, protos[i]);
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
		struct tc_filter *f;

		snprintf(b->origin, sizeof(b->origin), "match any");
		f = qos_filter_new(b, lvl, ETH_P_ALL);

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

/*
 * Child policy-map of a class, NULL when there is none or it cannot be
 * used.  Loops and too deep nesting are ignored (with a warning), a child
 * of the other type (HTB vs HFSC) makes the whole policy uninstallable as
 * an interface has a single queueing discipline.
 */
static const struct qos_policy_map *qos_child_policy(struct qos_build *b,
						     const struct qos_policy_map *pmap,
						     const struct qos_policy_class *pclass)
{
	const struct qos_policy_map *child;

	if (!pclass->service_policy[0])
		return NULL;

	child = qos_policy_map_lookup(pclass->service_policy);
	if (!child)
		return NULL;

	if (b->depth >= QOS_MAX_DEPTH || qos_on_stack(b, child)) {
		zlog_warn("QoS policy-map %s class %s: ignoring service-policy %s (loop or nesting too deep)",
			  pmap->name, pclass->name, child->name);
		return NULL;
	}

	if (child->hfsc != b->hw->hfsc) {
		if (!b->error[0])
			snprintf(b->error, sizeof(b->error),
				 "policy-map %s (%s) is used as child policy in %s (%s), types must match",
				 child->name, child->hfsc ? "hfsc" : "htb", pmap->name,
				 pmap->hfsc ? "hfsc" : "htb");
		return NULL;
	}

	return child;
}

/* Configured curve to bits/sec; percentages refer to the interface bandwidth */
static void qos_curve_resolve(const struct qos_curve *c, uint64_t if_bw, struct qos_hw_curve *out)
{
	memset(out, 0, sizeof(*out));

	if (!c->set || c->m2.type == QOS_RATE_NONE)
		return;

	out->m2 = MAX(qos_rate_resolve(&c->m2, if_bw), 1);
	if (c->d && c->m1.type != QOS_RATE_NONE) {
		out->m1 = qos_rate_resolve(&c->m1, if_bw);
		out->d = c->d;
	}
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
	const struct qos_policy_map **children;
	struct qos_hw_curve *rt = NULL, *ls = NULL, *ul = NULL;
	uint64_t *rates;
	uint64_t explicit = 0, share = 0;
	unsigned int n = 0, unset = 0, i, count;
	struct listnode *node;

	b->stack[b->depth++] = pmap;

	count = listcount(pmap->classes) + 1;
	pcs = XCALLOC(MTYPE_TMP, count * sizeof(*pcs));
	rates = XCALLOC(MTYPE_TMP, count * sizeof(*rates));
	children = XCALLOC(MTYPE_TMP, count * sizeof(*children));

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

	for (i = 0; i < n; i++)
		children[i] = qos_child_policy(b, pmap, pcs[i]);

	if (!b->hw->hfsc) {
		/* HTB: guaranteed rates; unconfigured classes share what is left */
		for (i = 0; i < n; i++) {
			rates[i] = qos_rate_resolve(&pcs[i]->bandwidth, parent_rate);
			if (rates[i])
				explicit += rates[i];
			else
				unset++;
		}
	} else {
		/*
		 * HFSC: rt and ls fall back to sc.  A class needs a link-share
		 * curve when it has children, an upper limit or no real-time
		 * curve; those without one get an equal share of what the
		 * siblings leave of the parent's link-share rate.
		 */
		rt = XCALLOC(MTYPE_TMP, count * sizeof(*rt));
		ls = XCALLOC(MTYPE_TMP, count * sizeof(*ls));
		ul = XCALLOC(MTYPE_TMP, count * sizeof(*ul));

		for (i = 0; i < n; i++) {
			pclass = pcs[i];
			qos_curve_resolve(pclass->rt.set ? &pclass->rt : &pclass->sc, b->if_bw,
					  &rt[i]);
			qos_curve_resolve(pclass->ls.set ? &pclass->ls : &pclass->sc, b->if_bw,
					  &ls[i]);
			qos_curve_resolve(&pclass->ul, b->if_bw, &ul[i]);

			if (ls[i].m2)
				explicit += ls[i].m2;
			else if (!rt[i].m2 || children[i] || ul[i].m2)
				unset++;
		}
	}

	if (explicit > parent_rate)
		zlog_warn("QoS policy-map %s: %s bandwidth %" PRIu64
			  " bps exceeds the available %" PRIu64 " bps",
			  pmap->name, b->hw->hfsc ? "link-share" : "guaranteed", explicit,
			  parent_rate);

	if (unset && parent_rate > explicit)
		share = (parent_rate - explicit) / unset;

	if (b->hw->hfsc) {
		for (i = 0; i < n; i++) {
			if (!ls[i].m2 && (!rt[i].m2 || children[i] || ul[i].m2))
				ls[i].m2 = MAX(share, QOS_MIN_RATE);
			/* children share the parent's link-share rate */
			rates[i] = ls[i].m2 ? ls[i].m2 : rt[i].m2;
		}
	}

	for (i = 0; i < n; i++) {
		struct qos_hw_class *hc;
		const struct qos_policy_map *child = children[i];
		uint32_t minor;

		pclass = pcs[i];

		if (!b->hw->hfsc) {
			if (!rates[i])
				rates[i] = share;
			rates[i] = MAX(rates[i], QOS_MIN_RATE);
		}

		if (b->next_minor >= QOS_MAX_CLASSES) {
			b->overflow = true;
			break;
		}
		minor = b->next_minor++;

		hc = qos_hw_class_add(b->hw);
		hc->minor = minor;
		hc->parent = parent_minor;
		hc->leaf = !child;
		hc->queue_limit = child ? 0 : pclass->queue_limit;
		snprintf(hc->name, sizeof(hc->name), "%s/%s", pmap->name, pclass->name);
		strlcpy(hc->pmap, pmap->name, sizeof(hc->pmap));
		strlcpy(hc->cmap, pclass->name, sizeof(hc->cmap));

		if (!b->hw->hfsc) {
			hc->rate = rates[i];
			hc->ceil = qos_rate_resolve(&pclass->max_bandwidth, b->if_bw);
			if (!hc->ceil)
				hc->ceil = b->if_bw;
			hc->ceil = MAX(hc->ceil, hc->rate);
			hc->prio = pclass->priority >= 0 ? (uint32_t)pclass->priority
							 : QOS_DEFAULT_PRIO;
		} else {
			hc->rt = rt[i];
			hc->ls = ls[i];
			hc->ul = ul[i];
			/*
			 * For "show": the guaranteed rate (real-time, else
			 * link-share) and the most the class can get.
			 */
			hc->rate = rt[i].m2 ? rt[i].m2 : ls[i].m2;
			hc->ceil = ul[i].m2 ? ul[i].m2 : b->if_bw;
		}

		/* hc may move when the child level adds classes */
		if (child)
			qos_build_level(b, child, minor, rates[i]);

		/* the filters below belong to this class */
		b->owner = minor;

		if (pclass == def) {
			struct tc_filter *f;

			snprintf(b->origin, sizeof(b->origin), "class-default: everything else");
			f = qos_filter_new(b, &lvl, ETH_P_ALL);
			qos_filter_classify(f, minor);
			if (lvl.parent == 0)
				b->hw->defcls = minor;
		} else {
			qos_build_class_filters(b, &lvl, qos_class_map_lookup(pclass->name), minor);
		}
	}

	XFREE(MTYPE_TMP, rt);
	XFREE(MTYPE_TMP, ls);
	XFREE(MTYPE_TMP, ul);
	XFREE(MTYPE_TMP, children);
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

static struct qos_hw *qos_hw_build(struct interface *ifp, struct zebra_if_qos *qos, char *reason,
				   size_t reason_len)
{
	const struct qos_policy_map *pmap;
	struct qos_build b = {};
	struct qos_hw_class *root;
	uint64_t bw;

	reason[0] = '\0';

	if (!qos->service_policy[0])
		return NULL;

	if (!qos_g.startup_done) {
		strlcpy(reason, "waiting for zebra startup to complete", reason_len);
		return NULL;
	}

	if (ifp->ifindex == IFINDEX_INTERNAL) {
		strlcpy(reason, "interface does not exist", reason_len);
		return NULL;
	}

	pmap = qos_policy_map_lookup(qos->service_policy);
	if (!pmap) {
		strlcpy(reason, "policy-map is not configured", reason_len);
		return NULL;
	}

	bw = qos_if_bandwidth(ifp, qos);
	if (!bw) {
		strlcpy(reason, "interface bandwidth unknown, configure \"qos bandwidth\"",
			reason_len);
		return NULL;
	}

	b.hw = XCALLOC(MTYPE_QOS_HW, sizeof(*b.hw));
	b.hw->ifindex = ifp->ifindex;
	b.hw->hfsc = pmap->hfsc;
	b.hw->mtu = ifp->mtu;
	b.hw->bandwidth = bw;
	b.if_bw = bw;
	b.next_minor = QOS_FIRST_MINOR;

	/* root class: the whole interface QoS bandwidth, never more */
	root = qos_hw_class_add(b.hw);
	root->minor = QOS_ROOT_MINOR;
	root->parent = 0;
	root->rate = bw;
	root->ceil = bw;
	root->prio = 0;
	root->leaf = false;
	if (b.hw->hfsc) {
		root->ls.m2 = bw;
		root->ul.m2 = bw;
	}
	snprintf(root->name, sizeof(root->name), "%s", pmap->name);
	strlcpy(root->pmap, pmap->name, sizeof(root->pmap));

	qos_build_level(&b, pmap, QOS_ROOT_MINOR, bw);

	if (b.error[0]) {
		strlcpy(reason, b.error, reason_len);
		qos_hw_free(&b.hw);
		return NULL;
	}

	if (b.overflow) {
		strlcpy(reason, "policy is too large (classes or filters)", reason_len);
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
	/* lets "show qos interface" report the current rate per class */
	zc->class.rate_est = true;

	/* the kernel wants bytes per second */
	if (hw->hfsc) {
		const struct qos_hw_curve *src[] = { &hc->rt, &hc->ls, &hc->ul };
		struct tc_hfsc_curve *dst[] = { &zc->class.u.hfsc.rsc, &zc->class.u.hfsc.fsc,
						&zc->class.u.hfsc.usc };

		zc->class.kind = TC_QDISC_HFSC;
		for (size_t i = 0; i < array_size(src); i++) {
			if (!src[i]->m2)
				continue;
			dst[i]->m1 = src[i]->m1 / 8;
			dst[i]->d = src[i]->d;
			dst[i]->m2 = MAX(src[i]->m2 / 8, 1);
		}
		return;
	}

	zc->class.kind = TC_QDISC_HTB;
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
	if (hw->hfsc) {
		qdisc.qdisc.kind = TC_QDISC_HFSC;
		qdisc.qdisc.u.hfsc.defcls = hw->defcls;
	} else {
		qdisc.qdisc.kind = TC_QDISC_HTB;
		qdisc.qdisc.u.htb.defcls = hw->defcls;
	}
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

static bool qos_hw_curve_equal(const struct qos_hw_curve *a, const struct qos_hw_curve *b)
{
	return a->m1 == b->m1 && a->d == b->d && a->m2 == b->m2;
}

/*
 * Same classes, queues and filters; only rates/ceilings/priorities (HTB)
 * or curve values (HFSC) may differ.  The kernel cannot remove an HFSC
 * curve from an existing class, so which curves a class has is part of
 * the shape.
 */
static bool qos_hw_same_shape(const struct qos_hw *a, const struct qos_hw *b)
{
	unsigned int i;

	if (a->ifindex != b->ifindex || a->hfsc != b->hfsc || a->defcls != b->defcls ||
	    a->nclasses != b->nclasses || a->nfilters != b->nfilters)
		return false;

	for (i = 0; i < a->nclasses; i++) {
		const struct qos_hw_class *ca = &a->classes[i], *cb = &b->classes[i];

		if (ca->minor != cb->minor || ca->parent != cb->parent || ca->leaf != cb->leaf ||
		    ca->queue_limit != cb->queue_limit)
			return false;

		if (!!ca->rt.m2 != !!cb->rt.m2 || !!ca->ls.m2 != !!cb->ls.m2 ||
		    !!ca->ul.m2 != !!cb->ul.m2)
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
		    old->mtu == new->mtu &&qos_hw_curve_equal(&co->rt, &cn->rt) &&
		    qos_hw_curve_equal(&co->ls, &cn->ls) && qos_hw_curve_equal(&co->ul, &cn->ul))
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

	if (!zif || !zif->qos)
		return;

	qos = zif->qos;
	old = qos->installed;

	hw = qos_hw_build(ifp, qos, qos->reason, sizeof(qos->reason));

	if (!hw) {
		if (old) {
			if (IS_ZEBRA_DEBUG_TC)
				zlog_debug("%s: %s: removing service-policy (%s)", __func__,
					   ifp->name,
					   qos->reason[0] ? qos->reason : "unconfigured");
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

/* Measured rates are rarely round numbers: always scale and keep 2 digits */
static const char *qos_measured2str(uint64_t bps, char *buf, size_t len)
{
	if (bps >= 1000000000ULL)
		snprintf(buf, len, "%.2fGbps", bps / 1e9);
	else if (bps >= 1000000ULL)
		snprintf(buf, len, "%.2fMbps", bps / 1e6);
	else if (bps >= 1000ULL)
		snprintf(buf, len, "%.2fkbps", bps / 1e3);
	else
		snprintf(buf, len, "%" PRIu64 "bps", bps);

	return buf;
}

/* Kernel statistics of the classes of one interface, indexed like hw->classes */
struct qos_show_stats {
	const struct qos_hw *hw;
	struct zebra_tc_class_stats *stats;
	bool *valid;
};

static void qos_show_stats_cb(const struct zebra_tc_class_stats *st, void *arg)
{
	struct qos_show_stats *ss = arg;

	if ((st->handle & 0xffff0000u) != TC_QDISC_MAJOR_ZEBRA)
		return;

	for (unsigned int i = 0; i < ss->hw->nclasses; i++) {
		if (ss->hw->classes[i].minor == (st->handle & 0x0000ffffu)) {
			ss->stats[i] = *st;
			ss->valid[i] = true;
			return;
		}
	}
}

static unsigned int qos_percent(uint64_t part, uint64_t whole)
{
	return whole ? (unsigned int)((part * 100 + whole / 2) / whole) : 0;
}

/* "1.00Mbps" or "2.00Mbps/10ms/1.00Mbps", "-" when the curve is not set */
static const char *qos_curve2str(const struct qos_hw_curve *c, char *buf, size_t len)
{
	char m1[32], m2[32];

	if (!c->m2) {
		snprintf(buf, len, "-");
	} else if (c->d) {
		qos_measured2str(c->m1, m1, sizeof(m1));
		qos_measured2str(c->m2, m2, sizeof(m2));
		if (c->d % 1000 == 0)
			snprintf(buf, len, "%s/%ums/%s", m1, c->d / 1000, m2);
		else
			snprintf(buf, len, "%s/%uus/%s", m1, c->d, m2);
	} else {
		qos_measured2str(c->m2, buf, len);
	}

	return buf;
}

static void qos_curve_json(json_object *jc, const char *name, const struct qos_hw_curve *c)
{
	json_object *jcurve;

	if (!c->m2)
		return;

	jcurve = json_object_new_object();
	json_object_object_add(jc, name, jcurve);
	json_object_int_add(jcurve, "m1", c->m1);
	json_object_int_add(jcurve, "d", c->d);
	json_object_int_add(jcurve, "m2", c->m2);
}

static void qos_show_interface(struct vty *vty, struct interface *ifp, json_object *json)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_if_qos *qos = zif ? zif->qos : NULL;
	const struct qos_hw *hw;
	struct qos_show_stats ss = {};
	json_object *json_if = NULL, *json_classes = NULL;
	char buf1[32], buf2[32], buf3[32], parent[16], defcls[16];
	bool have_stats = false;
	uint64_t bw;
	unsigned int i, in_kernel = 0;

	if (!qos || (!qos->service_policy[0] && !qos->bandwidth))
		return;

	bw = qos->bandwidth ? qos->bandwidth : qos_if_bandwidth(ifp, qos);
	hw = qos->installed;

	if (hw) {
		ss.hw = hw;
		ss.stats = XCALLOC(MTYPE_TMP, hw->nclasses * sizeof(*ss.stats));
		ss.valid = XCALLOC(MTYPE_TMP, hw->nclasses * sizeof(*ss.valid));
		have_stats = kernel_tc_class_stats(hw->ifindex, qos_show_stats_cb, &ss) == 0;
		snprintf(defcls, sizeof(defcls), "%x:%x", TC_QDISC_MAJOR_ZEBRA >> 16, hw->defcls);
		for (i = 0; i < hw->nclasses; i++)
			in_kernel += ss.valid[i];
	}

	if (json) {
		json_if = json_object_new_object();
		json_object_object_add(json, ifp->name, json_if);
		json_object_int_add(json_if, "qosBandwidth", bw);
		json_object_boolean_add(json_if, "qosBandwidthDerived", !qos->bandwidth);
		if (qos->service_policy[0])
			json_object_string_add(json_if, "servicePolicyOutput", qos->service_policy);
		json_object_boolean_add(json_if, "installed", !!hw);
		if (!hw) {
			if (qos->reason[0])
				json_object_string_add(json_if, "reason", qos->reason);
			return;
		}
		json_object_string_add(json_if, "qdisc", hw->hfsc ? "hfsc" : "htb");
		json_object_int_add(json_if, "filters", hw->nfilters);
		json_object_string_add(json_if, "defaultClass", defcls);
		json_object_boolean_add(json_if, "statistics", have_stats);
		if (have_stats)
			json_object_int_add(json_if, "classesInKernel", in_kernel);
		json_classes = json_object_new_array();
		json_object_object_add(json_if, "classes", json_classes);
	} else {
		vty_out(vty, "Interface %s\n", ifp->name);
		vty_out(vty, "  QoS bandwidth: %s%s\n", qos_bps2str(bw, buf1, sizeof(buf1)),
			qos->bandwidth ? "" : " (derived)");
		vty_out(vty, "  Service policy (output): %s\n",
			qos->service_policy[0] ? qos->service_policy : "none");

		if (!hw) {
			if (qos->service_policy[0])
				vty_out(vty, "  State: not installed%s%s%s\n",
					qos->reason[0] ? " (" : "", qos->reason,
					qos->reason[0] ? ")" : "");
			vty_out(vty, "\n");
			return;
		}

		vty_out(vty, "  State: installed (%s), %u classes, %u filters, default class %s\n",
			hw->hfsc ? "hfsc" : "htb", hw->nclasses, hw->nfilters, defcls);
		if (have_stats && in_kernel < hw->nclasses)
			vty_out(vty,
				"  Warning: only %u of %u classes are in the kernel, the installation failed\n"
				"  (does the kernel support %s? see the zebra log)\n",
				in_kernel, hw->nclasses, hw->hfsc ? "sch_hfsc" : "sch_htb");
		if (hw->hfsc)
			vty_out(vty, "  %-10s %-10s %-26s %-26s %-26s %-7s %s\n", "Class", "Parent",
				"RT (m1/d/m2)", "LS (m1/d/m2)", "UL (m1/d/m2)", "Queue", "Name");
		else
			vty_out(vty, "  %-10s %-10s %-12s %-12s %-4s %-7s %s\n", "Class", "Parent",
				"Rate", "Ceil", "Prio", "Queue", "Name");
	}

	for (i = 0; i < hw->nclasses; i++) {
		const struct qos_hw_class *hc = &hw->classes[i];
		char classid[16], queue[16];

		snprintf(classid, sizeof(classid), "%x:%x", TC_QDISC_MAJOR_ZEBRA >> 16, hc->minor);
		if (hc->parent)
			snprintf(parent, sizeof(parent), "%x:%x", TC_QDISC_MAJOR_ZEBRA >> 16,
				 hc->parent);
		else
			snprintf(parent, sizeof(parent), "root");

		if (json) {
			json_object *jc = json_object_new_object();

			json_object_array_add(json_classes, jc);
			json_object_string_add(jc, "classId", classid);
			json_object_string_add(jc, "parent", parent);
			json_object_string_add(jc, "name", hc->name);
			json_object_boolean_add(jc, "leaf", hc->leaf);
			json_object_int_add(jc, "rate", hc->rate);
			json_object_int_add(jc, "ceil", hc->ceil);
			if (hw->hfsc) {
				qos_curve_json(jc, "rt", &hc->rt);
				qos_curve_json(jc, "ls", &hc->ls);
				qos_curve_json(jc, "ul", &hc->ul);
			} else {
				json_object_int_add(jc, "priority", hc->prio);
			}
			if (hc->queue_limit)
				json_object_int_add(jc, "queueLimit", hc->queue_limit);

			if (ss.valid && ss.valid[i]) {
				const struct zebra_tc_class_stats *st = &ss.stats[i];
				json_object *js = json_object_new_object();

				json_object_object_add(jc, "stats", js);
				json_object_int_add(js, "bytes", st->bytes);
				json_object_int_add(js, "packets", st->packets);
				json_object_int_add(js, "drops", st->drops);
				json_object_int_add(js, "overlimits", st->overlimits);
				json_object_int_add(js, "backlogBytes", st->backlog);
				json_object_int_add(js, "backlogPackets", st->qlen);
				json_object_boolean_add(js, "rateValid", st->rate_valid);
				if (st->rate_valid) {
					json_object_int_add(js, "currentRate", st->bps);
					json_object_int_add(js, "currentPps", st->pps);
					json_object_int_add(js, "rateUtilization",
							    qos_percent(st->bps, hc->rate));
					json_object_int_add(js, "ceilUtilization",
							    qos_percent(st->bps, hc->ceil));
				}
			}
			continue;
		}

		if (hc->queue_limit)
			snprintf(queue, sizeof(queue), "%u", hc->queue_limit);
		else
			snprintf(queue, sizeof(queue), "-");

		if (hw->hfsc) {
			char rt[96], ls[96], ul[96];

			vty_out(vty, "  %-10s %-10s %-26s %-26s %-26s %-7s %s%s\n", classid,
				parent, qos_curve2str(&hc->rt, rt, sizeof(rt)),
				qos_curve2str(&hc->ls, ls, sizeof(ls)),
				qos_curve2str(&hc->ul, ul, sizeof(ul)), queue, hc->name,
				hc->leaf ? "" : " (parent)");
			continue;
		}

		vty_out(vty, "  %-10s %-10s %-12s %-12s %-4u %-7s %s%s\n", classid, parent,
			qos_bps2str(hc->rate, buf1, sizeof(buf1)),
			qos_bps2str(hc->ceil, buf2, sizeof(buf2)), hc->prio, queue, hc->name,
			hc->leaf ? "" : " (parent)");
	}

	if (!json) {
		vty_out(vty, "\n");
		if (!have_stats) {
			vty_out(vty, "  Statistics: not available\n\n");
		} else {
			/*
			 * Current rate is the kernel's rate estimator (1s
			 * interval, ~4s average).  %Rate is the share of the
			 * guaranteed rate in use (above 100%% the class is
			 * borrowing), %Ceil the share of its maximum.
			 */
			vty_out(vty, "  %-10s %-12s %-9s %-6s %-6s %-12s %-14s %-9s %-11s %s\n",
				"Class", "Current", "Pps", "%Rate", "%Ceil", "Packets", "Bytes",
				"Drops", "Backlog", "Name");

			for (i = 0; i < hw->nclasses; i++) {
				const struct qos_hw_class *hc = &hw->classes[i];
				const struct zebra_tc_class_stats *st = &ss.stats[i];
				char classid[16], pct_rate[8], pct_ceil[8], pps[16], backlog[24];

				snprintf(classid, sizeof(classid), "%x:%x",
					 TC_QDISC_MAJOR_ZEBRA >> 16, hc->minor);

				if (!ss.valid[i]) {
					vty_out(vty, "  %-10s %s\n", classid, "(no statistics)");
					continue;
				}

				if (st->rate_valid) {
					qos_measured2str(st->bps, buf3, sizeof(buf3));
					snprintf(pps, sizeof(pps), "%" PRIu64, st->pps);
					snprintf(pct_rate, sizeof(pct_rate), "%u%%",
						 qos_percent(st->bps, hc->rate));
					snprintf(pct_ceil, sizeof(pct_ceil), "%u%%",
						 qos_percent(st->bps, hc->ceil));
				} else {
					snprintf(buf3, sizeof(buf3), "-");
					snprintf(pps, sizeof(pps), "-");
					snprintf(pct_rate, sizeof(pct_rate), "-");
					snprintf(pct_ceil, sizeof(pct_ceil), "-");
				}
				snprintf(backlog, sizeof(backlog), "%ub/%up", st->backlog,
					 st->qlen);

				vty_out(vty,
					"  %-10s %-12s %-9s %-6s %-6s %-12" PRIu64 " %-14" PRIu64
					" %-9u %-11s %s\n",
					classid, buf3, pps, pct_rate, pct_ceil, st->packets,
					st->bytes, st->drops, backlog, hc->name);
			}
			vty_out(vty, "\n");
		}
	}

	XFREE(MTYPE_TMP, ss.stats);
	XFREE(MTYPE_TMP, ss.valid);
}

DEFPY (show_qos_interface,
       show_qos_interface_cmd,
       "show qos interface [IFNAME$ifname] [json$json]",
       SHOW_STR
       "Quality of Service\n"
       INTERFACE_STR
       "Interface name\n"
       JSON_STR)
{
	struct vrf *vrf;
	struct interface *ifp;
	json_object *json_out = json ? json_object_new_object() : NULL;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (ifname && strcmp(ifname, ifp->name))
				continue;
			qos_show_interface(vty, ifp, json_out);
		}
	}

	if (json_out)
		vty_json(vty, json_out);

	return CMD_SUCCESS;
}

/*
 * show class-map interface
 */

static void qos_addr2str(const struct prefix *p, const uint8_t *mask, char *buf, size_t len)
{
	size_t bytes = p->family == AF_INET ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
	unsigned int plen = 0;
	bool contiguous = true, ended = false;
	char addr[INET6_ADDRSTRLEN], maskstr[INET6_ADDRSTRLEN];

	for (size_t i = 0; i < bytes; i++) {
		for (int bit = 7; bit >= 0; bit--) {
			if (mask[i] & (1 << bit)) {
				if (ended)
					contiguous = false;
				plen++;
			} else {
				ended = true;
			}
		}
	}

	inet_ntop(p->family, &p->u.prefix, addr, sizeof(addr));
	if (!contiguous) {
		inet_ntop(p->family, mask, maskstr, sizeof(maskstr));
		snprintf(buf, len, "%s/%s", addr, maskstr);
	} else if (plen == bytes * 8) {
		snprintf(buf, len, "%s", addr);
	} else {
		snprintf(buf, len, "%s/%u", addr, plen);
	}
}

static const char *qos_filter_proto2str(uint16_t proto)
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

	/* vty output only, from the main thread */
	static char buf[8];

	snprintf(buf, sizeof(buf), "0x%04x", proto);
	return buf;
}

/* Human readable flower keys of a filter zebra generated */
static const char *qos_filter_match2str(const struct tc_filter *f, char *buf, size_t len)
{
	const struct tc_flower *fl = &f->u.flower;
	char addr[2 * INET6_ADDRSTRLEN + 2];

	buf[0] = '\0';

	if (CHECK_FLAG(fl->filter_bm, TC_FLOWER_SRC_IP)) {
		qos_addr2str(&fl->src_ip, fl->src_mask, addr, sizeof(addr));
		snprintf(buf + strlen(buf), len - strlen(buf), "src %s ", addr);
	}
	if (CHECK_FLAG(fl->filter_bm, TC_FLOWER_DST_IP)) {
		qos_addr2str(&fl->dst_ip, fl->dst_mask, addr, sizeof(addr));
		snprintf(buf + strlen(buf), len - strlen(buf), "dst %s ", addr);
	}
	if (CHECK_FLAG(fl->filter_bm, TC_FLOWER_DSFIELD))
		snprintf(buf + strlen(buf), len - strlen(buf), "dscp %s ",
			 qos_dscp_name(fl->dsfield >> 2));

	if (buf[0])
		buf[strlen(buf) - 1] = '\0';
	else
		snprintf(buf, len, "any");

	return buf;
}

static const char *qos_filter_action2str(const struct tc_filter *f, char *buf, size_t len)
{
	if (CHECK_FLAG(f->u.flower.filter_bm, TC_FLOWER_ACT_GOTO_CHAIN))
		snprintf(buf, len, "goto chain %u", f->u.flower.goto_chain);
	else
		snprintf(buf, len, "classify");

	return buf;
}

static const char *qos_handle2str(uint32_t minor, char *buf, size_t len)
{
	if (minor)
		snprintf(buf, len, "%x:%x", TC_QDISC_MAJOR_ZEBRA >> 16, minor);
	else
		snprintf(buf, len, "%x:", TC_QDISC_MAJOR_ZEBRA >> 16);

	return buf;
}

/* Counters of the kernel filters, indexed like hw->filters */
struct qos_filter_show_stats {
	const struct qos_hw *hw;
	/* attach point being dumped */
	uint32_t parent;
	struct zebra_tc_filter_stats *stats;
	/* counters available */
	bool *valid;
	/* present in the kernel */
	bool *found;
	/* at least one attach point could be read */
	bool any;
};

static void qos_filter_stats_cb(const struct zebra_tc_filter_stats *st, void *arg)
{
	struct qos_filter_show_stats *fs = arg;

	for (unsigned int i = 0; i < fs->hw->nfilters; i++) {
		const struct tc_filter *f = &fs->hw->filters[i];

		if (f->parent == fs->parent && f->chain == st->chain &&
		    f->priority == st->priority && f->handle == st->handle) {
			fs->stats[i] = *st;
			fs->valid[i] = st->stats_valid;
			fs->found[i] = true;
			return;
		}
	}
}

static void qos_show_class_map_interface(struct vty *vty, struct interface *ifp, json_object *json)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_if_qos *qos = zif ? zif->qos : NULL;
	const struct qos_hw *hw = qos ? qos->installed : NULL;
	struct qos_show_stats cs = {};
	struct qos_filter_show_stats fs = {};
	json_object *json_if = NULL, *json_cmaps = NULL;
	bool have_class_stats;
	unsigned int i, j, missing = 0;

	if (json) {
		json_if = json_object_new_object();
		json_object_object_add(json, ifp->name, json_if);
		if (qos && qos->service_policy[0])
			json_object_string_add(json_if, "servicePolicyOutput", qos->service_policy);
		json_object_boolean_add(json_if, "installed", !!hw);
	} else {
		vty_out(vty, "Interface %s", ifp->name);
		if (qos && qos->service_policy[0])
			vty_out(vty, ", service-policy output %s", qos->service_policy);
		vty_out(vty, "\n");
	}

	if (!hw) {
		const char *reason = !qos || !qos->service_policy[0]
					     ? "no service-policy"
					     : (qos->reason[0] ? qos->reason : "not installed");

		if (json_if)
			json_object_string_add(json_if, "reason", reason);
		else
			vty_out(vty, "  No classes installed: %s\n\n", reason);
		return;
	}

	/* class statistics */
	cs.hw = hw;
	cs.stats = XCALLOC(MTYPE_TMP, hw->nclasses * sizeof(*cs.stats));
	cs.valid = XCALLOC(MTYPE_TMP, hw->nclasses * sizeof(*cs.valid));
	have_class_stats = kernel_tc_class_stats(hw->ifindex, qos_show_stats_cb, &cs) == 0;

	/* filter statistics, per attach point: the root qdisc and inner classes */
	fs.hw = hw;
	fs.stats = XCALLOC(MTYPE_TMP, MAX(hw->nfilters, 1) * sizeof(*fs.stats));
	fs.valid = XCALLOC(MTYPE_TMP, MAX(hw->nfilters, 1) * sizeof(*fs.valid));
	fs.found = XCALLOC(MTYPE_TMP, MAX(hw->nfilters, 1) * sizeof(*fs.found));
	for (i = 0; i < hw->nclasses; i++) {
		const struct qos_hw_class *hc = &hw->classes[i];
		uint32_t attach;

		if (i == 0)
			attach = 0;
		else if (!hc->leaf)
			attach = hc->minor;
		else
			continue;

		fs.parent = attach;
		if (kernel_tc_filter_stats(hw->ifindex, QOS_TC_HANDLE(TC_QDISC_MAJOR_ZEBRA, attach),
					   qos_filter_stats_cb, &fs) == 0)
			fs.any = true;
	}

	if (json_if) {
		json_cmaps = json_object_new_array();
		json_object_object_add(json_if, "classMaps", json_cmaps);
	}

	/* every class except the HTB root class, in hierarchy order */
	for (i = 1; i < hw->nclasses; i++) {
		const struct qos_hw_class *hc = &hw->classes[i];
		const struct qos_class_map *cmap = qos_class_map_lookup(hc->cmap);
		const char *mtype;
		uint32_t attach = hc->parent == QOS_ROOT_MINOR ? 0 : hc->parent;
		char classid[16], parent[16], attach_str[16], buf[64];
		json_object *jc = NULL, *jfilters = NULL;
		unsigned int nfilt = 0;

		if (strcmp(hc->cmap, QOS_CLASS_DEFAULT) == 0)
			mtype = "everything else";
		else if (!cmap)
			mtype = "not configured";
		else if (cmap->match_any)
			mtype = "match-any";
		else
			mtype = "match-all";

		qos_handle2str(hc->minor, classid, sizeof(classid));
		qos_handle2str(hc->parent, parent, sizeof(parent));
		qos_handle2str(attach, attach_str, sizeof(attach_str));

		if (json_cmaps) {
			jc = json_object_new_object();
			json_object_array_add(json_cmaps, jc);
			json_object_string_add(jc, "classMap", hc->cmap);
			json_object_string_add(jc, "matchType", mtype);
			json_object_string_add(jc, "policyMap", hc->pmap);
			json_object_string_add(jc, "classId", classid);
			json_object_string_add(jc, "parent", parent);
			json_object_string_add(jc, "filtersAttachedTo", attach_str);
			if (!hc->leaf)
				json_object_boolean_add(jc, "hasChildPolicy", true);
			if (cs.valid[i]) {
				const struct zebra_tc_class_stats *st = &cs.stats[i];
				json_object *js = json_object_new_object();

				json_object_object_add(jc, "classStats", js);
				json_object_int_add(js, "packets", st->packets);
				json_object_int_add(js, "bytes", st->bytes);
				json_object_int_add(js, "drops", st->drops);
				json_object_int_add(js, "overlimits", st->overlimits);
				if (st->rate_valid) {
					json_object_int_add(js, "currentRate", st->bps);
					json_object_int_add(js, "currentPps", st->pps);
				}
			}
			jfilters = json_object_new_array();
			json_object_object_add(jc, "filters", jfilters);
		} else {
			vty_out(vty, "\n  Class-map %s (%s)\n", hc->cmap, mtype);
			vty_out(vty, "    Policy-map %s, %s class %s, parent %s%s\n", hc->pmap,
				hw->hfsc ? "HFSC" : "HTB", classid, parent,
				hc->leaf ? "" : ", has a child policy");
			if (cs.valid[i]) {
				const struct zebra_tc_class_stats *st = &cs.stats[i];

				vty_out(vty,
					"    Class: %" PRIu64 " packets, %" PRIu64
					" bytes, %u drops, %u overlimits",
					st->packets, st->bytes, st->drops, st->overlimits);
				if (st->rate_valid)
					vty_out(vty, ", current %s",
						qos_measured2str(st->bps, buf, sizeof(buf)));
				vty_out(vty, "\n");
			} else {
				vty_out(vty, "    Class: statistics %s\n",
					have_class_stats ? "not found" : "not available");
			}
		}

		for (j = 0; j < hw->nfilters; j++) {
			const struct tc_filter *f = &hw->filters[j];
			char match[QOS_MATCH_LEN + 128], action[32], pkts[24], bytes[24];

			if (hw->finfo[j].owner != hc->minor)
				continue;

			if (hw->finfo[j].match[0])
				strlcpy(match, hw->finfo[j].match, sizeof(match));
			else
				qos_filter_match2str(f, match, sizeof(match));
			qos_filter_action2str(f, action, sizeof(action));

			if (jfilters) {
				json_object *jf = json_object_new_object();

				json_object_array_add(jfilters, jf);
				json_object_int_add(jf, "chain", f->chain);
				json_object_int_add(jf, "pref", f->priority);
				json_object_string_add(jf, "protocol",
						       qos_filter_proto2str(f->protocol));
				json_object_string_add(jf, "match", match);
				json_object_string_add(jf, "action", action);
				json_object_string_add(jf, "origin", hw->finfo[j].origin);
				if (fs.any)
					json_object_boolean_add(jf, "inKernel", fs.found[j]);
				if (fs.valid[j]) {
					json_object_int_add(jf, "packets", fs.stats[j].packets);
					json_object_int_add(jf, "bytes", fs.stats[j].bytes);
				}
				nfilt++;
				continue;
			}

			if (nfilt++ == 0) {
				vty_out(vty, "    Filters attached to %s, in evaluation order:\n",
					attach_str);
				vty_out(vty, "      %-5s %-4s %-7s %-44s %-13s %-10s %-12s %s\n",
					"Chain", "Pref", "Proto", "Match", "Action", "Packets",
					"Bytes", "Origin");
			}

			if (fs.valid[j]) {
				snprintf(pkts, sizeof(pkts), "%" PRIu64, fs.stats[j].packets);
				snprintf(bytes, sizeof(bytes), "%" PRIu64, fs.stats[j].bytes);
			} else if (fs.any && !fs.found[j]) {
				/* the kernel does not have it: install failed */
				snprintf(pkts, sizeof(pkts), "missing");
				snprintf(bytes, sizeof(bytes), "-");
				missing++;
			} else {
				snprintf(pkts, sizeof(pkts), "-");
				snprintf(bytes, sizeof(bytes), "-");
			}

			vty_out(vty, "      %-5u %-4u %-7s %-44s %-13s %-10s %-12s %s\n", f->chain,
				f->priority, qos_filter_proto2str(f->protocol), match, action,
				pkts, bytes, hw->finfo[j].origin);
		}

		if (!jfilters && nfilt == 0)
			vty_out(vty, "    No filters: the class-map matches nothing\n");
	}

	if (json_if) {
		json_object_boolean_add(json_if, "filterStatistics", fs.any);
	} else {
		if (!fs.any)
			vty_out(vty, "\n  Filter statistics not available\n");
		else if (missing)
			vty_out(vty,
				"\n  Warning: %u of %u filters are missing from the kernel (\"missing\"),\n"
				"  traffic they should classify goes to the default class.\n"
				"  The kernel needs cls_flower and act_gact.\n",
				missing, hw->nfilters);
		vty_out(vty, "\n");
	}

	XFREE(MTYPE_TMP, cs.stats);
	XFREE(MTYPE_TMP, cs.valid);
	XFREE(MTYPE_TMP, fs.stats);
	XFREE(MTYPE_TMP, fs.valid);
	XFREE(MTYPE_TMP, fs.found);
}

DEFPY (show_class_map_interface,
       show_class_map_interface_cmd,
       "show class-map interface IFNAME$ifname [json$json]",
       SHOW_STR
       "QoS class-maps\n"
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
			if (strcmp(ifname, ifp->name))
				continue;
			qos_show_class_map_interface(vty, ifp, json_out);
			found = true;
		}
	}

	if (json_out) {
		vty_json(vty, json_out);
	} else if (!found) {
		vty_out(vty, "%% Interface %s not found\n", ifname);
		return CMD_WARNING;
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
	qos_g.acl_exts = list_new();

	access_list_add_hook(qos_acl_changed);
	access_list_delete_hook(qos_acl_changed);

	install_element(VIEW_NODE, &show_qos_interface_cmd);
	install_element(VIEW_NODE, &show_class_map_interface_cmd);
}

void zebra_qos_terminate(void)
{
	struct qos_class_map *cmap;
	struct qos_policy_map *pmap;
	struct qos_acl_ext *acl;

	event_cancel(&qos_g.t_apply);

	while ((cmap = listnode_head(qos_g.class_maps)))
		zebra_qos_class_map_del(cmap);
	while ((pmap = listnode_head(qos_g.policy_maps)))
		zebra_qos_policy_map_del(pmap);

	list_delete(&qos_g.class_maps);
	list_delete(&qos_g.policy_maps);
	while ((acl = listnode_head(qos_g.acl_exts)))
		zebra_qos_acl_ext_del(acl);
	list_delete(&qos_g.acl_exts);
}
