// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra stateful NAT (NAPT) using TC flower and act_ct.
 *
 * See zebra_nat.h for the dataplane layout. This file holds the
 * configuration state, keeps the kernel objects in sync with it (driven by
 * interface and address events), and implements the operational commands.
 */

#include <zebra.h>

#include "command.h"
#include "hook.h"
#include "if.h"
#include "json.h"
#include "lib_errors.h"
#include "log.h"
#include "memory.h"
#include "typesafe.h"
#include "vrf.h"
#include "vty.h"

#ifdef HAVE_NETLINK
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#endif

#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_nat.h"
#include "zebra/nat_port.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vrf.h"

#include "zebra/zebra_nat_clippy.c"

DEFINE_MTYPE_STATIC(ZEBRA, NAT_OUTSIDE, "Zebra NAT outside interface");
DEFINE_MTYPE_STATIC(ZEBRA, NAT_INSIDE, "Zebra NAT inside interfaces");
DEFINE_MTYPE_STATIC(ZEBRA, NAT_NS, "Zebra NAT namespace state");
DEFINE_MTYPE_STATIC(ZEBRA, NAT_STATIC, "Zebra NAT static translation");
DEFINE_MTYPE_STATIC(ZEBRA, NAT_TC_OBJ, "Zebra NAT tc objects");

/* Fallback values when the kernel headers are not around (non-Linux) */
#ifndef IPS_SRC_NAT
#define IPS_SRC_NAT (1 << 4)
#endif
#ifndef IPS_ASSURED
#define IPS_ASSURED (1 << 2)
#endif
#ifndef IPS_SEEN_REPLY
#define IPS_SEEN_REPLY (1 << 1)
#endif
#ifndef IPS_OFFLOAD
#define IPS_OFFLOAD (1 << 14)
#endif
#ifndef IPS_DST_NAT
#define IPS_DST_NAT (1 << 5)
#endif

/* An inside interface whose filter is installed on an outside interface */
struct zebra_nat_inside {
	ifindex_t ifindex;
	char ifname[IFNAMSIZ];

	/* The kernel rejected the filter for this interface */
	bool failed;
};

/* A tc object for static translations installed on an outside interface */
struct zebra_nat_tc_obj {
	struct dplane_nat_tc tc;

	/* The kernel rejected it */
	bool failed;
};

/* Fixed objects of an outside interface, for result tracking */
enum nat_core_obj {
	NAT_OBJ_QDISC = 0,
	NAT_OBJ_CT_NEW,
	NAT_OBJ_CT_INV,
	NAT_OBJ_LOCAL,
	NAT_OBJ_INGRESS,
	NAT_OBJ_MAX,
};

PREDECL_DLIST(nat_outside_list);

/* Installed state for one outside interface */
struct zebra_nat_outside {
	struct nat_outside_list_item item;

	ns_id_t ns_id;
	vrf_id_t vrf_id;
	ifindex_t ifindex;
	char ifname[IFNAMSIZ];

	uint16_t zone;
	struct in_addr addr;

	/* Inside interfaces programmed on this outside interface */
	struct zebra_nat_inside *inside;
	uint32_t inside_cnt;

	/* Objects programmed for static translations */
	struct zebra_nat_tc_obj *stobj;
	uint32_t stobj_cnt;

	/* Dataplane bookkeeping */
	uint32_t pending;
	uint32_t programmed;
	uint32_t errors;      /* total kernel errors */
	uint32_t failed_mask; /* NAT_OBJ_* currently not installed */
	time_t installed_time;

	/* Scratch flag used while reconciling */
	bool seen;
};

DECLARE_DLIST(nat_outside_list, struct zebra_nat_outside, item);

/* A configured static translation */
PREDECL_DLIST(nat_static_list);
struct zebra_nat_static {
	struct nat_static_list_item item;

	/* Unique id, used as the tc filter handle */
	uint32_t id;

	/* Configuration */
	char vrf_name[VRF_NAMSIZ];
	uint8_t proto; /* 0: one-to-one */
	struct in_addr local;
	uint16_t local_port;
	bool global_is_if;
	struct in_addr global;
	char global_ifname[IFNAMSIZ];
	uint16_t global_port;

	/* State, computed while reconciling */
	bool active;
	const char *reason;
	vrf_id_t vrf_id;
	ns_id_t ns_id;
	ifindex_t ifindex; /* outside interface */
	char outside_ifname[IFNAMSIZ];
	struct in_addr resolved; /* global address in use */
	bool port_in_use;
};
DECLARE_DLIST(nat_static_list, struct zebra_nat_static, item);

/* Namespace in which the kernel's initial state has been read */
PREDECL_DLIST(nat_ns_list);
struct zebra_nat_ns {
	struct nat_ns_list_item item;
	ns_id_t ns_id;
};
DECLARE_DLIST(nat_ns_list, struct zebra_nat_ns, item);

static void nat_schedule(void);

static struct zebra_nat_globals {
	struct nat_outside_list_head outsides;
	struct nat_ns_list_head ready_ns;
	struct nat_static_list_head statics;
	uint32_t next_static_id;
	struct event *t_reconcile;
	uint64_t ct_flushed;
	bool terminating;
} znat;

const char *zebra_nat_role2str(enum zebra_nat_role role)
{
	switch (role) {
	case ZEBRA_NAT_ROLE_INSIDE:
		return "inside";
	case ZEBRA_NAT_ROLE_OUTSIDE:
		return "outside";
	case ZEBRA_NAT_ROLE_NONE:
		break;
	}

	return "none";
}

static bool nat_ns_ready(ns_id_t ns_id)
{
	struct zebra_nat_ns *nns;

	frr_each (nat_ns_list, &znat.ready_ns, nns)
		if (nns->ns_id == ns_id)
			return true;

	return false;
}

static struct zebra_nat_outside *nat_outside_find(ns_id_t ns_id, ifindex_t ifindex)
{
	struct zebra_nat_outside *o;

	frr_each (nat_outside_list, &znat.outsides, o)
		if (o->ns_id == ns_id && o->ifindex == ifindex)
			return o;

	return NULL;
}

static struct zebra_ns *nat_if_zns(const struct interface *ifp)
{
	struct zebra_vrf *zvrf = ifp->vrf ? ifp->vrf->info : NULL;

	return zvrf ? zvrf->zns : NULL;
}

/*
 * The address used for translation: the first primary IPv4 address
 * on the interface (or any IPv4 address if there is no primary).
 */
static bool nat_if_primary_addr(const struct interface *ifp, struct in_addr *addr)
{
	const struct connected *ifc;
	const struct connected *fallback = NULL;

	frr_each (if_connected_const, ifp->connected, ifc) {
		if (ifc->address->family != AF_INET)
			continue;
		if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
			continue;
		if (!CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY)) {
			*addr = ifc->address->u.prefix4;
			return true;
		}
		if (!fallback)
			fallback = ifc;
	}

	if (fallback) {
		*addr = fallback->address->u.prefix4;
		return true;
	}

	return false;
}

/*
 * Dataplane programming
 */

static void nat_tc_init(struct dplane_nat_tc *tc, const struct zebra_nat_outside *o,
			enum dplane_nat_tc_obj obj, bool egress, uint32_t chain, uint16_t prio,
			uint32_t handle)
{
	memset(tc, 0, sizeof(*tc));
	tc->obj = obj;
	tc->ifindex = o->ifindex;
	strlcpy(tc->ifname, o->ifname, sizeof(tc->ifname));
	tc->egress = egress;
	tc->chain = chain;
	tc->prio = prio;
	tc->handle = handle;
	tc->ct_zone = o->zone;
}

static void nat_tc_install(struct zebra_nat_outside *o, const struct dplane_nat_tc *tc)
{
	struct zebra_ns *zns = zebra_ns_lookup(o->ns_id);

	if (dplane_nat_tc_install(zns, tc) == ZEBRA_DPLANE_REQUEST_FAILURE) {
		o->errors++;
		flog_warn(EC_ZEBRA_DP_INSTALL_FAIL,
			  "NAT: failed to queue tc object for %s (chain %u prio %u handle %u)",
			  o->ifname, tc->chain, tc->prio, tc->handle);
		return;
	}

	o->pending++;
}

static void nat_tc_delete(struct zebra_nat_outside *o, const struct dplane_nat_tc *tc,
			  bool ignore_errors)
{
	struct zebra_ns *zns = zebra_ns_lookup(o->ns_id);

	if (dplane_nat_tc_delete(zns, tc, ignore_errors) == ZEBRA_DPLANE_REQUEST_FAILURE) {
		if (!ignore_errors)
			flog_warn(EC_ZEBRA_DP_DELETE_FAIL,
				  "NAT: failed to queue tc delete for %s (chain %u prio %u handle %u)",
				  o->ifname, tc->chain, tc->prio, tc->handle);
		return;
	}

	if (!ignore_errors)
		o->pending++;
}

/* clsact qdisc on the outside interface */
static void nat_install_qdisc(struct zebra_nat_outside *o)
{
	struct dplane_nat_tc tc;

	nat_tc_init(&tc, o, DPLANE_NAT_TC_QDISC, false, 0, 0, 0);
	nat_tc_install(o, &tc);
}

/*
 * egress chain C: new connections get committed with a source NAT
 * mapping to the outside address; invalid packets are dropped so that
 * untranslated inside addresses never leak to the outside.
 */
static void nat_install_ct_new(struct zebra_nat_outside *o)
{
	struct dplane_nat_tc tc;

	nat_tc_init(&tc, o, DPLANE_NAT_TC_FILTER, true, ZEBRA_NAT_TC_CHAIN,
		    ZEBRA_NAT_TC_PRIO_CT_NEW, ZEBRA_NAT_TC_HANDLE);
	tc.match = DPLANE_NAT_TC_MATCH_CT_STATE;
	tc.ct_state = DPLANE_NAT_CT_STATE_TRK | DPLANE_NAT_CT_STATE_NEW;
	tc.ct_state_mask = DPLANE_NAT_CT_STATE_TRK | DPLANE_NAT_CT_STATE_NEW;
	tc.action = DPLANE_NAT_TC_ACT_CT;
	tc.ct_flags = DPLANE_NAT_CT_COMMIT | DPLANE_NAT_CT_NAT_SRC;
	tc.nat_addr = o->addr;
	nat_tc_install(o, &tc);
}

static void nat_install_ct_inv(struct zebra_nat_outside *o)
{
	struct dplane_nat_tc tc;

	nat_tc_init(&tc, o, DPLANE_NAT_TC_FILTER, true, ZEBRA_NAT_TC_CHAIN,
		    ZEBRA_NAT_TC_PRIO_CT_INV, ZEBRA_NAT_TC_HANDLE);
	tc.match = DPLANE_NAT_TC_MATCH_CT_STATE;
	tc.ct_state = DPLANE_NAT_CT_STATE_TRK | DPLANE_NAT_CT_STATE_INV;
	tc.ct_state_mask = DPLANE_NAT_CT_STATE_TRK | DPLANE_NAT_CT_STATE_INV;
	tc.action = DPLANE_NAT_TC_ACT_DROP;
	nat_tc_install(o, &tc);
}

/*
 * egress chain 0: the router's own traffic, sourced from the outside
 * address, is committed in the NAT zone (without translation) so that
 * NAPT never hands out a port the router itself is using.
 */
static void nat_install_local(struct zebra_nat_outside *o)
{
	struct dplane_nat_tc tc;

	nat_tc_init(&tc, o, DPLANE_NAT_TC_FILTER, true, 0, ZEBRA_NAT_TC_PRIO_LOCAL,
		    ZEBRA_NAT_TC_HANDLE);
	tc.match = DPLANE_NAT_TC_MATCH_SRC_IP;
	tc.src_ip = o->addr;
	tc.action = DPLANE_NAT_TC_ACT_CT;
	tc.ct_flags = DPLANE_NAT_CT_COMMIT;
	nat_tc_install(o, &tc);
}

/* ingress chain 0: translate replies back, then look for static translations */
static void nat_install_ingress(struct zebra_nat_outside *o)
{
	struct dplane_nat_tc tc;

	nat_tc_init(&tc, o, DPLANE_NAT_TC_FILTER, false, 0, ZEBRA_NAT_TC_PRIO_INGRESS,
		    ZEBRA_NAT_TC_HANDLE);
	tc.match = DPLANE_NAT_TC_MATCH_DST_IP;
	tc.dst_ip = o->addr;
	tc.action = DPLANE_NAT_TC_ACT_CT;
	tc.ct_flags = DPLANE_NAT_CT_NAT;
	/* New connections may match a static translation */
	tc.goto_chain = true;
	tc.goto_chain_index = ZEBRA_NAT_TC_CHAIN_IN;
	nat_tc_install(o, &tc);
}

/*
 * egress chain 0: traffic forwarded from an inside interface is tracked
 * (applying the existing translation, if any) and continues in chain C.
 */
static void nat_install_inside(struct zebra_nat_outside *o, const struct zebra_nat_inside *in)
{
	struct dplane_nat_tc tc;

	nat_tc_init(&tc, o, DPLANE_NAT_TC_FILTER, true, 0, ZEBRA_NAT_TC_PRIO_INSIDE,
		    (uint32_t)in->ifindex);
	tc.match = DPLANE_NAT_TC_MATCH_INDEV;
	strlcpy(tc.indev, in->ifname, sizeof(tc.indev));
	tc.action = DPLANE_NAT_TC_ACT_CT;
	tc.ct_flags = DPLANE_NAT_CT_NAT;
	tc.goto_chain = true;
	tc.goto_chain_index = ZEBRA_NAT_TC_CHAIN;
	nat_tc_install(o, &tc);
}

static void nat_uninstall_inside(struct zebra_nat_outside *o, const struct zebra_nat_inside *in)
{
	struct dplane_nat_tc tc;

	nat_tc_init(&tc, o, DPLANE_NAT_TC_FILTER, true, 0, ZEBRA_NAT_TC_PRIO_INSIDE,
		    (uint32_t)in->ifindex);
	nat_tc_delete(o, &tc, false);
}

static bool nat_stobj_prio_used(const struct zebra_nat_outside *o, bool egress, uint32_t chain,
				uint16_t prio)
{
	uint32_t i;

	for (i = 0; i < o->stobj_cnt; i++)
		if (o->stobj[i].tc.egress == egress && o->stobj[i].tc.chain == chain &&
		    o->stobj[i].tc.prio == prio)
			return true;

	return false;
}

/*
 * Remove every filter zebra may have installed on an interface. The
 * clsact qdisc itself is left alone: other applications may be using it.
 */
static void nat_uninstall_all(struct zebra_nat_outside *o, bool ignore_errors)
{
	static const struct {
		bool egress;
		uint32_t chain;
		uint16_t prio;
	} prios[] = {
		{ true, 0, ZEBRA_NAT_TC_PRIO_INSIDE },
		{ true, 0, ZEBRA_NAT_TC_PRIO_LOCAL },
		{ true, ZEBRA_NAT_TC_CHAIN, ZEBRA_NAT_TC_PRIO_CT_NEW },
		{ true, ZEBRA_NAT_TC_CHAIN, ZEBRA_NAT_TC_PRIO_CT_INV },
		{ true, ZEBRA_NAT_TC_CHAIN, ZEBRA_NAT_TC_PRIO_STATIC_SNAT },
		{ false, 0, ZEBRA_NAT_TC_PRIO_INGRESS },
		{ false, ZEBRA_NAT_TC_CHAIN_IN, ZEBRA_NAT_TC_PRIO_STATIC_DNAT },
	};
	struct dplane_nat_tc tc;
	size_t i;

	for (i = 0; i < array_size(prios); i++) {
		/* Nothing was installed at this prio */
		if (!ignore_errors && prios[i].egress && prios[i].chain == 0 &&
		    prios[i].prio == ZEBRA_NAT_TC_PRIO_INSIDE && o->inside_cnt == 0)
			continue;
		if (!ignore_errors &&
		    ((prios[i].egress && prios[i].prio == ZEBRA_NAT_TC_PRIO_STATIC_SNAT) ||
		     (!prios[i].egress && prios[i].chain == ZEBRA_NAT_TC_CHAIN_IN)) &&
		    !nat_stobj_prio_used(o, prios[i].egress, prios[i].chain, prios[i].prio))
			continue;

		nat_tc_init(&tc, o, DPLANE_NAT_TC_FILTER, prios[i].egress, prios[i].chain,
			    prios[i].prio, 0);
		nat_tc_delete(o, &tc, ignore_errors);
	}
}

/*
 * Conntrack helpers
 */

struct nat_flush_ctx {
	struct zebra_nat_ct_entry *entries;
	uint32_t cnt;
	uint32_t alloc;
};

static int nat_flush_collect(const struct zebra_nat_ct_entry *e, void *arg)
{
	struct nat_flush_ctx *fctx = arg;

	if (fctx->cnt == fctx->alloc) {
		fctx->alloc = fctx->alloc ? fctx->alloc * 2 : 64;
		fctx->entries = XREALLOC(MTYPE_TMP, fctx->entries,
					 fctx->alloc * sizeof(*fctx->entries));
	}
	fctx->entries[fctx->cnt++] = *e;

	return 0;
}

/* Remove every conntrack entry in a NAT zone. Returns the number removed. */
static uint32_t nat_ct_flush_zone(ns_id_t ns_id, uint16_t zone)
{
	struct nat_flush_ctx fctx = {};
	uint32_t i, deleted = 0;
	int ret;

	ret = kernel_nat_ct_walk(ns_id, zone, nat_flush_collect, &fctx);
	if (ret < 0 && IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("NAT: conntrack dump for zone %u failed: %s", zone, safe_strerror(-ret));

	for (i = 0; i < fctx.cnt; i++) {
		/* The entry may have expired in the meantime */
		if (kernel_nat_ct_delete(ns_id, &fctx.entries[i]) == 0)
			deleted++;
	}

	XFREE(MTYPE_TMP, fctx.entries);
	znat.ct_flushed += deleted;

	return deleted;
}

/*
 * State reconciliation
 */

static void nat_outside_free(struct zebra_nat_outside **o)
{
	XFREE(MTYPE_NAT_TC_OBJ, (*o)->stobj);
	XFREE(MTYPE_NAT_INSIDE, (*o)->inside);
	XFREE(MTYPE_NAT_OUTSIDE, *o);
}

static void nat_outside_remove(struct zebra_nat_outside *o)
{
	struct zebra_ns *zns = zebra_ns_lookup(o->ns_id);

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("NAT: removing outside interface %s ifindex %u", o->ifname, o->ifindex);

	/* If the device is gone the kernel removed the filters with it */
	if (zns && if_lookup_by_index_per_ns(zns, o->ifindex))
		nat_uninstall_all(o, false);

	nat_outside_list_del(&znat.outsides, o);
	nat_outside_free(&o);
}

static bool nat_inside_find(const struct zebra_nat_outside *o, ifindex_t ifindex)
{
	uint32_t i;

	for (i = 0; i < o->inside_cnt; i++)
		if (o->inside[i].ifindex == ifindex)
			return true;

	return false;
}

/* Bring the inside filters of an outside interface in line with config */
static void nat_outside_sync_inside(struct zebra_nat_outside *o, struct vrf *vrf)
{
	struct zebra_nat_inside *want = NULL;
	uint32_t want_cnt = 0, want_alloc = 0;
	struct interface *ifp;
	uint32_t i, j;

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct zebra_if *zif = ifp->info;

		if (!zif || zif->nat_role != ZEBRA_NAT_ROLE_INSIDE)
			continue;
		if (ifp->ifindex == IFINDEX_INTERNAL)
			continue;

		if (want_cnt == want_alloc) {
			want_alloc = want_alloc ? want_alloc * 2 : 8;
			want = XREALLOC(MTYPE_NAT_INSIDE, want, want_alloc * sizeof(*want));
		}
		want[want_cnt].ifindex = ifp->ifindex;
		strlcpy(want[want_cnt].ifname, ifp->name, sizeof(want[want_cnt].ifname));
		want[want_cnt].failed = false;
		want_cnt++;
	}

	/* Remove filters for interfaces that are no longer inside */
	for (i = 0; i < o->inside_cnt; i++) {
		bool keep = false;

		for (j = 0; j < want_cnt; j++)
			if (want[j].ifindex == o->inside[i].ifindex) {
				want[j].failed = o->inside[i].failed;
				keep = true;
				break;
			}
		if (!keep)
			nat_uninstall_inside(o, &o->inside[i]);
	}

	/* Add filters for new inside interfaces */
	for (j = 0; j < want_cnt; j++)
		if (!nat_inside_find(o, want[j].ifindex))
			nat_install_inside(o, &want[j]);

	XFREE(MTYPE_NAT_INSIDE, o->inside);
	o->inside = want;
	o->inside_cnt = want_cnt;
}

/*
 * Static translations
 */

static bool nat_if_has_addr(const struct interface *ifp, struct in_addr addr)
{
	const struct connected *ifc;

	frr_each (if_connected_const, ifp->connected, ifc) {
		if (ifc->address->family != AF_INET)
			continue;
		if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
			continue;
		if (ifc->address->u.prefix4.s_addr == addr.s_addr)
			return true;
	}

	return false;
}

/* Do two active static translations claim the same global address/port? */
static bool nat_static_global_overlap(const struct zebra_nat_static *a,
				      const struct zebra_nat_static *b)
{
	if (a->vrf_id != b->vrf_id || a->resolved.s_addr != b->resolved.s_addr)
		return false;

	/* A one-to-one translation owns the whole address */
	if (a->proto == 0 || b->proto == 0)
		return true;

	return a->proto == b->proto && a->global_port == b->global_port;
}

/*
 * Work out which outside interface every static translation belongs to,
 * and whether it can be active.
 */
static void nat_statics_bind(void)
{
	struct zebra_nat_static *st, *other;

	frr_each (nat_static_list, &znat.statics, st) {
		struct zebra_nat_outside *o, *found = NULL;
		struct vrf *vrf;

		st->active = false;
		st->port_in_use = false;
		st->outside_ifname[0] = '\0';

		vrf = vrf_lookup_by_name(st->vrf_name);
		if (!vrf || !vrf_is_enabled(vrf)) {
			st->reason = "VRF not active";
			continue;
		}
		st->vrf_id = vrf->vrf_id;

		if (st->global_is_if) {
			struct interface *ifp = if_lookup_by_name(st->global_ifname, vrf->vrf_id);
			struct zebra_ns *zns = ifp ? nat_if_zns(ifp) : NULL;

			if (ifp && zns)
				found = nat_outside_find(zns->ns_id, ifp->ifindex);
			if (found && !found->seen)
				found = NULL;
			if (!found) {
				st->reason = "interface is not an active NAT outside interface";
				continue;
			}
			st->resolved = found->addr;
		} else {
			frr_each (nat_outside_list, &znat.outsides, o) {
				struct zebra_ns *zns = zebra_ns_lookup(o->ns_id);
				struct interface *ifp;

				if (!o->seen || o->vrf_id != vrf->vrf_id || !zns)
					continue;
				ifp = if_lookup_by_index_per_ns(zns, o->ifindex);
				if (ifp && nat_if_has_addr(ifp, st->global)) {
					found = o;
					break;
				}
			}
			if (!found) {
				st->reason =
					"global address is not on an active NAT outside interface";
				continue;
			}
			st->resolved = st->global;
		}

		/* The first translation (in configuration order) wins */
		frr_each (nat_static_list, &znat.statics, other) {
			if (other == st)
				break;
			if (other->active && nat_static_global_overlap(other, st)) {
				st->reason =
					"global address/port used by another static translation";
				break;
			}
		}
		if (other != st)
			continue;

		st->active = true;
		st->reason = NULL;
		st->ns_id = found->ns_id;
		st->ifindex = found->ifindex;
		strlcpy(st->outside_ifname, found->ifname, sizeof(st->outside_ifname));

		/* zebra only sees the sockets of its own namespace */
		if (st->proto && found->ns_id == NS_DEFAULT)
			st->port_in_use = nat_local_port_in_use(st->proto, &st->resolved,
								st->global_port);
		if (st->port_in_use)
			zlog_warn("NAT: static translation %s %pI4:%u: a local service on the router uses this port, its traffic is forwarded to %pI4:%u",
				  st->proto == IPPROTO_TCP ? "tcp" : "udp", &st->resolved,
				  st->global_port, &st->local, st->local_port);
	}
}

struct nat_tc_set {
	struct zebra_nat_tc_obj *obj;
	uint32_t cnt;
	uint32_t alloc;
};

static void nat_tc_set_add(struct nat_tc_set *set, const struct dplane_nat_tc *tc)
{
	if (set->cnt == set->alloc) {
		set->alloc = set->alloc ? set->alloc * 2 : 8;
		set->obj = XREALLOC(MTYPE_NAT_TC_OBJ, set->obj, set->alloc * sizeof(*set->obj));
	}
	set->obj[set->cnt].tc = *tc;
	set->obj[set->cnt].failed = false;
	set->cnt++;
}

static struct zebra_nat_tc_obj *nat_tc_find(struct zebra_nat_tc_obj *objs, uint32_t cnt,
					    const struct dplane_nat_tc *key)
{
	uint32_t i;

	for (i = 0; i < cnt; i++)
		if (objs[i].tc.egress == key->egress && objs[i].tc.chain == key->chain &&
		    objs[i].tc.prio == key->prio && objs[i].tc.handle == key->handle)
			return &objs[i];

	return NULL;
}

static bool nat_tc_is_extra_ingress(const struct dplane_nat_tc *tc)
{
	return !tc->egress && tc->chain == 0 && tc->prio == ZEBRA_NAT_TC_PRIO_INGRESS;
}

/* Handle of the ingress filter for an extra global address */
static uint32_t nat_extra_ingress_handle(const struct zebra_nat_outside *o,
					 const struct nat_tc_set *want, struct in_addr addr)
{
	uint32_t i, h;

	for (i = 0; i < o->stobj_cnt; i++)
		if (nat_tc_is_extra_ingress(&o->stobj[i].tc) &&
		    o->stobj[i].tc.dst_ip.s_addr == addr.s_addr)
			return o->stobj[i].tc.handle;

	/* A handle used by nothing installed or wanted (1 is the core filter) */
	for (h = ZEBRA_NAT_TC_HANDLE + 1;; h++) {
		bool used = false;

		for (i = 0; i < o->stobj_cnt && !used; i++)
			used = nat_tc_is_extra_ingress(&o->stobj[i].tc) &&
			       o->stobj[i].tc.handle == h;
		for (i = 0; i < want->cnt && !used; i++)
			used = nat_tc_is_extra_ingress(&want->obj[i].tc) &&
			       want->obj[i].tc.handle == h;
		if (!used)
			return h;
	}
}

/* Bring the static translation filters of an outside interface in line */
static void nat_outside_sync_static(struct zebra_nat_outside *o)
{
	struct nat_tc_set want = {};
	struct zebra_nat_static *st;
	struct dplane_nat_tc tc;
	uint32_t i;

	frr_each (nat_static_list, &znat.statics, st) {
		if (!st->active || st->ns_id != o->ns_id || st->ifindex != o->ifindex)
			continue;

		/* Traffic to a global address other than the interface's own */
		if (st->resolved.s_addr != o->addr.s_addr) {
			bool have = false;

			for (i = 0; i < want.cnt && !have; i++)
				have = nat_tc_is_extra_ingress(&want.obj[i].tc) &&
				       want.obj[i].tc.dst_ip.s_addr == st->resolved.s_addr;
			if (!have) {
				nat_tc_init(&tc, o, DPLANE_NAT_TC_FILTER, false, 0,
					    ZEBRA_NAT_TC_PRIO_INGRESS, 0);
				tc.handle = nat_extra_ingress_handle(o, &want, st->resolved);
				tc.match = DPLANE_NAT_TC_MATCH_DST_IP;
				tc.dst_ip = st->resolved;
				tc.action = DPLANE_NAT_TC_ACT_CT;
				tc.ct_flags = DPLANE_NAT_CT_NAT;
				tc.goto_chain = true;
				tc.goto_chain_index = ZEBRA_NAT_TC_CHAIN_IN;
				nat_tc_set_add(&want, &tc);
			}
		}

		/* New connections to the global side: destination NAT */
		nat_tc_init(&tc, o, DPLANE_NAT_TC_FILTER, false, ZEBRA_NAT_TC_CHAIN_IN,
			    ZEBRA_NAT_TC_PRIO_STATIC_DNAT, st->id);
		tc.match = DPLANE_NAT_TC_MATCH_CT_STATE | DPLANE_NAT_TC_MATCH_DST_IP;
		tc.ct_state = DPLANE_NAT_CT_STATE_TRK | DPLANE_NAT_CT_STATE_NEW;
		tc.ct_state_mask = DPLANE_NAT_CT_STATE_TRK | DPLANE_NAT_CT_STATE_NEW;
		tc.dst_ip = st->resolved;
		if (st->proto) {
			tc.match |= DPLANE_NAT_TC_MATCH_IP_PROTO | DPLANE_NAT_TC_MATCH_DST_PORT;
			tc.ip_proto = st->proto;
			tc.dst_port = st->global_port;
			tc.nat_port = st->local_port;
		}
		tc.action = DPLANE_NAT_TC_ACT_CT;
		tc.ct_flags = DPLANE_NAT_CT_COMMIT | DPLANE_NAT_CT_NAT_DST;
		tc.nat_addr = st->local;
		nat_tc_set_add(&want, &tc);

		/* One-to-one: the local host's own connections use the global address */
		if (st->proto == 0) {
			nat_tc_init(&tc, o, DPLANE_NAT_TC_FILTER, true, ZEBRA_NAT_TC_CHAIN,
				    ZEBRA_NAT_TC_PRIO_STATIC_SNAT, st->id);
			tc.match = DPLANE_NAT_TC_MATCH_CT_STATE | DPLANE_NAT_TC_MATCH_SRC_IP;
			tc.ct_state = DPLANE_NAT_CT_STATE_TRK | DPLANE_NAT_CT_STATE_NEW;
			tc.ct_state_mask = DPLANE_NAT_CT_STATE_TRK | DPLANE_NAT_CT_STATE_NEW;
			tc.src_ip = st->local;
			tc.action = DPLANE_NAT_TC_ACT_CT;
			tc.ct_flags = DPLANE_NAT_CT_COMMIT | DPLANE_NAT_CT_NAT_SRC;
			tc.nat_addr = st->resolved;
			nat_tc_set_add(&want, &tc);
		}
	}

	/* Remove what is no longer wanted */
	for (i = 0; i < o->stobj_cnt; i++) {
		if (nat_tc_find(want.obj, want.cnt, &o->stobj[i].tc))
			continue;

		nat_tc_init(&tc, o, DPLANE_NAT_TC_FILTER, o->stobj[i].tc.egress,
			    o->stobj[i].tc.chain, o->stobj[i].tc.prio, o->stobj[i].tc.handle);
		nat_tc_delete(o, &tc, false);
	}

	/* Install what is new or changed */
	for (i = 0; i < want.cnt; i++) {
		struct zebra_nat_tc_obj *old;

		old = nat_tc_find(o->stobj, o->stobj_cnt, &want.obj[i].tc);
		if (old && !memcmp(&old->tc, &want.obj[i].tc, sizeof(old->tc))) {
			want.obj[i].failed = old->failed;
			continue;
		}
		nat_tc_install(o, &want.obj[i].tc);
	}

	XFREE(MTYPE_NAT_TC_OBJ, o->stobj);
	o->stobj = want.obj;
	o->stobj_cnt = want.cnt;
}

struct zebra_nat_static *zebra_nat_static_create(const char *vrf_name, uint8_t proto,
						 struct in_addr local, uint16_t local_port)
{
	struct zebra_nat_static *st;

	st = XCALLOC(MTYPE_NAT_STATIC, sizeof(*st));
	st->id = ++znat.next_static_id;
	strlcpy(st->vrf_name, vrf_name, sizeof(st->vrf_name));
	st->proto = proto;
	st->local = local;
	st->local_port = local_port;
	st->reason = "not yet programmed";
	nat_static_list_add_tail(&znat.statics, st);

	return st;
}

void zebra_nat_static_set_global(struct zebra_nat_static *st, const struct in_addr *global_addr,
				 const char *global_ifname, uint16_t global_port)
{
	st->global_is_if = (global_ifname != NULL);
	st->global.s_addr = global_addr ? global_addr->s_addr : INADDR_ANY;
	strlcpy(st->global_ifname, global_ifname ? global_ifname : "", sizeof(st->global_ifname));
	st->global_port = global_port;

	nat_schedule();
}

void zebra_nat_static_delete(struct zebra_nat_static *st)
{
	nat_static_list_del(&znat.statics, st);
	XFREE(MTYPE_NAT_STATIC, st);

	nat_schedule();
}

static void nat_reconcile(struct event *event)
{
	struct zebra_nat_outside *o;
	struct vrf *vrf;

	frr_each (nat_outside_list, &znat.outsides, o)
		o->seen = false;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		struct interface *ifp;

		FOR_ALL_INTERFACES (vrf, ifp) {
			struct zebra_if *zif = ifp->info;
			struct zebra_ns *zns;
			struct in_addr addr;

			if (!zif || zif->nat_role != ZEBRA_NAT_ROLE_OUTSIDE)
				continue;
			if (ifp->ifindex == IFINDEX_INTERNAL)
				continue;

			zns = nat_if_zns(ifp);
			if (!zns || !nat_ns_ready(zns->ns_id))
				continue;

			if (!nat_if_primary_addr(ifp, &addr))
				continue;

			o = nat_outside_find(zns->ns_id, ifp->ifindex);
			if (o && o->vrf_id != vrf->vrf_id) {
				/* Moved to another VRF: start over */
				nat_outside_remove(o);
				o = NULL;
			}

			if (!o) {
				o = XCALLOC(MTYPE_NAT_OUTSIDE, sizeof(*o));
				o->ns_id = zns->ns_id;
				o->vrf_id = vrf->vrf_id;
				o->ifindex = ifp->ifindex;
				strlcpy(o->ifname, ifp->name, sizeof(o->ifname));
				o->zone = ZEBRA_NAT_CT_ZONE(ifp->ifindex);
				o->addr = addr;
				o->installed_time = monotime(NULL);
				nat_outside_list_add_tail(&znat.outsides, o);

				if (IS_ZEBRA_DEBUG_DPLANE)
					zlog_debug("NAT: installing outside interface %s ifindex %u address %pI4 zone %u",
						   o->ifname, o->ifindex, &o->addr, o->zone);

				nat_install_qdisc(o);
				nat_install_ct_new(o);
				nat_install_ct_inv(o);
				nat_install_local(o);
				nat_install_ingress(o);
			} else if (o->addr.s_addr != addr.s_addr) {
				uint32_t flushed;

				if (IS_ZEBRA_DEBUG_DPLANE)
					zlog_debug("NAT: outside interface %s address changed %pI4 -> %pI4",
						   o->ifname, &o->addr, &addr);

				o->addr = addr;
				nat_install_ct_new(o);
				nat_install_local(o);
				nat_install_ingress(o);

				/* Translations to the old address are dead */
				flushed = nat_ct_flush_zone(o->ns_id, o->zone);
				if (IS_ZEBRA_DEBUG_DPLANE)
					zlog_debug("NAT: flushed %u translations on %s", flushed,
						   o->ifname);
			}

			strlcpy(o->ifname, ifp->name, sizeof(o->ifname));
			o->seen = true;

			nat_outside_sync_inside(o, vrf);
		}
	}

	frr_each_safe (nat_outside_list, &znat.outsides, o) {
		if (!o->seen)
			nat_outside_remove(o);
	}

	nat_statics_bind();

	frr_each (nat_outside_list, &znat.outsides, o)
		nat_outside_sync_static(o);
}

static void nat_schedule(void)
{
	if (!zrouter.master || znat.terminating)
		return;

	event_add_event(zrouter.master, nat_reconcile, NULL, 0, &znat.t_reconcile);
}

/*
 * Event entry points
 */

void zebra_nat_if_set_role(struct interface *ifp, enum zebra_nat_role role)
{
	struct zebra_if *zif = ifp->info;

	if (!zif || zif->nat_role == role)
		return;

	zif->nat_role = role;
	nat_schedule();
}

void zebra_nat_if_addr_update(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	if (zif && zif->nat_role == ZEBRA_NAT_ROLE_OUTSIDE)
		nat_schedule();
}

static int nat_if_event(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	/*
	 * Interfaces with a NAT role matter, and so does any interface while
	 * NAT is active (an outside interface may have gone away).
	 */
	if ((zif && zif->nat_role != ZEBRA_NAT_ROLE_NONE) || nat_outside_list_count(&znat.outsides))
		nat_schedule();

	return 0;
}

void zebra_nat_startup_complete(struct zebra_ns *zns)
{
	struct zebra_nat_ns *nns;

	if (!zns || nat_ns_ready(zns->ns_id))
		return;

	nns = XCALLOC(MTYPE_NAT_NS, sizeof(*nns));
	nns->ns_id = zns->ns_id;
	nat_ns_list_add_tail(&znat.ready_ns, nns);

	nat_schedule();
}

/*
 * A clsact qdisc was found while reading the kernel state at startup.
 * Remove whatever a previous zebra instance may have left behind; the
 * configuration will reinstall what is still wanted.
 */
void zebra_nat_startup_cleanup(ns_id_t ns_id, ifindex_t ifindex)
{
	struct zebra_nat_outside tmp = {};

	tmp.ns_id = ns_id;
	tmp.ifindex = ifindex;
	snprintfrr(tmp.ifname, sizeof(tmp.ifname), "ifindex %u", ifindex);

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("NAT: cleaning up leftover filters on ifindex %u", ifindex);

	nat_uninstall_all(&tmp, true);
}

/* Map an installed tc object back to what it is for */
static void nat_outside_track_result(struct zebra_nat_outside *o, const struct dplane_nat_tc *tc,
				     bool ok)
{
	struct zebra_nat_tc_obj *sobj;
	int obj = -1;
	uint32_t i;

	/* Static translation objects are compared in full: a stale result
	 * for a since replaced object must not mark the new one.
	 */
	sobj = tc->obj == DPLANE_NAT_TC_FILTER ? nat_tc_find(o->stobj, o->stobj_cnt, tc) : NULL;
	if (sobj) {
		if (!memcmp(&sobj->tc, tc, sizeof(*tc)))
			sobj->failed = !ok;
		return;
	}

	if (tc->obj == DPLANE_NAT_TC_QDISC)
		obj = NAT_OBJ_QDISC;
	else if (tc->handle != ZEBRA_NAT_TC_HANDLE)
		obj = -1; /* per inside interface, or a removed static object */
	else if (!tc->egress && tc->chain == 0 && tc->prio == ZEBRA_NAT_TC_PRIO_INGRESS)
		obj = NAT_OBJ_INGRESS;
	else if (tc->egress && tc->chain == ZEBRA_NAT_TC_CHAIN &&
		 tc->prio == ZEBRA_NAT_TC_PRIO_CT_NEW)
		obj = NAT_OBJ_CT_NEW;
	else if (tc->egress && tc->chain == ZEBRA_NAT_TC_CHAIN &&
		 tc->prio == ZEBRA_NAT_TC_PRIO_CT_INV)
		obj = NAT_OBJ_CT_INV;
	else if (tc->egress && tc->chain == 0 && tc->prio == ZEBRA_NAT_TC_PRIO_LOCAL)
		obj = NAT_OBJ_LOCAL;

	if (obj >= 0) {
		if (ok)
			UNSET_FLAG(o->failed_mask, 1U << obj);
		else
			SET_FLAG(o->failed_mask, 1U << obj);
		return;
	}

	if (!tc->egress || tc->chain != 0 || tc->prio != ZEBRA_NAT_TC_PRIO_INSIDE)
		return;

	for (i = 0; i < o->inside_cnt; i++)
		if ((uint32_t)o->inside[i].ifindex == tc->handle)
			o->inside[i].failed = !ok;
}

static uint32_t nat_outside_failed_count(const struct zebra_nat_outside *o)
{
	uint32_t i, cnt = __builtin_popcount(o->failed_mask);

	for (i = 0; i < o->inside_cnt; i++)
		if (o->inside[i].failed)
			cnt++;
	for (i = 0; i < o->stobj_cnt; i++)
		if (o->stobj[i].failed)
			cnt++;

	return cnt;
}

void zebra_nat_dplane_result(struct zebra_dplane_ctx *ctx)
{
	const struct dplane_nat_tc *tc = dplane_ctx_get_nat_tc(ctx);
	enum zebra_dplane_result res = dplane_ctx_get_status(ctx);
	struct zebra_nat_outside *o;

	if (dplane_ctx_nat_tc_ignore_errors(ctx))
		return;

	o = nat_outside_find(dplane_ctx_get_ns_id(ctx), dplane_ctx_get_ifindex(ctx));

	if (o && dplane_ctx_get_op(ctx) == DPLANE_OP_NAT_TC_INSTALL)
		nat_outside_track_result(o, tc, res == ZEBRA_DPLANE_REQUEST_SUCCESS);

	if (res != ZEBRA_DPLANE_REQUEST_SUCCESS) {
		flog_warn(EC_ZEBRA_DP_INSTALL_FAIL,
			  "NAT: kernel rejected %s of tc %s on %s (%s chain %u prio %u handle %u)",
			  dplane_ctx_get_op(ctx) == DPLANE_OP_NAT_TC_INSTALL ? "install" : "delete",
			  tc->obj == DPLANE_NAT_TC_QDISC ? "qdisc" : "filter",
			  dplane_ctx_get_ifname(ctx), tc->egress ? "egress" : "ingress", tc->chain,
			  tc->prio, tc->handle);
		if (o)
			o->errors++;
	} else if (o && dplane_ctx_get_op(ctx) == DPLANE_OP_NAT_TC_INSTALL) {
		o->programmed++;
	}

	if (o && o->pending)
		o->pending--;
}

/*
 * Operational commands
 */

static const char *nat_proto2str(uint8_t proto, char *buf, size_t len)
{
	switch (proto) {
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_UDP:
		return "udp";
	case IPPROTO_ICMP:
		return "icmp";
	case IPPROTO_SCTP:
		return "sctp";
	case IPPROTO_GRE:
		return "gre";
	default:
		snprintfrr(buf, len, "%u", proto);
		return buf;
	}
}

static const char *nat_tcp_state2str(uint8_t state)
{
	static const char *const names[] = {
		"NONE",	      "SYN_SENT", "SYN_RECV",  "ESTABLISHED", "FIN_WAIT",
		"CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE",	      "SYN_SENT2",
	};

	if (state < array_size(names))
		return names[state];

	return "UNKNOWN";
}

static bool nat_proto_has_ports(uint8_t proto)
{
	return proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_SCTP ||
	       proto == IPPROTO_UDPLITE || proto == IPPROTO_DCCP || proto == IPPROTO_ICMP;
}

static const char *nat_addrport2str(struct in_addr addr, uint16_t port, uint8_t proto, char *buf,
				    size_t len)
{
	if (nat_proto_has_ports(proto))
		snprintfrr(buf, len, "%pI4:%u", &addr, port);
	else
		snprintfrr(buf, len, "%pI4", &addr);

	return buf;
}

/* Which VRFs a command applies to */
struct nat_show_filter {
	bool all;
	vrf_id_t vrf_id;
};

static bool nat_show_filter_match(const struct nat_show_filter *f, vrf_id_t vrf_id)
{
	return f->all || f->vrf_id == vrf_id;
}

static int nat_show_filter_init(struct vty *vty, struct nat_show_filter *f, const char *vrf_name,
				bool vrf_all)
{
	struct vrf *vrf;

	f->all = vrf_all;
	f->vrf_id = VRF_DEFAULT;

	if (vrf_all || !vrf_name)
		return CMD_SUCCESS;

	vrf = vrf_lookup_by_name(vrf_name);
	if (!vrf) {
		vty_out(vty, "%% VRF %s not found\n", vrf_name);
		return CMD_WARNING;
	}
	f->vrf_id = vrf->vrf_id;

	return CMD_SUCCESS;
}

struct nat_show_ctx {
	struct vty *vty;
	const struct zebra_nat_outside *o;
	bool verbose;
	json_object *json_arr;
	uint32_t count;
	uint32_t per_proto[4]; /* tcp, udp, icmp, other */
};

static void nat_show_proto_count(struct nat_show_ctx *sctx, uint8_t proto)
{
	switch (proto) {
	case IPPROTO_TCP:
		sctx->per_proto[0]++;
		break;
	case IPPROTO_UDP:
		sctx->per_proto[1]++;
		break;
	case IPPROTO_ICMP:
		sctx->per_proto[2]++;
		break;
	default:
		sctx->per_proto[3]++;
		break;
	}
}

/* Port of one end of a tuple; for ICMP the echo identifier */
static uint16_t nat_tuple_port(const struct zebra_nat_ct_tuple *t, bool src)
{
	if (t->proto == IPPROTO_ICMP)
		return t->sport;

	return src ? t->sport : t->dport;
}

static int nat_show_translation_cb(const struct zebra_nat_ct_entry *e, void *arg)
{
	struct nat_show_ctx *sctx = arg;
	struct vty *vty = sctx->vty;
	char pbuf[8];
	char ig[32], il[32], ol[32], og[32];
	const char *proto;
	struct in_addr ig_a, il_a, ol_a, og_a;
	uint16_t ig_p, il_p, ol_p, og_p;
	uint64_t pkts_out, bytes_out, pkts_in, bytes_in;
	bool inbound;

	/* Router-local connections are tracked in the zone but not translated */
	if (!CHECK_FLAG(e->status, IPS_SRC_NAT | IPS_DST_NAT))
		return 0;

	sctx->count++;
	nat_show_proto_count(sctx, e->orig.proto);

	if (!vty)
		return 0;

	proto = nat_proto2str(e->orig.proto, pbuf, sizeof(pbuf));

	/* Opened from the outside through a static translation */
	inbound = CHECK_FLAG(e->status, IPS_DST_NAT);
	if (!inbound) {
		il_a = e->orig.src;
		il_p = nat_tuple_port(&e->orig, true);
		ol_a = e->orig.dst;
		ol_p = nat_tuple_port(&e->orig, false);
		ig_a = e->reply.dst;
		ig_p = nat_tuple_port(&e->reply, false);
		og_a = e->reply.src;
		og_p = nat_tuple_port(&e->reply, true);
		pkts_out = e->pkts_orig;
		bytes_out = e->bytes_orig;
		pkts_in = e->pkts_reply;
		bytes_in = e->bytes_reply;
	} else {
		og_a = e->orig.src;
		og_p = nat_tuple_port(&e->orig, true);
		ig_a = e->orig.dst;
		ig_p = nat_tuple_port(&e->orig, false);
		il_a = e->reply.src;
		il_p = nat_tuple_port(&e->reply, true);
		ol_a = e->reply.dst;
		ol_p = nat_tuple_port(&e->reply, false);
		pkts_out = e->pkts_reply;
		bytes_out = e->bytes_reply;
		pkts_in = e->pkts_orig;
		bytes_in = e->bytes_orig;
	}

	nat_addrport2str(ig_a, ig_p, e->orig.proto, ig, sizeof(ig));
	nat_addrport2str(il_a, il_p, e->orig.proto, il, sizeof(il));
	nat_addrport2str(ol_a, ol_p, e->orig.proto, ol, sizeof(ol));
	nat_addrport2str(og_a, og_p, e->orig.proto, og, sizeof(og));

	if (sctx->json_arr) {
		json_object *jt = json_object_new_object();

		json_object_string_add(jt, "protocol", proto);
		json_object_string_add(jt, "insideGlobal", ig);
		json_object_string_add(jt, "insideLocal", il);
		json_object_string_add(jt, "outsideLocal", ol);
		json_object_string_add(jt, "outsideGlobal", og);
		json_object_string_addf(jt, "insideGlobalAddress", "%pI4", &ig_a);
		json_object_int_add(jt, "insideGlobalPort", ig_p);
		json_object_string_addf(jt, "insideLocalAddress", "%pI4", &il_a);
		json_object_int_add(jt, "insideLocalPort", il_p);
		json_object_string_addf(jt, "outsideAddress", "%pI4", &og_a);
		json_object_int_add(jt, "outsidePort", og_p);
		json_object_boolean_add(jt, "static", false);
		json_object_boolean_add(jt, "inbound", inbound);
		json_object_string_add(jt, "outsideInterface", sctx->o->ifname);
		json_object_string_add(jt, "vrf", vrf_id_to_name(sctx->o->vrf_id));
		json_object_int_add(jt, "zone", e->zone);
		json_object_int_add(jt, "id", e->id);
		json_object_int_add(jt, "timeout", e->timeout);
		json_object_int_add(jt, "mark", e->mark);
		json_object_boolean_add(jt, "assured", CHECK_FLAG(e->status, IPS_ASSURED));
		json_object_boolean_add(jt, "seenReply", CHECK_FLAG(e->status, IPS_SEEN_REPLY));
		json_object_boolean_add(jt, "offloaded", CHECK_FLAG(e->status, IPS_OFFLOAD));
		if (e->has_tcp_state)
			json_object_string_add(jt, "tcpState", nat_tcp_state2str(e->tcp_state));
		if (e->has_counters) {
			json_object_int_add(jt, "packetsOut", pkts_out);
			json_object_int_add(jt, "bytesOut", bytes_out);
			json_object_int_add(jt, "packetsIn", pkts_in);
			json_object_int_add(jt, "bytesIn", bytes_in);
		}
		json_object_array_add(sctx->json_arr, jt);
		return 0;
	}

	vty_out(vty, "%-5s %-23s %-23s %-23s %s\n", proto, ig, il, ol, og);

	if (sctx->verbose) {
		vty_out(vty, "      interface %s, zone %u, id %u", sctx->o->ifname, e->zone, e->id);
		/* Offloaded (flowtable) connections have no conntrack timeout */
		if (!CHECK_FLAG(e->status, IPS_OFFLOAD))
			vty_out(vty, ", timeout %us", e->timeout);
		if (e->has_tcp_state)
			vty_out(vty, ", state %s", nat_tcp_state2str(e->tcp_state));
		vty_out(vty, ", flags%s%s%s%s\n", inbound ? " inbound" : "",
			CHECK_FLAG(e->status, IPS_ASSURED) ? " assured" : "",
			CHECK_FLAG(e->status, IPS_SEEN_REPLY) ? " seen-reply" : " unreplied",
			CHECK_FLAG(e->status, IPS_OFFLOAD) ? " offloaded" : "");
		if (e->has_counters)
			vty_out(vty,
				"      out %" PRIu64 " pkts / %" PRIu64 " bytes, in %" PRIu64
				" pkts / %" PRIu64 " bytes\n",
				pkts_out, bytes_out, pkts_in, bytes_in);
	}

	return 0;
}

static const char *nat_static_proto2str(uint8_t proto)
{
	switch (proto) {
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_UDP:
		return "udp";
	default:
		return "any";
	}
}

/* Static translations, as "inside global -> inside local" lines */
static uint32_t nat_show_static_translations(struct vty *vty, const struct nat_show_filter *filter,
					     json_object *json_arr)
{
	const struct zebra_nat_static *st;
	uint32_t cnt = 0;

	frr_each (nat_static_list_const, &znat.statics, st) {
		char ig[32], il[32];

		if (!st->active || !nat_show_filter_match(filter, st->vrf_id))
			continue;

		cnt++;
		nat_addrport2str(st->resolved, st->global_port, st->proto, ig, sizeof(ig));
		nat_addrport2str(st->local, st->local_port, st->proto, il, sizeof(il));

		if (json_arr) {
			json_object *jt = json_object_new_object();

			json_object_string_add(jt, "protocol",
					       st->proto ? nat_static_proto2str(st->proto) : "---");
			json_object_string_add(jt, "insideGlobal", ig);
			json_object_string_add(jt, "insideLocal", il);
			json_object_string_addf(jt, "insideGlobalAddress", "%pI4", &st->resolved);
			json_object_int_add(jt, "insideGlobalPort", st->global_port);
			json_object_string_addf(jt, "insideLocalAddress", "%pI4", &st->local);
			json_object_int_add(jt, "insideLocalPort", st->local_port);
			json_object_boolean_add(jt, "static", true);
			json_object_string_add(jt, "outsideInterface", st->outside_ifname);
			json_object_string_add(jt, "vrf", st->vrf_name);
			json_object_array_add(json_arr, jt);
			continue;
		}

		vty_out(vty, "%-5s %-23s %-23s %-23s %s\n",
			st->proto ? nat_static_proto2str(st->proto) : "---", ig, il, "---", "---");
	}

	return cnt;
}

DEFPY (show_ip_nat_translations,
       show_ip_nat_translations_cmd,
       "show ip nat translations [vrf <NAME$vrf_name|all$vrf_all>] [verbose$verbose] [json$json]",
       SHOW_STR
       IP_STR
       "Network address translation\n"
       "Translation entries (kernel conntrack state)\n"
       VRF_FULL_CMD_HELP_STR
       "Show extra details for every translation\n"
       JSON_STR)
{
	struct nat_show_filter filter;
	struct nat_show_ctx sctx = { .vty = vty, .verbose = !!verbose };
	const struct zebra_nat_outside *o;
	json_object *jroot = NULL;
	uint32_t static_cnt;
	int ret;

	ret = nat_show_filter_init(vty, &filter, vrf_name, !!vrf_all);
	if (ret != CMD_SUCCESS)
		return ret;

	if (json) {
		jroot = json_object_new_object();
		sctx.json_arr = json_object_new_array();
	} else {
		vty_out(vty, "%-5s %-23s %-23s %-23s %s\n", "Pro", "Inside global", "Inside local",
			"Outside local", "Outside global");
	}

	static_cnt = nat_show_static_translations(vty, &filter, sctx.json_arr);

	frr_each (nat_outside_list_const, &znat.outsides, o) {
		if (!nat_show_filter_match(&filter, o->vrf_id))
			continue;

		sctx.o = o;
		ret = kernel_nat_ct_walk(o->ns_id, o->zone, nat_show_translation_cb, &sctx);
		if (ret < 0 && !jroot)
			vty_out(vty, "%% Unable to read conntrack table for %s: %s\n", o->ifname,
				safe_strerror(-ret));
	}

	if (jroot) {
		json_object_object_add(jroot, "translations", sctx.json_arr);
		json_object_int_add(jroot, "total", sctx.count);
		json_object_int_add(jroot, "totalStatic", static_cnt);
		vty_json(vty, jroot);
	} else {
		vty_out(vty, "Total number of translations: %u", sctx.count);
		if (static_cnt)
			vty_out(vty, " (plus %u static)", static_cnt);
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

/* Why a configured outside interface is not active */
static const char *nat_outside_inactive_reason(const struct interface *ifp)
{
	struct zebra_ns *zns = nat_if_zns(ifp);
	struct in_addr addr;

	if (ifp->ifindex == IFINDEX_INTERNAL)
		return "interface not present";
	if (!zns || !nat_ns_ready(zns->ns_id))
		return "waiting for startup";
	if (!nat_if_primary_addr(ifp, &addr))
		return "no IPv4 address";

	return "pending";
}

static void nat_show_stats_vrf(struct vty *vty, struct vrf *vrf, json_object *json_vrfs,
			       bool *printed)
{
	struct interface *ifp;
	const struct zebra_nat_outside *o;
	const struct zebra_nat_static *st;
	json_object *jv = NULL, *jout = NULL, *jin = NULL, *jst = NULL;
	bool any = false;
	uint32_t total = 0, per_proto[4] = {};

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct zebra_if *zif = ifp->info;

		if (zif && zif->nat_role != ZEBRA_NAT_ROLE_NONE) {
			any = true;
			break;
		}
	}
	frr_each (nat_static_list_const, &znat.statics, st)
		if (!strcmp(st->vrf_name, vrf->name))
			any = true;
	if (!any)
		return;

	if (json_vrfs) {
		jv = json_object_new_object();
		jout = json_object_new_array();
		jin = json_object_new_array();
		jst = json_object_new_array();
	} else {
		if (*printed)
			vty_out(vty, "\n");
		vty_out(vty, "VRF %s:\n", vrf->name);
	}
	*printed = true;

	/* Count translations per outside interface first */
	if (!json_vrfs)
		vty_out(vty, "Outside interfaces:\n");

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct zebra_if *zif = ifp->info;
		struct zebra_ns *zns = nat_if_zns(ifp);
		struct nat_show_ctx sctx = { .vty = NULL };
		const char *status;
		int ret = 0;

		if (!zif || zif->nat_role != ZEBRA_NAT_ROLE_OUTSIDE)
			continue;

		o = zns ? nat_outside_find(zns->ns_id, ifp->ifindex) : NULL;
		if (o) {
			sctx.o = o;
			ret = kernel_nat_ct_walk(o->ns_id, o->zone, nat_show_translation_cb, &sctx);
			total += sctx.count;
			for (int i = 0; i < 4; i++)
				per_proto[i] += sctx.per_proto[i];

			if (nat_outside_failed_count(o))
				status = "error";
			else if (o->pending)
				status = "pending";
			else
				status = "installed";
		} else {
			status = nat_outside_inactive_reason(ifp);
		}

		if (jout) {
			json_object *jo = json_object_new_object();

			json_object_string_add(jo, "interface", ifp->name);
			json_object_string_add(jo, "status", status);
			if (o) {
				json_object_string_addf(jo, "address", "%pI4", &o->addr);
				json_object_int_add(jo, "zone", o->zone);
				json_object_int_add(jo, "translations", sctx.count);
				json_object_int_add(jo, "tcObjectsProgrammed", o->programmed);
				json_object_int_add(jo, "tcObjectsPending", o->pending);
				json_object_int_add(jo, "tcObjectsFailed",
						    nat_outside_failed_count(o));
				json_object_int_add(jo, "tcErrors", o->errors);
				json_object_int_add(jo, "insideInterfaces", o->inside_cnt);
				if (ret < 0)
					json_object_string_add(jo, "conntrackError",
							       safe_strerror(-ret));
			}
			json_object_array_add(jout, jo);
			continue;
		}

		if (o) {
			vty_out(vty,
				"  %s: address %pI4, conntrack zone %u, %u translations, status %s\n",
				ifp->name, &o->addr, o->zone, sctx.count, status);
			vty_out(vty,
				"    tc objects: %u programmed, %u pending, %u failed (%u kernel errors)\n",
				o->programmed, o->pending, nat_outside_failed_count(o), o->errors);
			if (ret < 0)
				vty_out(vty, "    %% unable to read conntrack: %s\n",
					safe_strerror(-ret));
		} else {
			vty_out(vty, "  %s: inactive (%s)\n", ifp->name, status);
		}
	}

	if (!json_vrfs)
		vty_out(vty, "Inside interfaces:\n");

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct zebra_if *zif = ifp->info;

		if (!zif || zif->nat_role != ZEBRA_NAT_ROLE_INSIDE)
			continue;

		if (jin) {
			json_object *ji = json_object_new_object();

			json_object_string_add(ji, "interface", ifp->name);
			json_object_boolean_add(ji, "active", ifp->ifindex != IFINDEX_INTERNAL);
			json_object_array_add(jin, ji);
		} else {
			vty_out(vty, "  %s%s\n", ifp->name,
				ifp->ifindex == IFINDEX_INTERNAL ? " (interface not present)" : "");
		}
	}

	if (!json_vrfs) {
		bool have = false;

		frr_each (nat_static_list_const, &znat.statics, st)
			if (!strcmp(st->vrf_name, vrf->name))
				have = true;
		if (have)
			vty_out(vty, "Static translations:\n");
	}

	frr_each (nat_static_list_const, &znat.statics, st) {
		char gbuf[48], lbuf[32];

		if (strcmp(st->vrf_name, vrf->name))
			continue;

		if (st->global_is_if)
			snprintfrr(gbuf, sizeof(gbuf), "interface %s", st->global_ifname);
		else
			snprintfrr(gbuf, sizeof(gbuf), "%pI4", &st->global);
		if (st->proto) {
			snprintfrr(lbuf, sizeof(lbuf), "%pI4:%u", &st->local, st->local_port);
			snprintfrr(gbuf + strlen(gbuf), sizeof(gbuf) - strlen(gbuf), " port %u",
				   st->global_port);
		} else {
			snprintfrr(lbuf, sizeof(lbuf), "%pI4", &st->local);
		}

		if (jst) {
			json_object *js = json_object_new_object();

			json_object_string_add(js, "protocol", nat_static_proto2str(st->proto));
			json_object_string_addf(js, "localAddress", "%pI4", &st->local);
			json_object_int_add(js, "localPort", st->local_port);
			if (st->global_is_if)
				json_object_string_add(js, "globalInterface", st->global_ifname);
			else
				json_object_string_addf(js, "globalAddress", "%pI4", &st->global);
			json_object_int_add(js, "globalPort", st->global_port);
			json_object_boolean_add(js, "active", st->active);
			if (st->active) {
				json_object_string_addf(js, "resolvedGlobalAddress", "%pI4",
							&st->resolved);
				json_object_string_add(js, "outsideInterface", st->outside_ifname);
				json_object_boolean_add(js, "localServiceConflict",
							st->port_in_use);
			} else {
				json_object_string_add(js, "reason", st->reason);
			}
			json_object_array_add(jst, js);
			continue;
		}

		vty_out(vty, "  %-3s %s -> %s: ", nat_static_proto2str(st->proto), gbuf, lbuf);
		if (st->active)
			vty_out(vty, "active via %s (%pI4)%s\n", st->outside_ifname, &st->resolved,
				st->port_in_use ? ", WARNING: a local service uses this port" : "");
		else
			vty_out(vty, "inactive (%s)\n", st->reason);
	}

	if (jv) {
		json_object_object_add(jv, "staticTranslations", jst);
		json_object_int_add(jv, "activeTranslations", total);
		json_object_int_add(jv, "tcpTranslations", per_proto[0]);
		json_object_int_add(jv, "udpTranslations", per_proto[1]);
		json_object_int_add(jv, "icmpTranslations", per_proto[2]);
		json_object_int_add(jv, "otherTranslations", per_proto[3]);
		json_object_object_add(jv, "outsideInterfaces", jout);
		json_object_object_add(jv, "insideInterfaces", jin);
		json_object_object_add(json_vrfs, vrf->name, jv);
	} else {
		vty_out(vty, "Total active translations: %u (%u tcp, %u udp, %u icmp, %u other)\n",
			total, per_proto[0], per_proto[1], per_proto[2], per_proto[3]);
	}
}

DEFPY (show_ip_nat_statistics,
       show_ip_nat_statistics_cmd,
       "show ip nat statistics [vrf <NAME$vrf_name|all$vrf_all>] [json$json]",
       SHOW_STR
       IP_STR
       "Network address translation\n"
       "Translation statistics (kernel conntrack state)\n"
       VRF_FULL_CMD_HELP_STR
       JSON_STR)
{
	struct nat_show_filter filter;
	struct zebra_nat_ct_stats st;
	json_object *jroot = NULL, *jvrfs = NULL;
	struct vrf *vrf;
	bool printed = false;
	ns_id_t ns_id = NS_DEFAULT;
	int ret;

	ret = nat_show_filter_init(vty, &filter, vrf_name, !!vrf_all);
	if (ret != CMD_SUCCESS)
		return ret;

	if (json) {
		jroot = json_object_new_object();
		jvrfs = json_object_new_object();
	}

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		if (!nat_show_filter_match(&filter, vrf->vrf_id))
			continue;
		nat_show_stats_vrf(vty, vrf, jvrfs, &printed);
	}

	if (!json && !printed)
		vty_out(vty, "No interfaces configured for NAT\n");

	/* Kernel-wide conntrack counters, from the namespace of the VRF */
	if (!filter.all) {
		struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(filter.vrf_id);

		if (zvrf && zvrf->zns)
			ns_id = zvrf->zns->ns_id;
	}

	ret = kernel_nat_ct_stats(ns_id, &st);

	if (json) {
		json_object *jk = json_object_new_object();

		json_object_object_add(jroot, "vrfs", jvrfs);
		if (ret == 0) {
			json_object_int_add(jk, "cpus", st.cpus);
			json_object_int_add(jk, "found", st.found);
			json_object_int_add(jk, "invalid", st.invalid);
			json_object_int_add(jk, "insert", st.insert);
			json_object_int_add(jk, "insertFailed", st.insert_failed);
			json_object_int_add(jk, "drop", st.drop);
			json_object_int_add(jk, "earlyDrop", st.early_drop);
			json_object_int_add(jk, "error", st.error);
			json_object_int_add(jk, "searchRestart", st.search_restart);
			json_object_int_add(jk, "clashResolve", st.clash_resolve);
			json_object_int_add(jk, "chainTooLong", st.chain_toolong);
			if (st.has_global) {
				json_object_int_add(jk, "entries", st.entries);
				json_object_int_add(jk, "maxEntries", st.max_entries);
			}
		} else {
			json_object_string_add(jk, "error", safe_strerror(-ret));
		}
		json_object_object_add(jroot, "conntrack", jk);
		json_object_int_add(jroot, "translationsFlushed", znat.ct_flushed);
		vty_json(vty, jroot);
		return CMD_SUCCESS;
	}

	vty_out(vty, "\nKernel conntrack statistics (all zones):\n");
	if (ret < 0) {
		vty_out(vty, "  unavailable: %s\n", safe_strerror(-ret));
		return CMD_SUCCESS;
	}
	if (st.has_global)
		vty_out(vty, "  Entries: %u (max %u)\n", st.entries, st.max_entries);
	vty_out(vty,
		"  Found: %" PRIu64 ", Invalid: %" PRIu64 ", Insert: %" PRIu64
		", Insert failed: %" PRIu64 "\n",
		st.found, st.invalid, st.insert, st.insert_failed);
	vty_out(vty,
		"  Drop: %" PRIu64 ", Early drop: %" PRIu64 ", Error: %" PRIu64
		", Search restart: %" PRIu64 ", Clash resolve: %" PRIu64 "\n",
		st.drop, st.early_drop, st.error, st.search_restart, st.clash_resolve);
	vty_out(vty, "  Translations cleared by zebra: %" PRIu64 "\n", znat.ct_flushed);

	return CMD_SUCCESS;
}

DEFPY (clear_ip_nat_translation,
       clear_ip_nat_translation_cmd,
       "clear ip nat translation [vrf <NAME$vrf_name|all$vrf_all>] *",
       CLEAR_STR
       IP_STR
       "Network address translation\n"
       "Translation entries\n"
       VRF_FULL_CMD_HELP_STR
       "Delete all dynamic translations\n")
{
	struct nat_show_filter filter;
	const struct zebra_nat_outside *o;
	uint32_t deleted = 0;
	int ret;

	ret = nat_show_filter_init(vty, &filter, vrf_name, !!vrf_all);
	if (ret != CMD_SUCCESS)
		return ret;

	frr_each (nat_outside_list_const, &znat.outsides, o) {
		if (!nat_show_filter_match(&filter, o->vrf_id))
			continue;
		deleted += nat_ct_flush_zone(o->ns_id, o->zone);
	}

	vty_out(vty, "Cleared %u conntrack entries\n", deleted);

	return CMD_SUCCESS;
}

void zebra_nat_init(void)
{
	nat_outside_list_init(&znat.outsides);
	nat_ns_list_init(&znat.ready_ns);
	nat_static_list_init(&znat.statics);

	hook_register(if_real, nat_if_event);
	hook_register(if_unreal, nat_if_event);
	hook_register(if_del, nat_if_event);
	hook_register(if_up, nat_if_event);
	hook_register(if_down, nat_if_event);

	install_element(VIEW_NODE, &show_ip_nat_translations_cmd);
	install_element(VIEW_NODE, &show_ip_nat_statistics_cmd);
	install_element(ENABLE_NODE, &clear_ip_nat_translation_cmd);
}

void zebra_nat_terminate(void)
{
	struct zebra_nat_outside *o;
	struct zebra_nat_ns *nns;
	struct zebra_nat_static *st;

	/*
	 * The kernel objects are left in place on shutdown so that
	 * forwarding (and established translations) survive a zebra
	 * restart; they are cleaned up and reinstalled at the next start.
	 */
	znat.terminating = true;

	hook_unregister(if_real, nat_if_event);
	hook_unregister(if_unreal, nat_if_event);
	hook_unregister(if_del, nat_if_event);
	hook_unregister(if_up, nat_if_event);
	hook_unregister(if_down, nat_if_event);

	event_cancel(&znat.t_reconcile);

	while ((o = nat_outside_list_pop(&znat.outsides)))
		nat_outside_free(&o);
	while ((nns = nat_ns_list_pop(&znat.ready_ns)))
		XFREE(MTYPE_NAT_NS, nns);
	while ((st = nat_static_list_pop(&znat.statics)))
		XFREE(MTYPE_NAT_STATIC, st);

	nat_outside_list_fini(&znat.outsides);
	nat_ns_list_fini(&znat.ready_ns);
	nat_static_list_fini(&znat.statics);
}
