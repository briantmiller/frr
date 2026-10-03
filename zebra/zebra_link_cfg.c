// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra - configured (zebra-created) Linux links and interface masters.
 *
 * Configuration is declarative: zebra keeps the desired state per interface
 * and re-evaluates it ("realizes" it) whenever something relevant changes -
 * the configuration, or an interface appearing or disappearing - so config
 * ordering and startup races do not matter.  The kernel is only touched
 * through the dataplane (DPLANE_OP_LINK_*).
 */

#include <zebra.h>

#include "lib/if.h"
#include "lib/vrf.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/frrevent.h"

#include "zebra/zebra_router.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_vrf.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/zebra_link_cfg_if.h"
#include "zebra/zebra_link_netlink.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_LINK_CFG, "Zebra configured link");

/* Desired bridge-port VLAN configuration, allocated only when needed */
struct zebra_link_vlan_cfg {
	uint8_t mode[ZEBRA_LINK_VID_MAX + 1]; /* enum zebra_link_vlan_mode */
	unsigned int count;		      /* vids with a mode */
	uint16_t pvid;			      /* 0 == none */
};

struct zebra_link_cfg {
	/* Desired kernel link */
	bool has_link;
	struct zebra_link_params params;
	bool create_inflight;

	/* Desired master */
	bool has_master;
	char master[IFNAMSIZ];
	bool master_inflight;
	/* ifindex of the master we last successfully enslaved to, or 0 */
	ifindex_t master_applied;

	/* Desired bridge-port vlan state and what has been pushed to the kernel */
	struct zebra_link_vlan_cfg *vl;
	uint32_t vl_gen;	   /* bumped on every vlan configuration change */
	uint32_t vl_applied_gen;   /* generation last queued; 0 == nothing applied */
	ifindex_t vl_applied_bridge; /* bridge it was applied for */
	bool isolated_set;	   /* we set the port isolated flag */
	unsigned int brport_inflight;

	/* Bridge / bridge port settings, per enum zebra_link_opt_scope */
	struct zebra_link_optset *opt[ZLO_SCOPE_MAX];
	uint32_t opt_gen[ZLO_SCOPE_MAX];
	uint32_t opt_applied_gen[ZLO_SCOPE_MAX];
	ifindex_t opt_applied_bridge; /* port scope: the bridge applied for */
	uint64_t opt_applied_mask[ZLO_SCOPE_MAX]; /* settings pushed to the kernel */
	uint64_t opt_reset[ZLO_SCOPE_MAX];	  /* removed: set the default again */
	unsigned int opt_inflight[ZLO_SCOPE_MAX];
};

static struct event *t_link_cfg_kick;

static inline bool ifp_is_real(const struct interface *ifp)
{
	return ifp->ifindex != IFINDEX_INTERNAL;
}

static struct zebra_link_cfg *link_cfg_get(struct interface *ifp, bool create)
{
	struct zebra_if *zif = ifp->info;

	if (!zif)
		return NULL;
	if (!zif->link_cfg && create)
		zif->link_cfg = XCALLOC(MTYPE_ZEBRA_LINK_CFG, sizeof(*zif->link_cfg));
	return zif->link_cfg;
}

/* Drop the state object once nothing is configured any more. */
static void link_cfg_release_if_empty(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_link_cfg *cfg = zif ? zif->link_cfg : NULL;

	/* Keep it alive while a request is outstanding; the result handler
	 * will look at it.
	 */
	if (!cfg || cfg->has_link || cfg->has_master || cfg->create_inflight ||
	    cfg->master_inflight || cfg->vl || cfg->brport_inflight ||
	    cfg->isolated_set || cfg->opt[ZLO_SCOPE_BRIDGE] || cfg->opt[ZLO_SCOPE_PORT] ||
	    cfg->opt_reset[ZLO_SCOPE_BRIDGE] || cfg->opt_reset[ZLO_SCOPE_PORT] ||
	    cfg->opt_inflight[ZLO_SCOPE_BRIDGE] || cfg->opt_inflight[ZLO_SCOPE_PORT])
		return;

	XFREE(MTYPE_ZEBRA_LINK_CFG, zif->link_cfg);
}

/*
 * Find an interface by name.  With the netns backend interface names are only
 * unique per vrf; otherwise a name identifies exactly one interface, whatever
 * vrf (l3mdev) it is enslaved to.
 */
static struct interface *link_cfg_lookup(const struct interface *ref,
					 const char *name)
{
	struct interface *ifp;
	struct vrf *vrf;

	if (vrf_is_backend_netns())
		return if_lookup_by_name(name, ref->vrf->vrf_id);

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		ifp = if_lookup_by_name_vrf(name, vrf);
		if (ifp)
			return ifp;
	}
	return NULL;
}

static bool link_matches_kind(struct interface *ifp, enum zebra_link_kind kind)
{
	if (!ifp->info)
		return false;

	switch (kind) {
	case ZEBRA_LINK_BRIDGE:
		return IS_ZEBRA_IF_BRIDGE(ifp);
	case ZEBRA_LINK_VETH:
		return IS_ZEBRA_IF_VETH(ifp);
	case ZEBRA_LINK_VLAN:
		return IS_ZEBRA_IF_VLAN(ifp);
	case ZEBRA_LINK_GRE:
		return IS_ZEBRA_IF_GRE(ifp);
	case ZEBRA_LINK_DUMMY:
		return IS_ZEBRA_IF_DUMMY(ifp);
	case ZEBRA_LINK_NONE:
	case ZEBRA_LINK_KIND_MAX:
		break;
	}
	return false;
}

static void brport_queue(struct interface *ifp, struct zebra_link_cfg *cfg,
			 const struct zebra_link_brport_req *req)
{
	const char *err = zebra_link_brport_validate(req);

	if (err) {
		zlog_warn("%s: bridge port request for %s rejected: %s", __func__,
			  ifp->name, err);
		return;
	}

	cfg->brport_inflight++;
	if (dplane_link_brport_set(ifp, req) != ZEBRA_DPLANE_REQUEST_QUEUED) {
		cfg->brport_inflight--;
		zlog_warn("%s: unable to queue bridge port request for %s", __func__,
			  ifp->name);
	}
}

/*
 * Push the whole desired vlan state to the kernel.  Consecutive VLANs with
 * the same mode are sent as one range.  Adds are idempotent and update the
 * flags (tagged/untagged/pvid) of an existing entry.
 */
static void brport_apply(struct interface *ifp, struct zebra_link_cfg *cfg,
			 ifindex_t bridge_ifindex)
{
	const struct zebra_link_vlan_cfg *vl = cfg->vl;
	struct zebra_link_brport_req req;
	bool any_private = false;
	unsigned int vid, start;
	uint8_t mode;

	cfg->vl_applied_gen = cfg->vl_gen;
	cfg->vl_applied_bridge = bridge_ifindex;

	if (vl) {
		for (vid = ZEBRA_LINK_VID_MIN; vid <= ZEBRA_LINK_VID_MAX;) {
			mode = vl->mode[vid];
			if (mode == ZEBRA_LINK_VLAN_UNSET) {
				vid++;
				continue;
			}

			/* The pvid is always sent on its own (single vid) */
			start = vid;
			vid++;
			if (start != vl->pvid) {
				while (vid <= ZEBRA_LINK_VID_MAX && vl->mode[vid] == mode &&
				       vid != vl->pvid)
					vid++;
			}

			memset(&req, 0, sizeof(req));
			req.vid_begin = start;
			req.vid_end = vid - 1;
			if (mode == ZEBRA_LINK_VLAN_OFF) {
				req.type = ZEBRA_LINK_BRPORT_VLAN_DEL;
			} else {
				req.type = ZEBRA_LINK_BRPORT_VLAN_ADD;
				req.untagged = (mode == ZEBRA_LINK_VLAN_UNTAGGED);
				req.pvid = (start == vl->pvid);
				if (mode == ZEBRA_LINK_VLAN_PRIVATE)
					any_private = true;
			}
			brport_queue(ifp, cfg, &req);
		}
	}

	/*
	 * The kernel only has a per-port isolation flag, see zebra_link_vlan_mode.
	 * An explicitly configured isolated setting takes precedence and is
	 * applied with the other port settings.
	 */
	if (cfg->opt[ZLO_SCOPE_PORT] && (cfg->opt[ZLO_SCOPE_PORT]->mask & (1ULL << ZPO_ISOLATED))) {
		cfg->isolated_set = false;
	} else if (any_private || cfg->isolated_set) {
		memset(&req, 0, sizeof(req));
		req.type = ZEBRA_LINK_BRPORT_ISOLATED;
		req.isolated = any_private;
		brport_queue(ifp, cfg, &req);
		cfg->isolated_set = any_private;
	}
}

/*
 * Push the settings of one scope.  Everything configured is sent (they are
 * idempotent), plus the kernel default for settings that were removed.
 */
static void opts_apply(struct interface *ifp, struct zebra_link_cfg *cfg,
		       enum zebra_link_opt_scope scope, ifindex_t bridge_ifindex)
{
	const struct zebra_link_optset *set = cfg->opt[scope];
	const struct zebra_link_opt_def *t;
	struct zebra_link_opts_req *req;
	unsigned int i, count;

	cfg->opt_applied_gen[scope] = cfg->opt_gen[scope];
	if (scope == ZLO_SCOPE_PORT)
		cfg->opt_applied_bridge = bridge_ifindex;

	t = zebra_link_opt_table(scope, &count);
	req = XCALLOC(MTYPE_ZEBRA_LINK_CFG, sizeof(*req));
	req->scope = scope;

	for (i = 0; i < count; i++) {
		if (set && (set->mask & (1ULL << i))) {
			req->item[req->count].idx = i;
			req->item[req->count++].val = set->val[i];
		} else if ((cfg->opt_reset[scope] & (1ULL << i)) && t[i].def != ZLO_NODEFAULT) {
			req->item[req->count].idx = i;
			req->item[req->count++].val = t[i].def;
		}
	}

	if (set)
		cfg->opt_applied_mask[scope] |= set->mask;
	cfg->opt_applied_mask[scope] &= ~cfg->opt_reset[scope];
	cfg->opt_reset[scope] = 0;

	if (req->count) {
		cfg->opt_inflight[scope]++;
		if (dplane_link_opts_set(ifp, req) != ZEBRA_DPLANE_REQUEST_QUEUED) {
			cfg->opt_inflight[scope]--;
			zlog_warn("%s: unable to queue settings for %s", __func__, ifp->name);
		}
	}
	XFREE(MTYPE_ZEBRA_LINK_CFG, req);

	if (set && !set->mask) {
		XFREE(MTYPE_ZEBRA_LINK_CFG, cfg->opt[scope]);
	}
}

/*
 * Bring the kernel in line with the desired state of one interface.  Safe to
 * call at any time and as often as needed.
 */
static void link_cfg_realize(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_link_cfg *cfg = zif ? zif->link_cfg : NULL;
	struct interface *dep_ifp, *master_ifp;
	const char *dep, *err;
	ifindex_t link_ifindex;

	if (!cfg)
		return;

	/* --- create --- */
	if (cfg->has_link && !ifp_is_real(ifp) && !cfg->create_inflight) {
		link_ifindex = 0;
		dep = zebra_link_params_dependency(&cfg->params);
		dep_ifp = dep ? link_cfg_lookup(ifp, dep) : NULL;

		if (dep && (!dep_ifp || !ifp_is_real(dep_ifp))) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: %s: waiting for %s to exist", __func__,
					   ifp->name, dep);
		} else if ((err = zebra_link_params_validate(ifp->name, &cfg->params))) {
			zlog_warn("%s: not creating %s link %s: %s", __func__,
				  zebra_link_kind2str(cfg->params.kind), ifp->name, err);
		} else {
			if (dep_ifp)
				link_ifindex = dep_ifp->ifindex;

			cfg->create_inflight = true;
			if (dplane_link_create(ifp, &cfg->params, link_ifindex) !=
			    ZEBRA_DPLANE_REQUEST_QUEUED) {
				cfg->create_inflight = false;
				zlog_warn("%s: unable to queue creation of %s link %s",
					  __func__, zebra_link_kind2str(cfg->params.kind),
					  ifp->name);
			}
		}
	}

	/* --- master --- */
	if (cfg->has_master && ifp_is_real(ifp) && !cfg->master_inflight) {
		master_ifp = link_cfg_lookup(ifp, cfg->master);

		if (!master_ifp || !ifp_is_real(master_ifp)) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: %s: waiting for master %s to exist",
					   __func__, ifp->name, cfg->master);
		} else if (master_ifp == ifp) {
			zlog_warn("%s: interface %s cannot be its own master", __func__,
				  ifp->name);
		} else if (cfg->master_applied != master_ifp->ifindex ||
			   (zif->brslave_info.bridge_ifindex &&
			    zif->brslave_info.bridge_ifindex != master_ifp->ifindex)) {
			/*
			 * Not known to be enslaved to the right master (or the
			 * kernel reports a different bridge): (re)apply.
			 */
			cfg->master_inflight = true;
			if (dplane_link_master_set(ifp, master_ifp->ifindex) !=
			    ZEBRA_DPLANE_REQUEST_QUEUED) {
				cfg->master_inflight = false;
				zlog_warn("%s: unable to queue master %s for %s", __func__,
					  cfg->master, ifp->name);
			}
		}
	}

	/* --- bridge port vlans --- */
	if ((cfg->vl || cfg->isolated_set) && ifp_is_real(ifp) && !cfg->master_inflight &&
	    !cfg->brport_inflight) {
		ifindex_t bridge = zif->brslave_info.bridge_ifindex
					   ? zif->brslave_info.bridge_ifindex
					   : cfg->master_applied;

		if (bridge && (cfg->vl_applied_gen != cfg->vl_gen ||
			       cfg->vl_applied_bridge != bridge))
			brport_apply(ifp, cfg, bridge);
	}

	/* --- bridge settings (this interface is a bridge) --- */
	if ((cfg->opt[ZLO_SCOPE_BRIDGE] || cfg->opt_reset[ZLO_SCOPE_BRIDGE]) && ifp_is_real(ifp) &&
	    IS_ZEBRA_IF_BRIDGE(ifp) && !cfg->opt_inflight[ZLO_SCOPE_BRIDGE] &&
	    cfg->opt_applied_gen[ZLO_SCOPE_BRIDGE] != cfg->opt_gen[ZLO_SCOPE_BRIDGE])
		opts_apply(ifp, cfg, ZLO_SCOPE_BRIDGE, 0);

	/* --- bridge port settings (this interface is enslaved to a bridge) --- */
	if ((cfg->opt[ZLO_SCOPE_PORT] || cfg->opt_reset[ZLO_SCOPE_PORT]) && ifp_is_real(ifp) &&
	    !cfg->master_inflight && !cfg->opt_inflight[ZLO_SCOPE_PORT]) {
		ifindex_t bridge = zif->brslave_info.bridge_ifindex
					   ? zif->brslave_info.bridge_ifindex
					   : cfg->master_applied;

		if (bridge && (cfg->opt_applied_gen[ZLO_SCOPE_PORT] != cfg->opt_gen[ZLO_SCOPE_PORT] ||
			       cfg->opt_applied_bridge != bridge))
			opts_apply(ifp, cfg, ZLO_SCOPE_PORT, bridge);
	}
}

static void link_cfg_realize_all(struct event *event)
{
	struct vrf *vrf;
	struct interface *ifp;
	struct zebra_if *zif;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			zif = ifp->info;
			if (zif && zif->link_cfg)
				link_cfg_realize(ifp);
		}
	}
}

/*
 * Re-evaluate every configured interface from the main loop, so we never act
 * in the middle of processing a kernel notification.
 */
static void link_cfg_kick(void)
{
	/* Never create (or delete) anything while zebra is going away */
	if (zebra_router_in_shutdown())
		return;

	event_add_event(zrouter.master, link_cfg_realize_all, NULL, 0, &t_link_cfg_kick);
}

/* ---- configuration API ---- */

void zebra_link_cfg_set_link(struct interface *ifp,
			     const struct zebra_link_params *params)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, true);

	if (!cfg)
		return;

	if (cfg->has_link && memcmp(&cfg->params, params, sizeof(*params)) == 0) {
		/* nothing changed */
		link_cfg_realize(ifp);
		return;
	}

	/*
	 * Parameters changed.  A link zebra can recognise as the old type is
	 * removed so the new definition can be created; the creation follows
	 * from the interface-deleted event.  If the existing interface is not
	 * recognisably of the old type we leave it alone.
	 */
	if (cfg->has_link && ifp_is_real(ifp) &&
	    link_matches_kind(ifp, cfg->params.kind)) {
		zlog_info("%s: link configuration of %s changed, re-creating it", __func__,
			  ifp->name);
		dplane_link_delete(ifp);
	}

	memcpy(&cfg->params, params, sizeof(*params));
	cfg->has_link = true;

	link_cfg_realize(ifp);
}

void zebra_link_cfg_unset_link(struct interface *ifp)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, false);

	if (!cfg || !cfg->has_link)
		return;

	/* Only ever delete something we can positively identify */
	if (ifp_is_real(ifp) && link_matches_kind(ifp, cfg->params.kind))
		dplane_link_delete(ifp);

	cfg->has_link = false;
	memset(&cfg->params, 0, sizeof(cfg->params));
	link_cfg_release_if_empty(ifp);
}

void zebra_link_cfg_set_master(struct interface *ifp, const char *master)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, true);

	if (!cfg)
		return;

	if (!cfg->has_master || strcmp(cfg->master, master) != 0)
		cfg->master_applied = 0;

	strlcpy(cfg->master, master, sizeof(cfg->master));
	cfg->has_master = true;

	link_cfg_realize(ifp);
}

void zebra_link_cfg_unset_master(struct interface *ifp)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, false);
	struct zebra_if *zif = ifp->info;
	struct interface *master_ifp;

	if (!cfg || !cfg->has_master)
		return;

	/*
	 * Release the interface only if it is (as far as we know) enslaved to
	 * the master we configured; never clear a master someone else set.
	 */
	if (ifp_is_real(ifp)) {
		master_ifp = link_cfg_lookup(ifp, cfg->master);
		if (master_ifp && ifp_is_real(master_ifp) &&
		    (cfg->master_applied == master_ifp->ifindex ||
		     zif->brslave_info.bridge_ifindex == master_ifp->ifindex))
			dplane_link_master_set(ifp, 0);
	}

	cfg->has_master = false;
	cfg->master[0] = '\0';
	cfg->master_applied = 0;
	link_cfg_release_if_empty(ifp);
}

void zebra_link_cfg_set_bridge_vlan(struct interface *ifp, uint16_t vid,
				    enum zebra_link_vlan_mode mode)
{
	struct zebra_link_cfg *cfg;

	if (vid < ZEBRA_LINK_VID_MIN || vid > ZEBRA_LINK_VID_MAX ||
	    mode == ZEBRA_LINK_VLAN_UNSET)
		return;

	cfg = link_cfg_get(ifp, true);
	if (!cfg)
		return;
	if (!cfg->vl)
		cfg->vl = XCALLOC(MTYPE_ZEBRA_LINK_CFG, sizeof(*cfg->vl));

	if (cfg->vl->mode[vid] == ZEBRA_LINK_VLAN_UNSET)
		cfg->vl->count++;
	if (cfg->vl->mode[vid] != mode) {
		cfg->vl->mode[vid] = mode;
		cfg->vl_gen++;
	}

	link_cfg_realize(ifp);
}

static void link_cfg_vl_release_if_empty(struct zebra_link_cfg *cfg)
{
	if (cfg->vl && !cfg->vl->count && !cfg->vl->pvid)
		XFREE(MTYPE_ZEBRA_LINK_CFG, cfg->vl);
}

void zebra_link_cfg_unset_bridge_vlan(struct interface *ifp, uint16_t vid)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, false);
	struct zebra_if *zif = ifp->info;
	struct zebra_link_brport_req req;
	uint8_t old;

	if (!cfg || !cfg->vl || vid < ZEBRA_LINK_VID_MIN || vid > ZEBRA_LINK_VID_MAX)
		return;
	old = cfg->vl->mode[vid];
	if (old == ZEBRA_LINK_VLAN_UNSET)
		return;

	/* Take back a membership we added (an explicit "off" is just forgotten) */
	if (old != ZEBRA_LINK_VLAN_OFF && ifp_is_real(ifp) && cfg->vl_applied_gen &&
	    zif->brslave_info.bridge_ifindex) {
		memset(&req, 0, sizeof(req));
		req.type = ZEBRA_LINK_BRPORT_VLAN_DEL;
		req.vid_begin = req.vid_end = vid;
		brport_queue(ifp, cfg, &req);
	}

	cfg->vl->mode[vid] = ZEBRA_LINK_VLAN_UNSET;
	cfg->vl->count--;
	if (cfg->vl->pvid == vid)
		cfg->vl->pvid = 0;
	cfg->vl_gen++;
	link_cfg_vl_release_if_empty(cfg);

	link_cfg_realize(ifp);
	link_cfg_release_if_empty(ifp);
}

void zebra_link_cfg_set_bridge_pvid(struct interface *ifp, uint16_t vid)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, vid != 0);

	if (!cfg)
		return;
	if (vid == 0 && !cfg->vl)
		return;
	if (!cfg->vl)
		cfg->vl = XCALLOC(MTYPE_ZEBRA_LINK_CFG, sizeof(*cfg->vl));

	if (cfg->vl->pvid != vid) {
		cfg->vl->pvid = vid;
		cfg->vl_gen++;
	}
	link_cfg_vl_release_if_empty(cfg);

	link_cfg_realize(ifp);
	link_cfg_release_if_empty(ifp);
}

void zebra_link_cfg_set_opt(struct interface *ifp, enum zebra_link_opt_scope scope,
			    unsigned int idx, uint64_t val)
{
	struct zebra_link_cfg *cfg;
	struct zebra_link_optset *set;

	if (scope >= ZLO_SCOPE_MAX || idx >= ZLO_MAX)
		return;
	cfg = link_cfg_get(ifp, true);
	if (!cfg)
		return;

	if (!cfg->opt[scope])
		cfg->opt[scope] = XCALLOC(MTYPE_ZEBRA_LINK_CFG, sizeof(*cfg->opt[scope]));
	set = cfg->opt[scope];

	if (!(set->mask & (1ULL << idx)) || set->val[idx] != val) {
		set->mask |= 1ULL << idx;
		set->val[idx] = val;
		cfg->opt_reset[scope] &= ~(1ULL << idx);
		cfg->opt_gen[scope]++;
		if (scope == ZLO_SCOPE_PORT && idx == ZPO_ISOLATED)
			cfg->vl_gen++;
	}

	link_cfg_realize(ifp);
}

void zebra_link_cfg_unset_opt(struct interface *ifp, enum zebra_link_opt_scope scope,
			      unsigned int idx)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, false);
	struct zebra_link_optset *set;

	if (!cfg || scope >= ZLO_SCOPE_MAX || idx >= ZLO_MAX)
		return;
	set = cfg->opt[scope];
	if (!set || !(set->mask & (1ULL << idx)))
		return;

	set->mask &= ~(1ULL << idx);
	set->val[idx] = 0;
	/* Put the kernel default back, if we had changed it */
	if (cfg->opt_applied_mask[scope] & (1ULL << idx))
		cfg->opt_reset[scope] |= 1ULL << idx;
	cfg->opt_gen[scope]++;
	if (scope == ZLO_SCOPE_PORT && idx == ZPO_ISOLATED)
		cfg->vl_gen++;

	if (!set->mask)
		XFREE(MTYPE_ZEBRA_LINK_CFG, cfg->opt[scope]);

	link_cfg_realize(ifp);
	link_cfg_release_if_empty(ifp);
}

const struct zebra_link_params *zebra_link_cfg_get_link(const struct interface *ifp)
{
	const struct zebra_if *zif = ifp->info;

	if (zif && zif->link_cfg && zif->link_cfg->has_link)
		return &zif->link_cfg->params;
	return NULL;
}

const char *zebra_link_cfg_get_master(const struct interface *ifp)
{
	const struct zebra_if *zif = ifp->info;

	if (zif && zif->link_cfg && zif->link_cfg->has_master)
		return zif->link_cfg->master;
	return NULL;
}

/* ---- events from the interface code ---- */

void zebra_link_cfg_if_added(struct interface *ifp)
{
	/*
	 * Something new exists: this interface may now be creatable or
	 * enslavable, and other interfaces may have been waiting for it.
	 */
	link_cfg_kick();
}

void zebra_link_cfg_if_deleted(struct interface *ifp)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, false);

	if (cfg) {
		/* The kernel state we recorded is gone */
		cfg->create_inflight = false;
		cfg->master_inflight = false;
		cfg->master_applied = 0;
		/* The port state went with the interface; re-apply on return */
		cfg->vl_applied_gen = 0;
		cfg->vl_applied_bridge = 0;
		cfg->isolated_set = false;
		cfg->brport_inflight = 0;
		/* The settings went with the interface; apply them again on return */
		cfg->opt_applied_gen[ZLO_SCOPE_BRIDGE] = 0;
		cfg->opt_applied_gen[ZLO_SCOPE_PORT] = 0;
		cfg->opt_applied_bridge = 0;
		memset(cfg->opt_applied_mask, 0, sizeof(cfg->opt_applied_mask));
		memset(cfg->opt_reset, 0, sizeof(cfg->opt_reset));
		memset(cfg->opt_inflight, 0, sizeof(cfg->opt_inflight));
	}

	/*
	 * A changed link definition is re-created from here, once the old
	 * interface is gone.  If the link was removed behind our back it is
	 * re-created as well, which is what a declarative config means.
	 */
	link_cfg_kick();
}

void zebra_link_cfg_if_free(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	if (zif && zif->link_cfg) {
		XFREE(MTYPE_ZEBRA_LINK_CFG, zif->link_cfg->vl);
		XFREE(MTYPE_ZEBRA_LINK_CFG, zif->link_cfg->opt[ZLO_SCOPE_BRIDGE]);
		XFREE(MTYPE_ZEBRA_LINK_CFG, zif->link_cfg->opt[ZLO_SCOPE_PORT]);
		XFREE(MTYPE_ZEBRA_LINK_CFG, zif->link_cfg);
	}
}

/* ---- dataplane results ---- */

void zebra_link_cfg_dplane_result(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op = dplane_ctx_get_op(ctx);
	bool ok = dplane_ctx_get_status(ctx) == ZEBRA_DPLANE_REQUEST_SUCCESS;
	enum zebra_link_kind kind;
	const char *name = dplane_ctx_get_ifname(ctx);
	struct interface *ifp = if_lookup_by_name(name, dplane_ctx_get_vrf(ctx));
	struct zebra_link_cfg *cfg = ifp ? link_cfg_get(ifp, false) : NULL;

	if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("%s: %s %s: %s", __func__, dplane_op2str(op), name,
			   ok ? "success" : "failure");

	if (op == DPLANE_OP_LINK_CREATE) {
		kind = dplane_ctx_link_get_params(ctx)->kind;
		if (cfg)
			cfg->create_inflight = false;
		if (!ok)
			zlog_warn("Failed to create %s link %s in the kernel",
				  zebra_link_kind2str(kind), name);
		/* On success the kernel notification brings the interface in */
	} else if (op == DPLANE_OP_LINK_MASTER_SET) {
		if (cfg) {
			cfg->master_inflight = false;
			if (ok)
				cfg->master_applied = dplane_ctx_link_get_master_ifindex(ctx);
		}
		/* VLAN settings wait for the enslavement */
		if (ok)
			link_cfg_kick();
		if (!ok)
			zlog_warn("Failed to set master of %s (master ifindex %d)", name,
				  dplane_ctx_link_get_master_ifindex(ctx));
	} else if (op == DPLANE_OP_LINK_BRPORT_SET) {
		if (cfg && cfg->brport_inflight)
			cfg->brport_inflight--;
		/* Configuration may have changed while this was in flight */
		if (cfg && !cfg->brport_inflight)
			link_cfg_kick();
		/*
		 * A failure is not retried by itself (that would loop on a
		 * permanent error, e.g. a kernel without bridge VLAN support):
		 * the settings are tried again when the configuration changes
		 * or the interface or its master is re-created.
		 */
		if (!ok)
			zlog_warn("Failed to apply bridge port setting on %s", name);
	} else if (op == DPLANE_OP_LINK_OPTS_SET) {
		const struct zebra_link_opts_req *r = dplane_ctx_link_get_opts(ctx);
		enum zebra_link_opt_scope scope = r ? r->scope : ZLO_SCOPE_MAX;

		if (cfg && scope < ZLO_SCOPE_MAX && cfg->opt_inflight[scope]) {
			cfg->opt_inflight[scope]--;
			/* Configuration may have changed while this was in flight */
			if (!cfg->opt_inflight[scope])
				link_cfg_kick();
		}
		/* Not retried by itself, like the vlans */
		if (!ok)
			zlog_warn("Failed to apply %s settings on %s",
				  scope == ZLO_SCOPE_BRIDGE ? "bridge" : "bridge port", name);
	} else if (op == DPLANE_OP_LINK_DELETE) {
		if (!ok)
			zlog_warn("Failed to delete link %s in the kernel", name);
	}

	if (ifp)
		link_cfg_release_if_empty(ifp);
}
