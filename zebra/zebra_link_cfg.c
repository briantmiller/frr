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
#include "zebra/ioctl.h"
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

/* Bond settings that are not one number, see zebra_link_cfg_set_bond_primary */
struct zebra_link_bondx {
	bool has_primary;
	char primary[IFNAMSIZ];
	bool primary_applied; /* we gave the kernel a primary, to be cleared again */
	bool primary_dirty;   /* configured, not applied yet (maybe that interface is missing) */

	unsigned int n_arp;
	struct in_addr arp[ZEBRA_LINK_BOND_MAX_TARGETS];
	bool arp_applied;
	bool arp_dirty;

	unsigned int n_ns;
	struct in6_addr ns[ZEBRA_LINK_BOND_MAX_TARGETS];
	bool ns_applied;
	bool ns_dirty;
};

struct zebra_link_cfg {
	/* Desired kernel link */
	bool has_link;
	struct zebra_link_params params;
	bool create_inflight;
	/* What the queued create asked for, to notice when it became unwanted */
	struct zebra_link_params create_params;
	/*
	 * A create that succeeded after the link-type was removed or changed.
	 * The link it made is deleted again once it shows up as an interface.
	 */
	bool create_stale;
	enum zebra_link_kind stale_kind;

	/* Desired master */
	bool has_master;
	char master[IFNAMSIZ];
	bool master_inflight;
	/* Setting the master failed: not tried again until the configuration changes */
	bool master_failed;
	/* ifindex of the master we last successfully enslaved to, or 0 */
	ifindex_t master_applied;

	/*
	 * A link zebra created is brought up administratively once it exists and its
	 * settings are in (tried once per kernel link; not forced again later).
	 */
	bool up_done;

	/* Desired MTU */
	bool has_mtu;
	uint32_t mtu;
	bool mtu_inflight;
	/* Tried once for this value on this kernel link (not retried by itself) */
	bool mtu_done;
	/* We changed the MTU; mtu_orig is what it was before */
	bool mtu_changed;
	uint32_t mtu_orig;

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
	struct zebra_link_bondx *bondx;
};

static struct event *t_link_cfg_kick;

/* Anything configured, or still to be removed from the kernel, in bondx? */
static bool bondx_active(const struct zebra_link_cfg *cfg)
{
	const struct zebra_link_bondx *x = cfg->bondx;

	return x && (x->has_primary || x->primary_applied || x->n_arp || x->arp_applied ||
		     x->n_ns || x->ns_applied);
}

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
	    cfg->create_stale || cfg->master_inflight || cfg->has_mtu || cfg->mtu_inflight ||
	    cfg->vl || cfg->brport_inflight || cfg->isolated_set || cfg->opt[ZLO_SCOPE_BRIDGE] ||
	    cfg->opt[ZLO_SCOPE_PORT] || cfg->opt_reset[ZLO_SCOPE_BRIDGE] ||
	    cfg->opt_reset[ZLO_SCOPE_PORT] || cfg->opt_inflight[ZLO_SCOPE_BRIDGE] ||
	    cfg->opt_inflight[ZLO_SCOPE_PORT] || cfg->opt[ZLO_SCOPE_BOND] ||
	    cfg->opt_reset[ZLO_SCOPE_BOND] || cfg->opt_inflight[ZLO_SCOPE_BOND] ||
	    bondx_active(cfg))
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
	case ZEBRA_LINK_VXLAN:
		return IS_ZEBRA_IF_VXLAN(ifp);
	case ZEBRA_LINK_BAREUDP:
		return IS_ZEBRA_IF_BAREUDP(ifp);
	case ZEBRA_LINK_BOND:
		return IS_ZEBRA_IF_BOND(ifp);
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
 * Add the bond settings that are not one number to the request: whatever is
 * configured, and an empty value for what was configured and has been removed.
 */
static void bond_fill_extras(struct interface *ifp, struct zebra_link_cfg *cfg,
			     struct zebra_link_opts_req *req)
{
	struct zebra_link_bondx *x = cfg->bondx;
	struct interface *pifp;
	unsigned int i;

	if (!x)
		return;

	/* Only what changed since it was last sent (or what is new in the kernel) */
	if (x->has_primary) {
		pifp = x->primary_dirty ? link_cfg_lookup(ifp, x->primary) : NULL;
		if (pifp && ifp_is_real(pifp)) {
			req->has_primary = true;
			req->primary_ifindex = pifp->ifindex;
			x->primary_applied = true;
			/* If that interface does not exist yet it stays dirty and is applied when it appears */
			x->primary_dirty = false;
		}
	} else if (x->primary_applied) {
		req->has_primary = true;
		req->primary_ifindex = 0;
		x->primary_applied = false;
	}

	if ((x->n_arp || x->arp_applied) && x->arp_dirty) {
		req->has_arp_targets = true;
		req->n_arp_targets = x->n_arp;
		for (i = 0; i < x->n_arp; i++)
			req->arp_targets[i] = x->arp[i].s_addr;
		x->arp_applied = x->n_arp != 0;
		x->arp_dirty = false;
	}

	if ((x->n_ns || x->ns_applied) && x->ns_dirty) {
		req->has_ns_targets = true;
		req->n_ns_targets = x->n_ns;
		for (i = 0; i < x->n_ns; i++)
			memcpy(req->ns_targets[i], &x->ns[i], 16);
		x->ns_applied = x->n_ns != 0;
		x->ns_dirty = false;
	}
}

/* Is the primary slave configured, not applied yet, and does it exist now? */
static bool bond_primary_ready(struct interface *ifp, const struct zebra_link_cfg *cfg)
{
	const struct zebra_link_bondx *x = cfg->bondx;
	struct interface *pifp;

	if (!x || !x->has_primary || !x->primary_dirty)
		return false;
	pifp = link_cfg_lookup(ifp, x->primary);
	return pifp && ifp_is_real(pifp);
}

static void opts_queue(struct interface *ifp, struct zebra_link_cfg *cfg,
		       const struct zebra_link_opts_req *req)
{
	cfg->opt_inflight[req->scope]++;
	if (dplane_link_opts_set(ifp, req) != ZEBRA_DPLANE_REQUEST_QUEUED) {
		cfg->opt_inflight[req->scope]--;
		zlog_warn("%s: unable to queue settings for %s", __func__, ifp->name);
	}
}

/*
 * Push the settings of one scope.  Everything configured is sent (they are
 * idempotent), plus the kernel default for settings that were removed.
 */
static void opts_apply(struct interface *ifp, struct zebra_link_cfg *cfg,
		       enum zebra_link_opt_scope scope, ifindex_t bridge_ifindex)
{
	struct zebra_link_optset *set = cfg->opt[scope];
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
			/*
			 * Bond settings are sent one by one and a refused one is
			 * not retried, so send only what changed since last time.
			 */
			if (scope == ZLO_SCOPE_BOND && (set->sent_mask & (1ULL << i)) &&
			    set->sent[i] == set->val[i])
				continue;
			if (scope == ZLO_SCOPE_BOND) {
				set->sent_mask |= 1ULL << i;
				set->sent[i] = set->val[i];
			}
			req->item[req->count].idx = i;
			req->item[req->count++].val = set->val[i];
		} else if ((cfg->opt_reset[scope] & (1ULL << i)) && t[i].def != ZLO_NODEFAULT) {
			if (set)
				set->sent_mask &= ~(1ULL << i);
			req->item[req->count].idx = i;
			req->item[req->count++].val = t[i].def;
		}
	}

	if (scope == ZLO_SCOPE_BOND)
		bond_fill_extras(ifp, cfg, req);

	if (set)
		cfg->opt_applied_mask[scope] |= set->mask;
	cfg->opt_applied_mask[scope] &= ~cfg->opt_reset[scope];
	cfg->opt_reset[scope] = 0;

	if (scope == ZLO_SCOPE_BOND) {
		/*
		 * The kernel stops at the first bond attribute it refuses, so one
		 * the bond cannot take in its current mode would hide all the
		 * ones after it.  Send them one by one, in the order the kernel
		 * itself applies them.
		 */
		struct zebra_link_opts_req one;

		for (i = 0; i < req->count; i++) {
			memset(&one, 0, sizeof(one));
			one.scope = scope;
			one.count = 1;
			one.item[0] = req->item[i];
			opts_queue(ifp, cfg, &one);
		}
		if (req->has_arp_targets) {
			memset(&one, 0, sizeof(one));
			one.scope = scope;
			one.has_arp_targets = true;
			one.n_arp_targets = req->n_arp_targets;
			memcpy(one.arp_targets, req->arp_targets, sizeof(one.arp_targets));
			opts_queue(ifp, cfg, &one);
		}
		if (req->has_ns_targets) {
			memset(&one, 0, sizeof(one));
			one.scope = scope;
			one.has_ns_targets = true;
			one.n_ns_targets = req->n_ns_targets;
			memcpy(one.ns_targets, req->ns_targets, sizeof(one.ns_targets));
			opts_queue(ifp, cfg, &one);
		}
		if (req->has_primary) {
			memset(&one, 0, sizeof(one));
			one.scope = scope;
			one.has_primary = true;
			one.primary_ifindex = req->primary_ifindex;
			opts_queue(ifp, cfg, &one);
		}
	} else if (req->count) {
		opts_queue(ifp, cfg, req);
	}
	XFREE(MTYPE_ZEBRA_LINK_CFG, req);

	if (set && !set->mask) {
		XFREE(MTYPE_ZEBRA_LINK_CFG, cfg->opt[scope]);
	}
}

/*
 * A new Linux link starts administratively down, and nothing else in zebra
 * brings it up unless an address is configured on it.  A link that zebra was
 * asked to create is meant to be used, so it is brought up, unless "shutdown"
 * is configured.  This waits for what the kernel wants to be done on a down
 * link (bond settings such as ad-select cannot be changed on a bond that is
 * up) and for the master to be set, and is done once per kernel link: if
 * somebody sets it down afterwards, that is left alone.
 */
static bool link_cfg_shutdown_configured(const struct interface *ifp)
{
	const struct zebra_if *zif = ifp->info;

	return zif && zif->shutdown == IF_ZEBRA_DATA_ON;
}

static void link_cfg_set_up(struct interface *ifp)
{
	if (if_is_up(ifp))
		return;

	if (if_set_flags(ifp, IFF_UP | IFF_RUNNING) < 0) {
		zlog_warn("Unable to bring up %s", ifp->name);
		return;
	}
	if_refresh(ifp);
	/* IPv6 addresses are removed when a link goes down; add them again */
	if_addr_wakeup(ifp);
}

static void link_cfg_admin_up(struct interface *ifp, struct zebra_link_cfg *cfg)
{
	struct interface *peer = NULL;
	unsigned int scope;

	if (!link_matches_kind(ifp, cfg->params.kind))
		return;

	if (cfg->create_inflight || cfg->master_inflight || cfg->mtu_inflight ||
	    cfg->brport_inflight)
		return;
	for (scope = 0; scope < ZLO_SCOPE_MAX; scope++)
		if (cfg->opt_inflight[scope])
			return;
	/* Bond settings go first: some can only be changed while it is down */
	if ((cfg->opt[ZLO_SCOPE_BOND] || cfg->opt_reset[ZLO_SCOPE_BOND] || bondx_active(cfg)) &&
	    cfg->opt_applied_gen[ZLO_SCOPE_BOND] != cfg->opt_gen[ZLO_SCOPE_BOND])
		return;

	if (link_cfg_shutdown_configured(ifp)) {
		cfg->up_done = true;
		return;
	}

	/* Both ends of a veth pair are ours, and a pair needs both up */
	if (cfg->params.kind == ZEBRA_LINK_VETH) {
		peer = link_cfg_lookup(ifp, cfg->params.u.veth.peer_name);
		if (!peer || !ifp_is_real(peer))
			return; /* its arrival re-evaluates this */
	}

	cfg->up_done = true;
	link_cfg_set_up(ifp);
	if (peer && !link_cfg_shutdown_configured(peer))
		link_cfg_set_up(peer);
}

/*
 * A create that succeeded after its link-type was removed or changed made a
 * link nobody wants.  Delete it, once it is known as an interface and only if
 * it is what we created.  (A changed definition is created again afterwards.)
 */
static void link_cfg_drop_stale(struct interface *ifp, struct zebra_link_cfg *cfg)
{
	if (!cfg->create_stale || !ifp_is_real(ifp))
		return;

	cfg->create_stale = false;
	if (link_matches_kind(ifp, cfg->stale_kind)) {
		zlog_info("%s: removing %s, its link configuration changed while it was being created",
			  __func__, ifp->name);
		dplane_link_delete(ifp);
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

	/* --- undo a create that is no longer wanted --- */
	link_cfg_drop_stale(ifp, cfg);

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
			memcpy(&cfg->create_params, &cfg->params, sizeof(cfg->params));
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
	if (cfg->has_master && ifp_is_real(ifp) && !cfg->master_inflight && !cfg->master_failed) {
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

	/* --- mtu --- */
	if (cfg->has_mtu && ifp_is_real(ifp) && !cfg->mtu_inflight && !cfg->mtu_done) {
		if (ifp->mtu == cfg->mtu) {
			cfg->mtu_done = true;
		} else {
			/*
			 * Remember what it was so that removing the
			 * configuration can put it back.
			 */
			if (!cfg->mtu_changed)
				cfg->mtu_orig = ifp->mtu;
			cfg->mtu_inflight = true;
			if (dplane_link_mtu_set(ifp, cfg->mtu) != ZEBRA_DPLANE_REQUEST_QUEUED) {
				cfg->mtu_inflight = false;
				cfg->mtu_done = true;
				zlog_warn("%s: unable to queue mtu %u for %s", __func__,
					  cfg->mtu, ifp->name);
			}
		}
	}

	/* --- admin up, after everything above has had its say --- */
	if (cfg->has_link && ifp_is_real(ifp) && !cfg->up_done)
		link_cfg_admin_up(ifp, cfg);

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

	/* --- bond settings (this interface is a bond) --- */
	if ((cfg->opt[ZLO_SCOPE_BOND] || cfg->opt_reset[ZLO_SCOPE_BOND] || bondx_active(cfg)) &&
	    ifp_is_real(ifp) && IS_ZEBRA_IF_BOND(ifp) && !cfg->opt_inflight[ZLO_SCOPE_BOND] &&
	    (cfg->opt_applied_gen[ZLO_SCOPE_BOND] != cfg->opt_gen[ZLO_SCOPE_BOND] ||
	     bond_primary_ready(ifp, cfg)))
		opts_apply(ifp, cfg, ZLO_SCOPE_BOND, 0);

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
	cfg->master_failed = false;

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

	/*
	 * If the assignment is still in flight there is nothing to undo yet:
	 * the result handler releases the interface when it completes.
	 */
	cfg->has_master = false;
	cfg->master[0] = '\0';
	cfg->master_applied = 0;
	cfg->master_failed = false;
	link_cfg_release_if_empty(ifp);
}

void zebra_link_cfg_set_mtu(struct interface *ifp, uint32_t mtu)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, true);

	if (!cfg)
		return;

	if (!cfg->has_mtu || cfg->mtu != mtu)
		cfg->mtu_done = false;

	cfg->mtu = mtu;
	cfg->has_mtu = true;

	link_cfg_realize(ifp);
}

void zebra_link_cfg_unset_mtu(struct interface *ifp)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, false);

	if (!cfg || !cfg->has_mtu)
		return;

	/*
	 * Put the old MTU back, but only if the interface still has the one we
	 * set; if somebody else changed it since, leave it alone.
	 */
	if (ifp_is_real(ifp) && cfg->mtu_changed && cfg->mtu_orig && !cfg->mtu_inflight &&
	    ifp->mtu == cfg->mtu)
		dplane_link_mtu_set(ifp, cfg->mtu_orig);

	cfg->has_mtu = false;
	cfg->mtu = 0;
	cfg->mtu_done = false;
	cfg->mtu_changed = false;
	cfg->mtu_orig = 0;
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

/* ---- bond settings that are not one number ---- */

static struct zebra_link_bondx *bondx_get(struct zebra_link_cfg *cfg)
{
	if (!cfg->bondx)
		cfg->bondx = XCALLOC(MTYPE_ZEBRA_LINK_CFG, sizeof(*cfg->bondx));
	return cfg->bondx;
}

/* Free bondx when it holds nothing, then re-evaluate the interface */
static void bondx_changed(struct interface *ifp, struct zebra_link_cfg *cfg)
{
	cfg->opt_gen[ZLO_SCOPE_BOND]++;
	if (cfg->bondx && !bondx_active(cfg))
		XFREE(MTYPE_ZEBRA_LINK_CFG, cfg->bondx);

	link_cfg_realize(ifp);
	link_cfg_release_if_empty(ifp);
}

void zebra_link_cfg_set_bond_primary(struct interface *ifp, const char *name)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, true);
	struct zebra_link_bondx *x;

	if (!cfg)
		return;
	x = bondx_get(cfg);
	strlcpy(x->primary, name, sizeof(x->primary));
	x->has_primary = true;
	x->primary_dirty = true;
	bondx_changed(ifp, cfg);
}

void zebra_link_cfg_unset_bond_primary(struct interface *ifp)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, false);

	if (!cfg || !cfg->bondx || !cfg->bondx->has_primary)
		return;
	cfg->bondx->has_primary = false;
	cfg->bondx->primary[0] = '\0';
	cfg->bondx->primary_dirty = false;
	bondx_changed(ifp, cfg);
}

void zebra_link_cfg_bond_arp_target(struct interface *ifp, const struct in_addr *addr, bool add)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, add);
	struct zebra_link_bondx *x;
	unsigned int i;

	if (!cfg)
		return;
	if (!add && !cfg->bondx)
		return;
	x = bondx_get(cfg);

	for (i = 0; i < x->n_arp; i++)
		if (x->arp[i].s_addr == addr->s_addr)
			break;

	if (add && i == x->n_arp && x->n_arp < ZEBRA_LINK_BOND_MAX_TARGETS)
		x->arp[x->n_arp++] = *addr;
	else if (!add && i < x->n_arp) {
		memmove(&x->arp[i], &x->arp[i + 1], (x->n_arp - i - 1) * sizeof(x->arp[0]));
		x->n_arp--;
	}
	x->arp_dirty = true;
	bondx_changed(ifp, cfg);
}

void zebra_link_cfg_bond_ns_target(struct interface *ifp, const struct in6_addr *addr, bool add)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, add);
	struct zebra_link_bondx *x;
	unsigned int i;

	if (!cfg)
		return;
	if (!add && !cfg->bondx)
		return;
	x = bondx_get(cfg);

	for (i = 0; i < x->n_ns; i++)
		if (IPV6_ADDR_SAME(&x->ns[i], addr))
			break;

	if (add && i == x->n_ns && x->n_ns < ZEBRA_LINK_BOND_MAX_TARGETS)
		x->ns[x->n_ns++] = *addr;
	else if (!add && i < x->n_ns) {
		memmove(&x->ns[i], &x->ns[i + 1], (x->n_ns - i - 1) * sizeof(x->ns[0]));
		x->n_ns--;
	}
	x->ns_dirty = true;
	bondx_changed(ifp, cfg);
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
		cfg->create_stale = false;
		cfg->master_inflight = false;
		cfg->master_failed = false;
		cfg->master_applied = 0;
		/* A new kernel link starts from its own MTU */
		cfg->mtu_inflight = false;
		cfg->mtu_done = false;
		cfg->mtu_changed = false;
		cfg->mtu_orig = 0;
		cfg->up_done = false;
		/* The port state went with the interface; re-apply on return */
		cfg->vl_applied_gen = 0;
		cfg->vl_applied_bridge = 0;
		cfg->isolated_set = false;
		cfg->brport_inflight = 0;
		/* The settings went with the interface; apply them again on return */
		cfg->opt_applied_gen[ZLO_SCOPE_BRIDGE] = 0;
		cfg->opt_applied_gen[ZLO_SCOPE_PORT] = 0;
		cfg->opt_applied_gen[ZLO_SCOPE_BOND] = 0;
		if (cfg->opt[ZLO_SCOPE_BOND])
			cfg->opt[ZLO_SCOPE_BOND]->sent_mask = 0;
		if (cfg->bondx) {
			/* Nothing of it is in the kernel any more */
			cfg->bondx->primary_applied = false;
			cfg->bondx->primary_dirty = cfg->bondx->has_primary;
			cfg->bondx->arp_applied = false;
			cfg->bondx->arp_dirty = cfg->bondx->n_arp != 0;
			cfg->bondx->ns_applied = false;
			cfg->bondx->ns_dirty = cfg->bondx->n_ns != 0;
		}
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
		XFREE(MTYPE_ZEBRA_LINK_CFG, zif->link_cfg->opt[ZLO_SCOPE_BOND]);
		XFREE(MTYPE_ZEBRA_LINK_CFG, zif->link_cfg->bondx);
		XFREE(MTYPE_ZEBRA_LINK_CFG, zif->link_cfg);
	}
}

/* ---- dataplane results ---- */

/*
 * The interface a result is about.  It may have changed VRF since the request
 * was made (enslaving it to a VRF device moves it), so it is found by its
 * index in the namespace first, and by name in the VRF it was in only if that
 * is not possible (it has no index before it is created).
 */
static struct interface *link_cfg_result_ifp(const struct zebra_dplane_ctx *ctx)
{
	const char *name = dplane_ctx_get_ifname(ctx);
	ifindex_t idx = dplane_ctx_get_ifindex(ctx);
	struct interface *ifp = NULL;

	if (idx != IFINDEX_INTERNAL) {
		ifp = if_lookup_by_index_per_nsid(dplane_ctx_get_ns_id(ctx), idx);
		if (ifp && strcmp(ifp->name, name) != 0)
			ifp = NULL;
	}
	if (!ifp)
		ifp = if_lookup_by_name(name, dplane_ctx_get_vrf(ctx));
	return ifp;
}

void zebra_link_cfg_dplane_result(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op = dplane_ctx_get_op(ctx);
	bool ok = dplane_ctx_get_status(ctx) == ZEBRA_DPLANE_REQUEST_SUCCESS;
	enum zebra_link_kind kind;
	const char *name = dplane_ctx_get_ifname(ctx);
	struct interface *ifp = link_cfg_result_ifp(ctx);
	struct zebra_link_cfg *cfg = ifp ? link_cfg_get(ifp, false) : NULL;

	if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("%s: %s %s: %s", __func__, dplane_op2str(op), name,
			   ok ? "success" : "failure");

	if (op == DPLANE_OP_LINK_CREATE) {
		kind = dplane_ctx_link_get_params(ctx)->kind;
		if (cfg) {
			cfg->create_inflight = false;
			/* Wanted when it was queued, but not any more? */
			if (ok && (!cfg->has_link || memcmp(&cfg->params, &cfg->create_params,
							    sizeof(cfg->params)) != 0)) {
				cfg->create_stale = true;
				cfg->stale_kind = kind;
				/* Or later, when the interface appears */
				link_cfg_drop_stale(ifp, cfg);
			}
		}
		if (!ok)
			zlog_warn("Failed to create %s link %s in the kernel",
				  zebra_link_kind2str(kind), name);
		/* On success the kernel notification brings the interface in */
	} else if (op == DPLANE_OP_LINK_MASTER_SET) {
		ifindex_t master_ifindex = dplane_ctx_link_get_master_ifindex(ctx);

		/* Releasing a port (master 0) is not tracked as in flight */
		if (cfg && master_ifindex) {
			cfg->master_inflight = false;
			if (!ok) {
				/* Not tried again by itself, but the rest goes on */
				cfg->master_failed = true;
			} else if (!cfg->has_master) {
				/* The master was removed from the configuration meanwhile */
				cfg->master_applied = 0;
				if (ifp && ifp_is_real(ifp))
					dplane_link_master_set(ifp, 0);
			} else {
				cfg->master_applied = master_ifindex;
			}
		}
		/*
		 * VLAN settings and bringing the link up wait for this, and the
		 * kernel's notification of the enslavement is not a new interface.
		 */
		if (cfg && master_ifindex)
			link_cfg_kick();
		if (!ok)
			zlog_warn("Failed to set master of %s (master ifindex %d)", name,
				  dplane_ctx_link_get_master_ifindex(ctx));
	} else if (op == DPLANE_OP_LINK_MTU_SET) {
		if (cfg && cfg->mtu_inflight) {
			cfg->mtu_inflight = false;
			/* One attempt per value; a failure is not retried by itself */
			cfg->mtu_done = true;
			if (ok)
				cfg->mtu_changed = true;
			/* Bringing the link up waited for this */
			link_cfg_kick();
		}
		if (!ok)
			zlog_warn("Failed to set MTU of %s to %u", name, dplane_ctx_link_get_mtu(ctx));
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
		if (!ok && scope == ZLO_SCOPE_BOND) {
			unsigned int cnt;
			const struct zebra_link_opt_def *t = zebra_link_opt_table(scope, &cnt);

			zlog_warn("Failed to apply bond setting %s on %s (the bond may need to be down, without slaves, or in another mode)",
				  r->count && r->item[0].idx < cnt ? t[r->item[0].idx].name
				  : r->has_primary		    ? "primary"
				  : r->has_arp_targets		    ? "arp-ip-target"
								    : "ns-ip6-target",
				  name);
		} else if (!ok) {
			zlog_warn("Failed to apply %s settings on %s",
				  scope == ZLO_SCOPE_BRIDGE ? "bridge" : "bridge port", name);
		}
	} else if (op == DPLANE_OP_LINK_DELETE) {
		if (!ok)
			zlog_warn("Failed to delete link %s in the kernel", name);
	}

	if (ifp)
		link_cfg_release_if_empty(ifp);
}
