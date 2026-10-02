// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra - interface-facing API for configured (zebra-created) links and
 * configured interface masters.
 */

#ifndef _ZEBRA_LINK_CFG_IF_H
#define _ZEBRA_LINK_CFG_IF_H

#include "lib/if.h"
#include "zebra/zebra_link_cfg.h"
#include "zebra/zebra_link_opts.h"

#ifdef __cplusplus
extern "C" {
#endif

struct zebra_dplane_ctx;
struct zebra_link_cfg;

/*
 * Set (or replace) the configured link type for 'ifp'.  If the interface does
 * not exist in the kernel zebra will create it, as soon as any interface it
 * depends on (vlan parent, gre dev) exists.  An existing kernel interface is
 * never modified in place: if its configuration changes, a link that zebra
 * can identify as being of the old type is deleted and re-created.
 */
extern void zebra_link_cfg_set_link(struct interface *ifp,
				    const struct zebra_link_params *params);

/*
 * Remove the configured link type.  A kernel interface of the matching type
 * is deleted.
 */
extern void zebra_link_cfg_unset_link(struct interface *ifp);

/*
 * Configure the master of 'ifp' (any interface may be enslaved to any
 * master: bridge, bond, vrf, ...).  Applied as soon as both interfaces exist.
 */
extern void zebra_link_cfg_set_master(struct interface *ifp, const char *master);

/* Remove the configured master (the interface is released if we set it). */
extern void zebra_link_cfg_unset_master(struct interface *ifp);

/*
 * Configure the bridge-port VLAN membership of 'ifp' for one VLAN.  Applied
 * once the interface is enslaved to a bridge, and re-applied if it is
 * enslaved again or re-created.  See enum zebra_link_vlan_mode.
 */
extern void zebra_link_cfg_set_bridge_vlan(struct interface *ifp, uint16_t vid,
					   enum zebra_link_vlan_mode mode);

/* Remove the configuration for one VLAN; a membership we added is removed. */
extern void zebra_link_cfg_unset_bridge_vlan(struct interface *ifp, uint16_t vid);

/* Native VLAN (PVID) of the port; 0 to unset */
extern void zebra_link_cfg_set_bridge_pvid(struct interface *ifp, uint16_t vid);

/*
 * Settings of a bridge (scope ZLO_SCOPE_BRIDGE, on a bridge interface) or of
 * a bridge port (ZLO_SCOPE_PORT, once enslaved), see zebra_link_opts.h.
 * Applied in place; 'val' is the stored form of the value.  Removing a
 * setting that was applied sets the kernel default again.
 */
extern void zebra_link_cfg_set_opt(struct interface *ifp, enum zebra_link_opt_scope scope,
				   unsigned int idx, uint64_t val);
extern void zebra_link_cfg_unset_opt(struct interface *ifp, enum zebra_link_opt_scope scope,
				     unsigned int idx);

/* Lookups for show/config-write */
extern const struct zebra_link_params *
zebra_link_cfg_get_link(const struct interface *ifp);
extern const char *zebra_link_cfg_get_master(const struct interface *ifp);

/* Event hooks, called from the interface code */
extern void zebra_link_cfg_if_added(struct interface *ifp);
extern void zebra_link_cfg_if_deleted(struct interface *ifp);
extern void zebra_link_cfg_if_free(struct interface *ifp);

/* Dataplane result handler for the DPLANE_OP_LINK_* operations */
extern void zebra_link_cfg_dplane_result(struct zebra_dplane_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_LINK_CFG_IF_H */
