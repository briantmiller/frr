// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Interface access control: "ip access-group NAME in|out" with extended
 * access-lists, implemented with tc flower filters on a clsact qdisc.
 *
 * Copyright (C) 2026 FRRouting
 */

#ifndef _ZEBRA_ACL_GROUP_H
#define _ZEBRA_ACL_GROUP_H

#include <zebra.h>

#ifdef __cplusplus
extern "C" {
#endif

enum aclg_dir {
	ACLG_IN = 0,
	ACLG_OUT,
	ACLG_DIRS,
};

struct aclg_state;
struct interface;
struct zebra_dplane_ctx;

/* (Re)program the access-groups of an interface, called on any change */
extern void zebra_acl_group_if_apply(struct interface *ifp);

/*
 * After all interfaces were applied: clean up what a previous zebra left on
 * interfaces that have no access-group (any more).
 */
extern void zebra_acl_group_apply_done(void);

/* The interface went away, and its clsact qdisc with it */
extern void zebra_acl_group_if_removed(struct interface *ifp);

/* Free the state of an interface */
extern void zebra_acl_group_if_fini(struct interface *ifp);

/* The initial kernel state was read; starts the hold time for stale filters */
extern void zebra_acl_group_startup_done(void);

/* A clsact qdisc exists at startup: it may hold filters of a previous run */
extern void zebra_acl_group_startup_clsact(ifindex_t ifindex);

/* A clsact qdisc was deleted (by someone else): its filters are gone */
extern void zebra_acl_group_clsact_deleted(ifindex_t ifindex);

/* Result of a tc filter operation from the dataplane */
extern void zebra_acl_group_dplane_result(struct zebra_dplane_ctx *ctx);

extern void zebra_acl_group_init(void);
extern void zebra_acl_group_terminate(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_ACL_GROUP_H */
