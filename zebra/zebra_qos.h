// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra class based QoS (CBWFQ style) on top of HTB.
 *
 * Copyright (C) 2026 FRRouting
 */

#ifndef _ZEBRA_QOS_H
#define _ZEBRA_QOS_H

#include <zebra.h>

#include "if.h"
#include "linklist.h"
#include "northbound.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QOS_NAME_LEN	  64
#define QOS_CLASS_DEFAULT "class-default"

enum qos_rate_type {
	QOS_RATE_NONE = 0,
	QOS_RATE_PERCENT,
	QOS_RATE_BPS,
};

struct qos_rate {
	enum qos_rate_type type;
	/* percent (1..100) or bits per second */
	uint64_t value;
};

/* HFSC service curve (rt, ls, sc or ul), as configured */
struct qos_curve {
	bool set;
	/* first segment: rate m1 for d microseconds, m1.type NONE when absent */
	struct qos_rate m1;
	uint32_t d;
	/* long term rate */
	struct qos_rate m2;
};

/* class-map NAME */
struct qos_class_map {
	char name[QOS_NAME_LEN];

	/* match-any (true) or match-all (false) */
	bool match_any;

	/* "match any" */
	bool match_all_packets;

	/* "match access-group name X", list of char * */
	struct list *acls;

	/* "match ip dscp ...", bit N set means DSCP N */
	uint64_t dscp;
};

struct qos_policy_map;

/* class NAME, inside a policy-map */
struct qos_policy_class {
	struct qos_policy_map *pmap;

	char name[QOS_NAME_LEN];

	struct qos_rate bandwidth;
	struct qos_rate max_bandwidth;

	/* HTB priority 0..7, -1 when not configured */
	int priority;

	/* HFSC service curves */
	struct qos_curve rt;
	struct qos_curve ls;
	struct qos_curve sc;
	struct qos_curve ul;

	/* packets, 0 when not configured */
	uint32_t queue_limit;

	/* child policy-map name, empty when not configured */
	char service_policy[QOS_NAME_LEN];
};

/* policy-map NAME */
struct qos_policy_map {
	char name[QOS_NAME_LEN];

	/* "policy-map NAME hfsc": HFSC instead of HTB */
	bool hfsc;

	/* struct qos_policy_class, in evaluation order */
	struct list *classes;
};

struct qos_hw;

/* Per interface QoS configuration and state, hangs off struct zebra_if */
struct zebra_if_qos {
	/* "qos bandwidth", bits per second, 0 when not configured */
	uint64_t bandwidth;

	/* "service-policy output NAME" */
	char service_policy[QOS_NAME_LEN];

	/* What is currently programmed in the kernel, NULL if nothing */
	struct qos_hw *installed;

	/* Why the policy is not installed, for show output, empty if it is */
	char reason[256];
};

/* Northbound */
extern const struct frr_yang_module_info frr_qos_info;

/* Configuration helpers used by the northbound callbacks */
extern struct qos_class_map *zebra_qos_class_map_get(const char *name);
extern void zebra_qos_class_map_del(struct qos_class_map *cmap);
extern void zebra_qos_class_map_acl_add(struct qos_class_map *cmap, const char *name);
extern void zebra_qos_class_map_acl_del(struct qos_class_map *cmap, const char *name);
extern struct qos_policy_map *zebra_qos_policy_map_get(const char *name);
extern void zebra_qos_policy_map_del(struct qos_policy_map *pmap);
extern struct qos_policy_class *zebra_qos_policy_class_add(struct qos_policy_map *pmap,
							   const char *name,
							   struct qos_policy_class *after);
extern void zebra_qos_policy_class_move(struct qos_policy_class *pclass,
					struct qos_policy_class *after);
extern void zebra_qos_policy_class_del(struct qos_policy_class *pclass);
extern struct zebra_if_qos *zebra_qos_if_get(struct interface *ifp);

/*
 * Something changed, re-evaluate every interface on the next event loop
 * iteration.  Interfaces whose resulting kernel state did not change are
 * left alone.
 */
extern void zebra_qos_config_changed(void);

/* Interface life cycle */
extern void zebra_qos_if_added(struct interface *ifp);
extern void zebra_qos_if_removed(struct interface *ifp);
extern void zebra_qos_if_fini(struct interface *ifp);

/* Called once zebra finished reading the initial kernel state */
extern void zebra_qos_startup_done(void);

extern void zebra_qos_init(void);
extern void zebra_qos_terminate(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_QOS_H */
