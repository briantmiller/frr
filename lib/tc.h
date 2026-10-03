// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Traffic Control (TC) main header
 * Copyright (C) 2022  Shichu Yang
 */

#ifndef _TC_H
#define _TC_H

#include <zebra.h>
#include "stream.h"
#include "prefix.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TC_STR "Traffic Control\n"

/* qdisc definitions */

/* qdisc kind (same as class kinds) */
enum tc_qdisc_kind {
	TC_QDISC_UNSPEC,
	TC_QDISC_HTB,
	TC_QDISC_NOQUEUE,
	TC_QDISC_PFIFO,
};

struct tc_qdisc_htb {
	/* minor number of the default class, 0 means "no default class" */
	uint32_t defcls;
};

struct tc_qdisc_fifo {
	/* queue limit in packets, 0 means kernel default (txqueuelen) */
	uint32_t limit;
};

struct tc_qdisc {
	ifindex_t ifindex;

	/*
	 * Full qdisc handle and parent.  When both are zero the qdisc is the
	 * zebra owned root qdisc (TC_QDISC_MAJOR_ZEBRA attached to TC_H_ROOT).
	 */
	uint32_t handle;
	uint32_t parent;

	enum tc_qdisc_kind kind;
	union {
		struct tc_qdisc_htb htb;
		struct tc_qdisc_fifo fifo;
	} u;
};

/* class definitions */

/* since classes share the same kinds of qdisc, duplicates omitted */
struct tc_class_htb {
	/* rates are in bytes per second */
	uint64_t rate;
	uint64_t ceil;
	/* priority 0 (highest) .. 7 */
	uint32_t prio;
	/* DRR quantum in bytes, 0 lets the kernel derive it from rate */
	uint32_t quantum;
	/* interface MTU used for burst calculation, 0 means 1500 */
	uint32_t mtu;
	/* ask the kernel to maintain a rate estimator for the class */
	bool rate_est;
};

struct tc_class {
	ifindex_t ifindex;
	/* minor number of this class (major is TC_QDISC_MAJOR_ZEBRA) */
	uint32_t handle;
	/* minor number of the parent class, 0 means the root qdisc */
	uint32_t parent;

	enum tc_qdisc_kind kind;
	union {
		struct tc_class_htb htb;
	} u;
};

/* filter definitions */

/* filter kinds */
enum tc_filter_kind {
	TC_FILTER_UNSPEC,
	TC_FILTER_BPF,
	TC_FILTER_FLOW,
	TC_FILTER_FLOWER,
	TC_FILTER_U32,
};

struct tc_bpf {
	/* TODO: fill in */
};

struct tc_flow {
	/* TODO: fill in */
};

struct tc_flower {
	uint32_t classid;

#define TC_FLOWER_IP_PROTOCOL (1 << 0)
#define TC_FLOWER_SRC_IP (1 << 1)
#define TC_FLOWER_DST_IP (1 << 2)
#define TC_FLOWER_SRC_PORT (1 << 3)
#define TC_FLOWER_DST_PORT (1 << 4)
#define TC_FLOWER_DSFIELD (1 << 5)
/* src_mask/dst_mask hold an arbitrary (e.g. wildcard derived) mask */
#define TC_FLOWER_SRC_IP_MASK (1 << 6)
#define TC_FLOWER_DST_IP_MASK (1 << 7)
/*
 * Instead of selecting a class, a match continues classification in
 * another filter chain (gact "goto chain <goto_chain>").  Used to
 * implement first-match access-list semantics (deny entries) and the
 * ordered evaluation of policy-map classes.
 */
#define TC_FLOWER_ACT_GOTO_CHAIN (1 << 8)
/*
 * Select the class and also attach a gact "pass" action: it does not change
 * the result but gives the filter packet/byte counters.
 */
#define TC_FLOWER_ACT_COUNT (1 << 9)

	uint32_t filter_bm;

	uint8_t ip_proto;

	struct prefix src_ip;
	struct prefix dst_ip;

	uint16_t src_port_min;
	uint16_t src_port_max;
	uint16_t dst_port_min;
	uint16_t dst_port_max;

	uint8_t dsfield;
	uint8_t dsfield_mask;

	uint32_t goto_chain;

	/* network byte order, 4 bytes used for IPv4, 16 for IPv6 */
	uint8_t src_mask[16];
	uint8_t dst_mask[16];
};

struct tc_u32 {
	/* TODO: fill in */
};

struct tc_filter {
	ifindex_t ifindex;
	uint32_t handle;
	/* minor number of the class the filter is attached to, 0 = root */
	uint32_t parent;
	/* filter chain index */
	uint32_t chain;

	uint32_t priority;
	uint16_t protocol;

	enum tc_filter_kind kind;

	union {
		struct tc_bpf bpf;
		struct tc_flow flow;
		struct tc_flower flower;
		struct tc_u32 u32;
	} u;
};

extern int tc_getrate(const char *str, uint64_t *rate);

extern int zapi_tc_qdisc_encode(uint8_t cmd, struct stream *s,
				struct tc_qdisc *qdisc);
extern int zapi_tc_class_encode(uint8_t cmd, struct stream *s,
				struct tc_class *class);
extern int zapi_tc_filter_encode(uint8_t cmd, struct stream *s,
				 struct tc_filter *filter);

#ifdef __cplusplus
}
#endif

#endif /* _TC_H */
