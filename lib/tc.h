// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Traffic Control (TC) main header
 * Copyright (C) 2022  Shichu Yang
 */

#ifndef _TC_H
#define _TC_H

#include <zebra.h>
#include "stream.h"

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
	TC_QDISC_INGRESS
};

struct tc_qdisc_htb {
	/* currently no members */
};

struct tc_qdisc_ingress {
	/* currently no members */
};

struct tc_qdisc {
	ifindex_t ifindex;

	enum tc_qdisc_kind kind;
	union {
		struct tc_qdisc_htb htb;
		struct tc_qdisc_ingress ingress;
	} u;
};

/* class definitions */

/* since classes share the same kinds of qdisc, duplicates omitted */
struct tc_class_htb {
	uint64_t rate;
	uint64_t ceil;
};

struct tc_class {
	ifindex_t ifindex;
	uint32_t handle;

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

enum tc_mirred_direction {
	TC_MIRRED_INGRESS,
	TC_MIRRED_EGRESS,
};

enum tc_mirred_mode {
	TC_MIRRED_MIRROR,
	TC_MIRRED_REDIRECT,
};

/* action iknds */
enum tc_action_kind {
	TC_ACTION_UNSPEC,
	TC_ACTION_MPLS_POP,
	TC_ACTION_MPLS_MAC_PUSH,
	TC_ACTION_VLAN_POP_ETH,
	TC_ACTION_VLAN_PUSH_ETH,
	TC_ACTION_MIRRED,
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
#define TC_FLOWER_MPLS (1 << 6)

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

	uint32_t mpls_label;
	uint8_t mpls_bos;
};

struct tc_u32 {
	/* TODO: fill in */
};

struct tc_act_mpls_pop {
	uint16_t protocol;
};

struct tc_act_mpls_mac_push {
	uint16_t protocol;
	uint8_t tc;
	uint8_t ttl;
	uint8_t bos;
	uint32_t label;
};

struct tc_act_vlan_pop_eth {
	/* No parameters, just pop eth header */	
};

struct tc_act_vlan_push_eth {
	struct ethaddr dst;
	struct ethaddr src;
};

struct tc_act_mirred {
	uint32_t ifindex;

	enum tc_mirred_direction direction;
	enum tc_mirred_mode mode;
};

struct tc_action {
	struct tc_action *next;
	struct tc_action *prev;

	uint32_t index;
	enum tc_action_kind kind;
	union {
		struct tc_act_mpls_pop mpls_pop;
		struct tc_act_mpls_mac_push mpls_mac_push;
		struct tc_act_vlan_pop_eth vlan_pop_eth;
		struct tc_act_vlan_push_eth vlan_push_eth;
		struct tc_act_mirred mirred;
	} u;
};

struct tc_filter {
	ifindex_t ifindex;
	uint32_t handle;

	uint32_t priority;
	uint16_t protocol;

	enum tc_filter_kind kind;

	union {
		struct tc_bpf bpf;
		struct tc_flow flow;
		struct tc_flower flower;
		struct tc_u32 u32;
	} u;

	struct tc_action *actions;
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
