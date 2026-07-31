// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Traffic Control (TC) interaction with the kernel using netlink.
 *
 * Copyright (C) 2022 Shichu Yang
 */

#include <zebra.h>

#ifdef HAVE_NETLINK

#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/tc_act/tc_mpls.h>
#include <linux/tc_act/tc_mirred.h>
#include <linux/tc_act/tc_vlan.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>

#include "if.h"
#include "prefix.h"
#include "vrf.h"

#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/rt.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/kernel_netlink.h"
#include "zebra/tc_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_tc.h"
#include "zebra/zebra_trace.h"
#include "lib/netlink_parser.h"

#define TC_FREQ_DEFAULT (100)

/* some magic number */
#define TC_MINOR_NOCLASS (0xffffu)

#define TIME_UNITS_PER_SEC (1000000)
#define xmittime(r, s) (TIME_UNITS_PER_SEC * ((double)(s) / (double)(r)))

static uint32_t tc_get_freq(void)
{
	int freq = 0;
	FILE *fp = fopen("/proc/net/psched", "r");

	if (fp) {
		uint32_t nom, denom;

		if (fscanf(fp, "%*08x%*08x%08x%08x", &nom, &denom) == 2) {
			if (nom == 1000000)
				freq = denom;
		}
		fclose(fp);
	}

	return freq == 0 ? TC_FREQ_DEFAULT : freq;
}

static void tc_calc_rate_table(struct tc_ratespec *ratespec, uint32_t *table,
			       uint32_t mtu)
{
	if (mtu == 0)
		mtu = 2047;

	int cell_log = -1;

	if (cell_log < 0) {
		cell_log = 0;
		while ((mtu >> cell_log) > 255)
			cell_log++;
	}

	for (int i = 0; i < 256; i++)
		table[i] = xmittime(ratespec->rate, (i + 1) << cell_log);

	ratespec->cell_align = -1;
	ratespec->cell_log = cell_log;
	ratespec->linklayer = TC_LINKLAYER_ETHERNET;
}

static int tc_flower_get_inet_prefix(const struct prefix *prefix,
				     struct inet_prefix *addr)
{
	addr->family = prefix->family;

	if (addr->family == AF_INET) {
		addr->bytelen = 4;
		addr->bitlen = prefix->prefixlen;
		addr->flags = 0;
		addr->flags |= PREFIXLEN_SPECIFIED;
		addr->flags |= ADDRTYPE_INET;
		memcpy(addr->data, prefix->u.val32, sizeof(prefix->u.val32));
	} else if (addr->family == AF_INET6) {
		addr->bytelen = 16;
		addr->bitlen = prefix->prefixlen;
		addr->flags = 0;
		addr->flags |= PREFIXLEN_SPECIFIED;
		addr->flags |= ADDRTYPE_INET;
		memcpy(addr->data, prefix->u.val, sizeof(prefix->u.val));
	} else {
		return -1;
	}

	return 0;
}

static int tc_flower_get_inet_mask(const struct prefix *prefix,
				   struct inet_prefix *addr)
{
	addr->family = prefix->family;

	if (addr->family == AF_INET) {
		addr->bytelen = 4;
		addr->bitlen = prefix->prefixlen;
		addr->flags = 0;
		addr->flags |= PREFIXLEN_SPECIFIED;
		addr->flags |= ADDRTYPE_INET;
	} else if (addr->family == AF_INET6) {
		addr->bytelen = 16;
		addr->bitlen = prefix->prefixlen;
		addr->flags = 0;
		addr->flags |= PREFIXLEN_SPECIFIED;
		addr->flags |= ADDRTYPE_INET;
	} else {
		return -1;
	}

	memset(addr->data, 0xff, addr->bytelen);

	int rest = prefix->prefixlen;

	for (int i = 0; i < addr->bytelen / 4; i++) {
		if (!rest) {
			addr->data[i] = 0;
		} else if (rest / 32 >= 1) {
			rest -= 32;
		} else {
			addr->data[i] <<= 32 - rest;
			addr->data[i] = htonl(addr->data[i]);
			rest = 0;
		}
	}

	return 0;
}

/*
 * Traffic control queue discipline encoding (only "htb" supported)
 */
static ssize_t netlink_qdisc_msg_encode(int cmd, struct zebra_dplane_ctx *ctx,
					void *data, size_t datalen)
{
	struct nlsock *nl;
	const char *kind_str = NULL;

	struct rtattr *nest;

	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[0];
	} *req = data;

	if (datalen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	req->n.nlmsg_flags |= NLM_F_REPLACE;

	req->n.nlmsg_type = cmd;

	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->t.tcm_family = AF_UNSPEC;
	req->t.tcm_ifindex = dplane_ctx_get_ifindex(ctx);
	req->t.tcm_info = 0;
	req->t.tcm_handle = 0;
	req->t.tcm_parent = TC_H_ROOT;

	if (cmd == RTM_NEWQDISC) {
		req->t.tcm_handle = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA, 0);

		kind_str = dplane_ctx_tc_qdisc_get_kind_str(ctx);

		if (!nl_attr_put(&req->n, datalen, TCA_KIND, kind_str, strlen(kind_str) + 1))
			return 0;

		nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);

		if (!nest)
			return 0;

		switch (dplane_ctx_tc_qdisc_get_kind(ctx)) {
		case TC_QDISC_HTB: {
			struct tc_htb_glob htb_glob = {
				.rate2quantum = 10,
				.version = 3,
				.defcls = TC_MINOR_NOCLASS};
			if (!nl_attr_put(&req->n, datalen, TCA_HTB_INIT, &htb_glob,
					 sizeof(htb_glob))) {
				return 0;
			}
			break;
		}
		case TC_QDISC_INGRESS:
			break;
		case TC_QDISC_NOQUEUE:
			break;
		default:
			break;
			/* not implemented */
		}

		nl_attr_nest_end(&req->n, nest);
	} else {
		/* ifindex are enough for del/get qdisc */
	}
	/* Always set handle and parent for ingress qdisc */
	if (dplane_ctx_tc_qdisc_get_kind(ctx) == TC_QDISC_INGRESS) {
		req->t.tcm_parent = TC_H_INGRESS;
		req->t.tcm_handle = TC_H_MAKE(TC_H_INGRESS, 0);
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

/*
 * Traffic control class encoding
 */
static ssize_t netlink_tclass_msg_encode(int cmd, struct zebra_dplane_ctx *ctx,
					 void *data, size_t datalen)
{
	enum dplane_op_e op = dplane_ctx_get_op(ctx);

	struct nlsock *nl;
	const char *kind_str = NULL;

	struct rtattr *nest;

	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[0];
	} *req = data;

	if (datalen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	if (op == DPLANE_OP_TC_CLASS_UPDATE)
		req->n.nlmsg_flags |= NLM_F_REPLACE;

	req->n.nlmsg_type = cmd;

	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->t.tcm_family = AF_UNSPEC;
	req->t.tcm_ifindex = dplane_ctx_get_ifindex(ctx);

	req->t.tcm_handle = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA,
				      dplane_ctx_tc_class_get_handle(ctx));
	req->t.tcm_parent = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA, 0);
	req->t.tcm_info = 0;

	kind_str = dplane_ctx_tc_class_get_kind_str(ctx);

	if (op == DPLANE_OP_TC_CLASS_ADD || op == DPLANE_OP_TC_CLASS_UPDATE) {
		zlog_debug("netlink tclass encoder: op: %s kind: %s handle: %u",
			   op == DPLANE_OP_TC_CLASS_UPDATE ? "update" : "add",
			   kind_str, dplane_ctx_tc_class_get_handle(ctx));

		if (!nl_attr_put(&req->n, datalen, TCA_KIND, kind_str, strlen(kind_str) + 1))
			return 0;

		nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);
		if (!nest)
			return 0;

		switch (dplane_ctx_tc_class_get_kind(ctx)) {
		case TC_QDISC_HTB: {
			struct tc_htb_opt htb_opt = {};

			uint64_t rate = dplane_ctx_tc_class_get_rate(ctx),
				 ceil = dplane_ctx_tc_class_get_ceil(ctx);

			uint64_t buffer, cbuffer;

			/* TODO: fetch mtu from interface */
			uint32_t mtu = 1500;

			uint32_t rtab[256];
			uint32_t ctab[256];

			ceil = MAX(rate, ceil);

			htb_opt.rate.rate = (rate >> 32 != 0) ? ~0U : rate;
			htb_opt.ceil.rate = (ceil >> 32 != 0) ? ~0U : ceil;

			buffer = rate / tc_get_freq() + mtu;
			cbuffer = ceil / tc_get_freq() + mtu;

			htb_opt.buffer = buffer;
			htb_opt.cbuffer = cbuffer;

			tc_calc_rate_table(&htb_opt.rate, rtab, mtu);
			tc_calc_rate_table(&htb_opt.ceil, ctab, mtu);

			htb_opt.ceil.mpu = htb_opt.rate.mpu = 0;
			htb_opt.ceil.overhead = htb_opt.rate.overhead = 0;

			if (rate >> 32 != 0) {
				if (!nl_attr_put(&req->n, datalen, TCA_HTB_RATE64, &rate,
						 sizeof(rate)))
					return 0;
			}

			if (ceil >> 32 != 0) {
				if (!nl_attr_put(&req->n, datalen, TCA_HTB_CEIL64, &ceil,
						 sizeof(ceil)))
					return 0;
			}

			if (!nl_attr_put(&req->n, datalen, TCA_HTB_PARMS, &htb_opt,
					 sizeof(htb_opt)))
				return 0;

			if (!nl_attr_put(&req->n, datalen, TCA_HTB_RTAB, rtab, sizeof(rtab)))
				return 0;
			if (!nl_attr_put(&req->n, datalen, TCA_HTB_CTAB, ctab, sizeof(ctab)))
				return 0;
			break;
		}
		default:
			break;
		}

		nl_attr_nest_end(&req->n, nest);
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

static int netlink_tfilter_flower_port_type(uint8_t ip_proto, bool src)
{
	if (ip_proto == IPPROTO_TCP)
		return src ? TCA_FLOWER_KEY_TCP_SRC : TCA_FLOWER_KEY_TCP_DST;
	else if (ip_proto == IPPROTO_UDP)
		return src ? TCA_FLOWER_KEY_UDP_SRC : TCA_FLOWER_KEY_UDP_DST;
	else if (ip_proto == IPPROTO_SCTP)
		return src ? TCA_FLOWER_KEY_SCTP_SRC : TCA_FLOWER_KEY_SCTP_DST;
	else
		return -1;
}

static int netlink_tfilter_flower_put_options(struct nlmsghdr *n, size_t datalen,
					      struct zebra_dplane_ctx *ctx, const uint32_t parent)
{
	struct inet_prefix addr;
	uint32_t flags = 0, classid;
	uint16_t protocol = htons(dplane_ctx_tc_filter_get_eth_proto(ctx));
	uint32_t filter_bm = dplane_ctx_tc_filter_get_filter_bm(ctx);

	if (filter_bm & TC_FLOWER_SRC_IP) {
		const struct prefix *src_p =
			dplane_ctx_tc_filter_get_src_ip(ctx);

		if (tc_flower_get_inet_prefix(src_p, &addr) != 0)
			return -1;

		if (!nl_attr_put(n, datalen,
				 (addr.family == AF_INET) ? TCA_FLOWER_KEY_IPV4_SRC
							  : TCA_FLOWER_KEY_IPV6_SRC,
				 addr.data, addr.bytelen))
			return 0;

		if (tc_flower_get_inet_mask(src_p, &addr) != 0)
			return -1;

		if (!nl_attr_put(n, datalen,
				 (addr.family == AF_INET) ? TCA_FLOWER_KEY_IPV4_SRC_MASK
							  : TCA_FLOWER_KEY_IPV6_SRC_MASK,
				 addr.data, addr.bytelen))
			return 0;
	}

	if (filter_bm & TC_FLOWER_DST_IP) {
		const struct prefix *dst_p =
			dplane_ctx_tc_filter_get_dst_ip(ctx);

		if (tc_flower_get_inet_prefix(dst_p, &addr) != 0)
			return -1;

		if (!nl_attr_put(n, datalen,
				 (addr.family == AF_INET) ? TCA_FLOWER_KEY_IPV4_DST
							  : TCA_FLOWER_KEY_IPV6_DST,
				 addr.data, addr.bytelen))
			return 0;

		if (tc_flower_get_inet_mask(dst_p, &addr) != 0)
			return -1;

		if (!nl_attr_put(n, datalen,
				 (addr.family == AF_INET) ? TCA_FLOWER_KEY_IPV4_DST_MASK
							  : TCA_FLOWER_KEY_IPV6_DST_MASK,
				 addr.data, addr.bytelen))
			return 0;
	}

	if (filter_bm & TC_FLOWER_IP_PROTOCOL) {
		if (!nl_attr_put8(n, datalen, TCA_FLOWER_KEY_IP_PROTO,
				  dplane_ctx_tc_filter_get_ip_proto(ctx)))
			return 0;
	}

	if (filter_bm & TC_FLOWER_SRC_PORT) {
		uint16_t min, max;

		min = dplane_ctx_tc_filter_get_src_port_min(ctx);
		max = dplane_ctx_tc_filter_get_src_port_max(ctx);

		if (max > min) {
			if (!nl_attr_put16(n, datalen, TCA_FLOWER_KEY_PORT_SRC_MIN, htons(min)))
				return 0;
			if (!nl_attr_put16(n, datalen, TCA_FLOWER_KEY_PORT_SRC_MAX, htons(max)))
				return 0;
		} else {
			int type = netlink_tfilter_flower_port_type(
				dplane_ctx_tc_filter_get_ip_proto(ctx), true);

			if (type < 0)
				return -1;

			if (!nl_attr_put16(n, datalen, type, htons(min)))
				return 0;
		}
	}

	if (filter_bm & TC_FLOWER_DST_PORT) {
		uint16_t min = dplane_ctx_tc_filter_get_dst_port_min(ctx),
			 max = dplane_ctx_tc_filter_get_dst_port_max(ctx);

		if (max > min) {
			if (!nl_attr_put16(n, datalen, TCA_FLOWER_KEY_PORT_DST_MIN, htons(min)))
				return 0;

			if (!nl_attr_put16(n, datalen, TCA_FLOWER_KEY_PORT_DST_MAX, htons(max)))
				return 0;
		} else {
			int type = netlink_tfilter_flower_port_type(
				dplane_ctx_tc_filter_get_ip_proto(ctx), false);

			if (type < 0)
				return -1;

			if (!nl_attr_put16(n, datalen, type, htons(min)))
				return 0;
		}
	}

	if (filter_bm & TC_FLOWER_DSFIELD) {
		if (!nl_attr_put8(n, datalen, TCA_FLOWER_KEY_IP_TOS,
				  dplane_ctx_tc_filter_get_dsfield(ctx)))
			return 0;
		if (!nl_attr_put8(n, datalen, TCA_FLOWER_KEY_IP_TOS_MASK,
				  dplane_ctx_tc_filter_get_dsfield_mask(ctx)))
			return 0;
	}

	if (filter_bm & TC_FLOWER_MPLS) {
		uint32_t label = dplane_ctx_tc_filter_get_mpls_label(ctx);
		if (!nl_attr_put32(n, datalen, TCA_FLOWER_KEY_MPLS_LABEL,
			           label))
			return 0;
		if (!nl_attr_put8(n, datalen, TCA_FLOWER_KEY_MPLS_BOS,1))
			return 0;
	}

	if (parent >= TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA,0) && 
	    parent <= TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA,0xFFFFU)) {
		classid = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA,
				    dplane_ctx_tc_filter_get_classid(ctx));
		if (!nl_attr_put32(n, datalen, TCA_FLOWER_CLASSID, classid))
			return 0;
	}


	if (!nl_attr_put32(n, datalen, TCA_FLOWER_FLAGS, flags))
		return 0;

	if (protocol && protocol != htons(ETH_P_ALL) && 
	    !nl_attr_put16(n, datalen, TCA_FLOWER_KEY_ETH_TYPE, protocol))
		return 0;

	return 1;
}

static void
netlink_taction_mpls_put_parm(struct nlmsghdr *n, size_t datalen,
			      const int mpls_act_type)
{
	struct tc_mpls mpls_parm = {
                .action = TC_ACT_PIPE,
                .m_action = mpls_act_type,
        };
	nl_attr_put(n, datalen, TCA_MPLS_PARMS, &mpls_parm, sizeof(mpls_parm));
}

static void
netlink_tcaction_vlan_put_parm(struct nlmsghdr *n, size_t datalen, int vlan_act_type)
{
	struct tc_vlan vlan_parm  = {
		.action = TC_ACT_PIPE,
		.v_action = vlan_act_type,
	};
	nl_attr_put(n, datalen, TCA_VLAN_PARMS, &vlan_parm, sizeof(vlan_parm));
}

static void
netlink_tcaction_mirred_redirect(struct nlmsghdr *n, size_t datalen,
				 const int ifindex, const int eaction)
{
	struct tc_mirred m_parm = {
		.action = TC_ACT_STOLEN,
		.eaction = eaction,
		.ifindex = ifindex,
	};
	nl_attr_put(n, datalen, TCA_MIRRED_PARMS, &m_parm, sizeof(m_parm));
}

/*
 * Traffic control filter encoding
 */
static ssize_t netlink_tfilter_msg_encode(int cmd, struct zebra_dplane_ctx *ctx,
					  void *data, size_t datalen)
{
	enum dplane_op_e op = dplane_ctx_get_op(ctx);

	struct nlsock *nl;
	const char *kind_str = NULL;

	struct rtattr *nest, *act_nest = NULL, *act_nest1, *act_nest2;

	uint16_t priority;
	uint16_t protocol;
	uint32_t parent;
	int act_tab = 0;
	int eaction;

	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[0];
	} *req = data;

	ssize_t ret = 0;

	const struct ethaddr *dst, *src;

	if (datalen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	if (op == DPLANE_OP_TC_FILTER_UPDATE)
		req->n.nlmsg_flags |= NLM_F_REPLACE;

	req->n.nlmsg_type = cmd;

	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->t.tcm_family = AF_UNSPEC;
	req->t.tcm_ifindex = dplane_ctx_get_ifindex(ctx);

	priority = dplane_ctx_tc_filter_get_priority(ctx);
	protocol = htons(dplane_ctx_tc_filter_get_eth_proto(ctx));

	req->t.tcm_info = TC_H_MAKE(priority << 16, protocol);
	req->t.tcm_handle = dplane_ctx_tc_filter_get_handle(ctx);

	parent = dplane_ctx_tc_filter_get_parent(ctx);
	if (!parent)
		parent = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA,0);
	req->t.tcm_parent = parent;

	kind_str = dplane_ctx_tc_filter_get_kind_str(ctx);
	
	if (!nl_attr_put(&req->n, datalen, TCA_KIND, kind_str, strlen(kind_str) + 1))
		return 0;

	if (op == DPLANE_OP_TC_FILTER_ADD || op == DPLANE_OP_TC_FILTER_UPDATE) {

		zlog_debug(
			"netlink tfilter encoder: op: %s priority: %u protocol: %u kind: %s handle: %u",
			op == DPLANE_OP_TC_FILTER_UPDATE ? "update" : "add",
			priority, protocol, kind_str,
			dplane_ctx_tc_filter_get_handle(ctx));

		nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);
		if (!nest)
			return 0;

		switch (dplane_ctx_tc_filter_get_kind(ctx)) {
		case TC_FILTER_FLOWER: {
			ret = netlink_tfilter_flower_put_options(&req->n, datalen, ctx, parent);
			if (ret <= 0)
				return 0;
			act_tab = TCA_FLOWER_ACT;
			break;
		}
		case TC_FILTER_MATCHALL: {
			/* Nothing to do, match all packets */
			act_tab = TCA_MATCHALL_ACT;
			break;
		}
		default:
			break;
		}
		uint32_t action_count = dplane_ctx_tc_filter_get_action_count(ctx);
		if (cmd == RTM_DELTFILTER)
			action_count = 0;
		if (action_count)
			act_nest = nl_attr_nest(&req->n, datalen, act_tab);
		for (uint32_t i = 0; i < action_count; i++) {
			act_nest1 = nl_attr_nest(&req->n, datalen, i+1);
			kind_str = dplane_ctx_tc_filter_get_action_kind_str(ctx, i);
			nl_attr_put(&req->n, datalen, TCA_ACT_KIND, kind_str,
				    strlen(kind_str) + 1);
			act_nest2 = nl_attr_nest(&req->n, datalen, TCA_ACT_OPTIONS | NLA_F_NESTED);
			switch(dplane_ctx_tc_filter_get_action_kind(ctx,i)) {
			case TC_ACTION_MPLS:
				switch(dplane_ctx_tc_filter_get_action_mpls_mode(ctx,i)) {
				case TC_MPLS_POP:
					netlink_taction_mpls_put_parm(&req->n,datalen,TCA_MPLS_ACT_POP);
					nl_attr_put16(&req->n, datalen, TCA_MPLS_PROTO, htons(ETH_P_MPLS_UC));
					break;
				case TC_MPLS_PUSH:
					netlink_taction_mpls_put_parm(&req->n,datalen,TCA_MPLS_ACT_PUSH);
					nl_attr_put32(&req->n, datalen, TCA_MPLS_LABEL,
						      dplane_ctx_tc_filter_get_action_mpls_label(ctx,i));
					nl_attr_put16(&req->n, datalen, TCA_MPLS_PROTO, htons(ETH_P_MPLS_UC));
					nl_attr_put8(&req->n, datalen, TCA_MPLS_TTL,
						     dplane_ctx_tc_filter_get_action_mpls_ttl(ctx,i));
					break;
				case TC_MPLS_PUSH_MAC:
					netlink_taction_mpls_put_parm(&req->n,datalen,TCA_MPLS_ACT_MAC_PUSH);
					nl_attr_put32(&req->n, datalen, TCA_MPLS_LABEL,
						      dplane_ctx_tc_filter_get_action_mpls_label(ctx,i));
						      //htonl(dplane_ctx_tc_filter_get_action_mpls_label(ctx,i)));
					/*nl_attr_put16(&req->n, datalen, TCA_MPLS_PROTO, htons(ETH_P_MPLS_UC));
					nl_attr_put8(&req->n, datalen, TCA_MPLS_TC,
						     dplane_ctx_tc_filter_get_action_mpls_tc(ctx,i));
					nl_attr_put8(&req->n, datalen, TCA_MPLS_TTL,
						     dplane_ctx_tc_filter_get_action_mpls_ttl(ctx,i));*/
					nl_attr_put8(&req->n, datalen, TCA_MPLS_BOS, dplane_ctx_tc_filter_get_action_mpls_bos(ctx,i));
					break;
				case TC_MPLS_DEC_TTL:
					netlink_taction_mpls_put_parm(&req->n,datalen,TCA_MPLS_ACT_DEC_TTL);
					break;
				}
				break;
			case TC_ACTION_VLAN:
				switch(dplane_ctx_tc_filter_get_action_vlan_mode(ctx,i)) {
				case TC_VLAN_POP:
					netlink_tcaction_vlan_put_parm(&req->n, datalen, TCA_VLAN_ACT_POP);
					break;
				case TC_VLAN_POP_ETH:
					netlink_tcaction_vlan_put_parm(&req->n, datalen, TCA_VLAN_ACT_POP_ETH);
					break;
				case TC_VLAN_PUSH:
					netlink_tcaction_vlan_put_parm(&req->n, datalen, TCA_VLAN_ACT_PUSH);
					break;
				case TC_VLAN_PUSH_ETH:
					dst = dplane_ctx_tc_filter_get_action_vlan_dst(ctx, i);
					src = dplane_ctx_tc_filter_get_action_vlan_src(ctx, i);
					netlink_tcaction_vlan_put_parm(&req->n, datalen, TCA_VLAN_ACT_PUSH_ETH);
					nl_attr_put(&req->n, datalen, TCA_VLAN_PUSH_ETH_DST, dst->octet, ETH_ALEN);
					nl_attr_put(&req->n, datalen, TCA_VLAN_PUSH_ETH_SRC, src->octet, ETH_ALEN);
					break;
				case TC_VLAN_REPLACE:
					//netlink_tcaction_vlan_put_parm(&req->n, datalen, TCA_VLAN_ACT_REPLACE);
					break;
				}
				break;
			case TC_ACTION_MIRRED:
				eaction = TCA_EGRESS_REDIR;
				if (dplane_ctx_tc_filter_get_action_mirred_direction(ctx,i) == TC_MIRRED_INGRESS)
				      eaction = TCA_INGRESS_REDIR;
				netlink_tcaction_mirred_redirect(&req->n, datalen, dplane_ctx_tc_filter_get_action_mirred_ifindex(ctx,i),eaction);
				break;
			case TC_ACTION_UNSPEC:
				break;
			}
			nl_attr_nest_end(&req->n, act_nest2);
			nl_attr_nest_end(&req->n, act_nest1);

		}
		if (act_nest)
			nl_attr_nest_end(&req->n, act_nest);
		nl_attr_nest_end(&req->n, nest);
	}
	if (cmd == RTM_DELTFILTER) {
		req->n.nlmsg_flags = NLM_F_REQUEST;
		zlog_debug(
                        "netlink tfilter encoder: op: delete priority: %u protocol: %u kind: %s handle: %u",
                        priority, protocol, kind_str,
                        dplane_ctx_tc_filter_get_handle(ctx));
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

static ssize_t netlink_newqdisc_msg_encoder(struct zebra_dplane_ctx *ctx,
					    void *buf, size_t buflen)
{
	return netlink_qdisc_msg_encode(RTM_NEWQDISC, ctx, buf, buflen);
}

static ssize_t netlink_delqdisc_msg_encoder(struct zebra_dplane_ctx *ctx,
					    void *buf, size_t buflen)
{
	return netlink_qdisc_msg_encode(RTM_DELQDISC, ctx, buf, buflen);
}

static ssize_t netlink_newtclass_msg_encoder(struct zebra_dplane_ctx *ctx,
					     void *buf, size_t buflen)
{
	return netlink_tclass_msg_encode(RTM_NEWTCLASS, ctx, buf, buflen);
}

static ssize_t netlink_deltclass_msg_encoder(struct zebra_dplane_ctx *ctx,
					     void *buf, size_t buflen)
{
	return netlink_tclass_msg_encode(RTM_DELTCLASS, ctx, buf, buflen);
}

static ssize_t netlink_newtfilter_msg_encoder(struct zebra_dplane_ctx *ctx,
					      void *buf, size_t buflen)
{
	return netlink_tfilter_msg_encode(RTM_NEWTFILTER, ctx, buf, buflen);
}

static ssize_t netlink_deltfilter_msg_encoder(struct zebra_dplane_ctx *ctx,
					      void *buf, size_t buflen)
{
	return netlink_tfilter_msg_encode(RTM_DELTFILTER, ctx, buf, buflen);
}

enum netlink_msg_status
netlink_put_tc_qdisc_update_msg(struct nl_batch *bth,
				struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	enum netlink_msg_status ret;

	op = dplane_ctx_get_op(ctx);

	if (op == DPLANE_OP_TC_QDISC_INSTALL) {
		ret = netlink_batch_add_msg(
			bth, ctx, netlink_newqdisc_msg_encoder, false);
	} else if (op == DPLANE_OP_TC_QDISC_UNINSTALL) {
		ret = netlink_batch_add_msg(
			bth, ctx, netlink_delqdisc_msg_encoder, false);
	} else {
		return FRR_NETLINK_ERROR;
	}

	return ret;
}

enum netlink_msg_status
netlink_put_tc_class_update_msg(struct nl_batch *bth,
				struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	enum netlink_msg_status ret;

	op = dplane_ctx_get_op(ctx);

	if (op == DPLANE_OP_TC_CLASS_ADD || op == DPLANE_OP_TC_CLASS_UPDATE) {
		ret = netlink_batch_add_msg(
			bth, ctx, netlink_newtclass_msg_encoder, false);
	} else if (op == DPLANE_OP_TC_CLASS_DELETE) {
		ret = netlink_batch_add_msg(
			bth, ctx, netlink_deltclass_msg_encoder, false);
	} else {
		return FRR_NETLINK_ERROR;
	}

	return ret;
}

enum netlink_msg_status
netlink_put_tc_filter_update_msg(struct nl_batch *bth,
				 struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	enum netlink_msg_status ret;

	op = dplane_ctx_get_op(ctx);

	if (op == DPLANE_OP_TC_FILTER_ADD) {
		ret = netlink_batch_add_msg(
			bth, ctx, netlink_newtfilter_msg_encoder, false);
	} else if (op == DPLANE_OP_TC_FILTER_UPDATE) {
		/*
		 * Replace will fail if either filter type or the number of
		 * filter options is changed, so DEL then NEW
		 *
		 * TFILTER may have refs to TCLASS.
		 */

		(void)netlink_batch_add_msg(
			bth, ctx, netlink_deltfilter_msg_encoder, false);
		ret = netlink_batch_add_msg(
			bth, ctx, netlink_newtfilter_msg_encoder, false);
	} else if (op == DPLANE_OP_TC_FILTER_DELETE) {
		ret = netlink_batch_add_msg(
			bth, ctx, netlink_deltfilter_msg_encoder, false);
	} else {
		return FRR_NETLINK_ERROR;
	}

	return ret;
}

/*
 * Request queue discipline from the kernel
 */
static int netlink_request_qdiscs(struct nlsock *nl, int family, int type)
{
	struct {
		struct nlmsghdr n;
		struct tcmsg tc;
	} req;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = type;
	req.n.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.tc.tcm_family = family;

	return netlink_request(nl, &req);
}

int netlink_qdisc_change(struct nlmsghdr *h, ns_id_t ns_id, int startup, void *arg)
{
	struct tcmsg *tcm;
	enum tc_qdisc_kind kind = TC_QDISC_UNSPEC;

	int len;
	struct rtattr *tb[TCA_MAX + 1];

	frrtrace(3, frr_zebra, netlink_tc_qdisc_change, h, ns_id, startup);

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct tcmsg));

	if (len < 0) {
		flog_err(EC_ZEBRA_NETLINK_LENGTH_ERROR,
			 "%s: Message received from netlink is of a broken size %d %zu", __func__,
			 h->nlmsg_len, (size_t)NLMSG_LENGTH(sizeof(struct tcmsg)));
		return -1;
	}

	tcm = NLMSG_DATA(h);
	netlink_parse_rtattr(tb, TCA_MAX, TCA_RTA(tcm), len);

	if (RTA_DATA(tb[TCA_KIND]))
		kind = tc_qdisc_str2kind((const char *)RTA_DATA(tb[TCA_KIND]));

	enum dplane_tc_qdisc_notify_e notify_type = (h->nlmsg_type == RTM_NEWQDISC)
							    ? DPLANE_TC_QDISC_NOTIFY_NEW
							    : DPLANE_TC_QDISC_NOTIFY_DEL;

	/*
	 * Hand the decoded fields off to the zebra master pthread.
	 * The dplane thread is purely a decoder here -- the policy
	 * (e.g. cleaning up a leftover zebra-owned qdisc at startup)
	 * is decided by zebra_tc_qdisc_handle_notify() in the master
	 * thread.
	 */
	dplane_tc_qdisc_notify_enqueue(ns_id, notify_type, !!startup, kind, tcm->tcm_ifindex,
				       TC_H_MAJ(tcm->tcm_handle));

	return 0;
}

int netlink_tclass_change(struct nlmsghdr *h, ns_id_t ns_id, int startup, void *arg)
{
	struct tcmsg *tcm;

	int len;
	struct rtattr *tb[TCA_MAX + 1];

	frrtrace(3, frr_zebra, netlink_tc_class_change, h, ns_id, startup);

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct tcmsg));

	if (len < 0) {
		flog_err(EC_ZEBRA_NETLINK_LENGTH_ERROR,
			 "%s: Message received from netlink is of a broken size %d %zu", __func__,
			 h->nlmsg_len, (size_t)NLMSG_LENGTH(sizeof(struct tcmsg)));
		return -1;
	}

	tcm = NLMSG_DATA(h);
	netlink_parse_rtattr(tb, TCA_MAX, TCA_RTA(tcm), len);


	if (tb[TCA_OPTIONS] != NULL) {
		struct rtattr *options[TCA_HTB_MAX + 1];

		netlink_parse_rtattr_nested(options, TCA_HTB_MAX,
					    tb[TCA_OPTIONS]);

		/* TODO: more details */
		/* struct tc_htb_opt *opt = RTA_DATA(options[TCA_HTB_PARMS]); */
	}

	return 0;
}

int netlink_tfilter_change(struct nlmsghdr *h, ns_id_t ns_id, int startup, void *arg)
{
	struct tcmsg *tcm;

	int len;
	struct rtattr *tb[TCA_MAX + 1];


	frrtrace(3, frr_zebra, netlink_tc_filter_change, h, ns_id, startup);

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct tcmsg));

	if (len < 0) {
		flog_err(EC_ZEBRA_NETLINK_LENGTH_ERROR,
			 "%s: Message received from netlink is of a broken size %d %zu", __func__,
			 h->nlmsg_len, (size_t)NLMSG_LENGTH(sizeof(struct tcmsg)));
		return -1;
	}

	tcm = NLMSG_DATA(h);
	netlink_parse_rtattr(tb, TCA_MAX, TCA_RTA(tcm), len);


	return 0;
}

void kernel_read_tc_qdisc(struct zebra_dplane_ctx *ctx)
{
	const struct zebra_dplane_info *dp_info = dplane_ctx_get_ns(ctx);
	struct nlsock *nl;
	int ret;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));
	if (!nl) {
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
		zebra_dplane_startup_stage(dplane_ctx_get_ns_id(ctx),
					   ZEBRA_DPLANE_FINISHED_READING);
		return;
	}

	ret = netlink_request_qdiscs(nl, AF_UNSPEC, RTM_GETQDISC);
	if (ret >= 0)
		netlink_parse_info(netlink_qdisc_change, nl, dp_info, 0, true, NULL, NULL);

	dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);

	/*
	 * Signal that startup reads are finished. Any platform-specific
	 * implementation of this function must do the same once it has
	 * finished reading all TC data, so that zebra can advance from
	 * ZEBRA_DPLANE_ADDRESSES_READ to ZEBRA_DPLANE_FINISHED_READING.
	 */
	zebra_dplane_startup_stage(dplane_ctx_get_ns_id(ctx),
				   ZEBRA_DPLANE_FINISHED_READING);
}

#endif /* HAVE_NETLINK */
