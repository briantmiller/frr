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
#include <linux/tc_act/tc_gact.h>
#include <linux/gen_stats.h>
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

/* largest DRR quantum HTB accepts without complaining */
#define TC_HTB_QUANTUM_MAX (200000)
/* default rate2quantum of the zebra HTB qdisc */
#define TC_HTB_R2Q (10)

/*
 * Rate estimator parameters, as iproute2 computes them for "est 1sec 4sec":
 * interval is log2(interval / 250ms) - 2, ewma_log gives a time constant
 * of about 4 seconds.
 */
#define TC_EST_INTERVAL_1SEC (0)
#define TC_EST_EWMA_LOG_4SEC (2)

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

/*
 * Number of psched ticks per microsecond, computed the same way iproute2
 * does (tc_core_init()).  HTB expects buffer sizes expressed in ticks.
 */
static double tc_get_tick_in_usec(void)
{
	static double tick_in_usec;
	uint32_t t2us, us2t, clock_res;
	double clock_factor;
	FILE *fp;

	if (tick_in_usec > 0)
		return tick_in_usec;

	tick_in_usec = 1;

	fp = fopen("/proc/net/psched", "r");
	if (!fp)
		return tick_in_usec;

	if (fscanf(fp, "%08x%08x%08x", &t2us, &us2t, &clock_res) == 3 && us2t) {
		if (clock_res == 1000000000)
			t2us = us2t;
		clock_factor = (double)clock_res / TIME_UNITS_PER_SEC;
		tick_in_usec = (double)t2us / us2t * clock_factor;
	}
	fclose(fp);

	return tick_in_usec;
}

/* time (in psched ticks) needed to send @size bytes at @rate bytes/sec */
static uint32_t tc_calc_xmittime(uint64_t rate, uint64_t size)
{
	double ticks;

	if (rate == 0)
		return 0;

	ticks = TIME_UNITS_PER_SEC * ((double)size / (double)rate) * tc_get_tick_in_usec();

	return ticks > UINT32_MAX ? UINT32_MAX : (uint32_t)ticks;
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
		table[i] = tc_calc_xmittime(ratespec->rate, (i + 1) << cell_log);

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

	/*
	 * A zero handle/parent pair is the zebra owned root qdisc, anything
	 * else is an explicitly addressed (e.g. leaf class) qdisc.
	 */
	if (dplane_ctx_tc_qdisc_get_handle(ctx) || dplane_ctx_tc_qdisc_get_parent(ctx)) {
		req->t.tcm_handle = dplane_ctx_tc_qdisc_get_handle(ctx);
		req->t.tcm_parent = dplane_ctx_tc_qdisc_get_parent(ctx);
	} else {
		req->t.tcm_handle = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA, 0);
		req->t.tcm_parent = TC_H_ROOT;
	}

	if (cmd == RTM_NEWQDISC) {
		kind_str = dplane_ctx_tc_qdisc_get_kind_str(ctx);

		if (!nl_attr_put(&req->n, datalen, TCA_KIND, kind_str, strlen(kind_str) + 1))
			return 0;

		switch (dplane_ctx_tc_qdisc_get_kind(ctx)) {
		case TC_QDISC_HTB: {
			uint32_t defcls = dplane_ctx_tc_qdisc_get_defcls(ctx);
			struct tc_htb_glob htb_glob = {
				.rate2quantum = TC_HTB_R2Q,
				.version = 3,
				.defcls = defcls ? defcls : TC_MINOR_NOCLASS};

			nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);
			if (!nest)
				return 0;

			if (!nl_attr_put(&req->n, datalen, TCA_HTB_INIT, &htb_glob,
					 sizeof(htb_glob))) {
				return 0;
			}

			nl_attr_nest_end(&req->n, nest);
			break;
		}
		case TC_QDISC_HFSC: {
			/* hfsc options are a plain struct, not nested */
			struct tc_hfsc_qopt qopt = {
				.defcls = dplane_ctx_tc_qdisc_get_defcls(ctx),
			};

			if (!nl_attr_put(&req->n, datalen, TCA_OPTIONS, &qopt, sizeof(qopt)))
				return 0;
			break;
		}
		case TC_QDISC_PFIFO: {
			/* fifo options are a plain struct, not nested */
			struct tc_fifo_qopt fifo = {
				.limit = dplane_ctx_tc_qdisc_get_limit(ctx),
			};

			if (fifo.limit &&
			    !nl_attr_put(&req->n, datalen, TCA_OPTIONS, &fifo, sizeof(fifo)))
				return 0;
			break;
		}
		case TC_QDISC_CLSACT:
			/* no options: replacing an existing clsact is then a no-op */
			break;
		case TC_QDISC_NOQUEUE:
		case TC_QDISC_UNSPEC:
			nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);
			if (!nest)
				return 0;
			nl_attr_nest_end(&req->n, nest);
			break;
		}
	} else {
		/* ifindex, handle and parent are enough for del/get qdisc */
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
	req->t.tcm_parent = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA,
				      dplane_ctx_tc_class_get_parent(ctx));
	req->t.tcm_info = 0;

	kind_str = dplane_ctx_tc_class_get_kind_str(ctx);

	if (op == DPLANE_OP_TC_CLASS_ADD || op == DPLANE_OP_TC_CLASS_UPDATE) {
		if (IS_ZEBRA_DEBUG_TC)
			zlog_debug("netlink tclass encoder: op: %s kind: %s handle: %x parent: %x",
				   op == DPLANE_OP_TC_CLASS_UPDATE ? "update" : "add", kind_str,
				   dplane_ctx_tc_class_get_handle(ctx),
				   dplane_ctx_tc_class_get_parent(ctx));

		if (!nl_attr_put(&req->n, datalen, TCA_KIND, kind_str, strlen(kind_str) + 1))
			return 0;

		if (dplane_ctx_tc_class_get_rate_est(ctx)) {
			/*
			 * Rate estimator ("est 1sec 4sec"): HTB classes only
			 * report a current rate when one is attached.
			 */
			struct tc_estimator est = {
				.interval = TC_EST_INTERVAL_1SEC,
				.ewma_log = TC_EST_EWMA_LOG_4SEC,
			};

			if (!nl_attr_put(&req->n, datalen, TCA_RATE, &est, sizeof(est)))
				return 0;
		}

		nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);
		if (!nest)
			return 0;

		switch (dplane_ctx_tc_class_get_kind(ctx)) {
		case TC_QDISC_HTB: {
			struct tc_htb_opt htb_opt = {};

			uint64_t rate = dplane_ctx_tc_class_get_rate(ctx),
				 ceil = dplane_ctx_tc_class_get_ceil(ctx);

			uint64_t buffer, cbuffer;
			uint32_t mtu = dplane_ctx_tc_class_get_mtu(ctx);
			uint32_t quantum = dplane_ctx_tc_class_get_quantum(ctx);

			uint32_t rtab[256];
			uint32_t ctab[256];

			if (mtu == 0)
				mtu = 1500;

			ceil = MAX(rate, ceil);

			htb_opt.rate.rate = (rate >> 32 != 0) ? ~0U : rate;
			htb_opt.ceil.rate = (ceil >> 32 != 0) ? ~0U : ceil;

			/*
			 * Burst sizes (bytes) as computed by iproute2, which
			 * HTB wants converted into transmission time (ticks).
			 */
			buffer = rate / tc_get_freq() + mtu;
			cbuffer = ceil / tc_get_freq() + mtu;

			htb_opt.buffer = tc_calc_xmittime(rate, buffer);
			htb_opt.cbuffer = tc_calc_xmittime(ceil, cbuffer);

			htb_opt.prio = dplane_ctx_tc_class_get_prio(ctx);

			/*
			 * Keep the DRR quantum in the range HTB is happy
			 * with, otherwise the kernel complains loudly about
			 * every class with a "big" rate.
			 */
			if (!quantum) {
				uint64_t q = rate / TC_HTB_R2Q;

				q = MAX(q, mtu);
				q = MIN(q, TC_HTB_QUANTUM_MAX);
				quantum = q;
			}
			htb_opt.quantum = quantum;

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
		case TC_QDISC_HFSC: {
			/*
			 * Service curves, kernel units: bytes/sec and usec.
			 * Unset curves (m2 == 0) are left out.
			 */
			const struct tc_hfsc_curve *curves[] = {
				dplane_ctx_tc_class_get_hfsc_rsc(ctx),
				dplane_ctx_tc_class_get_hfsc_fsc(ctx),
				dplane_ctx_tc_class_get_hfsc_usc(ctx),
			};
			const int types[] = { TCA_HFSC_RSC, TCA_HFSC_FSC, TCA_HFSC_USC };

			for (size_t k = 0; k < array_size(curves); k++) {
				struct tc_service_curve sc;

				if (!curves[k]->m2)
					continue;

				sc.m1 = MIN(curves[k]->m1, UINT32_MAX);
				sc.d = curves[k]->d;
				sc.m2 = MIN(curves[k]->m2, UINT32_MAX);
				if (!nl_attr_put(&req->n, datalen, types[k], &sc, sizeof(sc)))
					return 0;
			}
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

/* Attach a single gact action (TCA_FLOWER_ACT) with the given verdict */
static bool netlink_tfilter_put_gact(struct nlmsghdr *n, size_t datalen, int action)
{
	struct rtattr *act_nest, *prio_nest, *opt_nest;
	struct tc_gact gact = { .action = action };

	act_nest = nl_attr_nest(n, datalen, TCA_FLOWER_ACT);
	if (!act_nest)
		return false;
	prio_nest = nl_attr_nest(n, datalen, 1);
	if (!prio_nest)
		return false;
	if (!nl_attr_put(n, datalen, TCA_ACT_KIND, "gact", strlen("gact") + 1))
		return false;
	opt_nest = nl_attr_nest(n, datalen, TCA_ACT_OPTIONS);
	if (!opt_nest)
		return false;
	if (!nl_attr_put(n, datalen, TCA_GACT_PARMS, &gact, sizeof(gact)))
		return false;
	nl_attr_nest_end(n, opt_nest);
	nl_attr_nest_end(n, prio_nest);
	nl_attr_nest_end(n, act_nest);

	return true;
}

static int netlink_tfilter_flower_put_options(struct nlmsghdr *n, size_t datalen,
					      struct zebra_dplane_ctx *ctx)
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

		if (filter_bm & TC_FLOWER_SRC_IP_MASK)
			memcpy(addr.data, dplane_ctx_tc_filter_get_src_mask(ctx), addr.bytelen);

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

		if (filter_bm & TC_FLOWER_DST_IP_MASK)
			memcpy(addr.data, dplane_ctx_tc_filter_get_dst_mask(ctx), addr.bytelen);

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

	if (filter_bm & TC_FLOWER_RAW_KEYS) {
		uint16_t raw_len;
		const uint8_t *raw = dplane_ctx_tc_filter_get_raw(ctx, &raw_len);

		/* pre-built, 4 byte aligned TCA_FLOWER_KEY_* attributes */
		if (NLMSG_ALIGN(n->nlmsg_len) + raw_len > datalen)
			return 0;
		memcpy((uint8_t *)n + NLMSG_ALIGN(n->nlmsg_len), raw, raw_len);
		n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + raw_len;
	}

	if (filter_bm & TC_FLOWER_ACT_GOTO_CHAIN) {
		/*
		 * gact "goto chain N": carry on classifying in another chain
		 * instead of selecting a class.
		 */
		if (!netlink_tfilter_put_gact(n, datalen,
					      TC_ACT_GOTO_CHAIN |
						      (dplane_ctx_tc_filter_get_goto_chain(ctx) &
						       TC_ACT_EXT_VAL_MASK)))
			return 0;
	} else if (filter_bm & TC_FLOWER_ACT_DROP) {
		if (!netlink_tfilter_put_gact(n, datalen, TC_ACT_SHOT))
			return 0;
	} else if (filter_bm & TC_FLOWER_ACT_PASS) {
		if (!netlink_tfilter_put_gact(n, datalen, TC_ACT_OK))
			return 0;
	} else {
		classid = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA,
				    dplane_ctx_tc_filter_get_classid(ctx));
		if (!nl_attr_put32(n, datalen, TCA_FLOWER_CLASSID, classid))
			return 0;

		/* gact "pass" keeps the class and counts the matches */
		if ((filter_bm & TC_FLOWER_ACT_COUNT) &&
		    !netlink_tfilter_put_gact(n, datalen, TC_ACT_OK))
			return 0;
	}

	if (!nl_attr_put32(n, datalen, TCA_FLOWER_FLAGS, flags))
		return 0;

	/* "protocol all" filters do not match on the ethertype */
	if (protocol != htons(ETH_P_ALL) &&
	    !nl_attr_put16(n, datalen, TCA_FLOWER_KEY_ETH_TYPE, protocol))
		return 0;

	return 1;
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

	struct rtattr *nest;

	uint16_t priority;
	uint16_t protocol;

	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[0];
	} *req = data;

	ssize_t ret = 0;

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
	/* a minor of the zebra qdisc, or a full handle (clsact hooks) */
	if (TC_H_MAJ(dplane_ctx_tc_filter_get_parent(ctx)))
		req->t.tcm_parent = dplane_ctx_tc_filter_get_parent(ctx);
	else
		req->t.tcm_parent = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA,
					      dplane_ctx_tc_filter_get_parent(ctx));

	if (dplane_ctx_tc_filter_get_chain(ctx) &&
	    !nl_attr_put32(&req->n, datalen, TCA_CHAIN, dplane_ctx_tc_filter_get_chain(ctx)))
		return 0;

	kind_str = dplane_ctx_tc_filter_get_kind_str(ctx);

	if (op == DPLANE_OP_TC_FILTER_ADD || op == DPLANE_OP_TC_FILTER_UPDATE) {
		if (!nl_attr_put(&req->n, datalen, TCA_KIND, kind_str, strlen(kind_str) + 1))
			return 0;

		if (IS_ZEBRA_DEBUG_TC)
			zlog_debug(
			"netlink tfilter encoder: op: %s priority: %u protocol: %u kind: %s handle: %u filter_bm: %u ip_proto: %u",
			op == DPLANE_OP_TC_FILTER_UPDATE ? "update" : "add",
			priority, protocol, kind_str,
			dplane_ctx_tc_filter_get_handle(ctx),
			dplane_ctx_tc_filter_get_filter_bm(ctx),
			dplane_ctx_tc_filter_get_ip_proto(ctx));

		nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);
		if (!nest)
			return 0;

		switch (dplane_ctx_tc_filter_get_kind(ctx)) {
		case TC_FILTER_FLOWER: {
			ret = netlink_tfilter_flower_put_options(&req->n, datalen, ctx);
			if (ret <= 0)
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

/*
 * Synchronously dump the TC classes of one interface and hand their
 * statistics to @cb.  Used by show commands, which need an answer right
 * away, so this does not go through the dataplane thread; it uses a
 * private, short lived socket in zebra's own (default) namespace.
 */
static void tc_class_stats_parse(struct nlmsghdr *h, ifindex_t ifindex,
				 void (*cb)(const struct zebra_tc_class_stats *stats, void *arg),
				 void *arg)
{
	struct rtattr *tb[TCA_MAX + 1];
	struct rtattr *st[TCA_STATS_MAX + 1];
	struct zebra_tc_class_stats stats = {};
	struct tcmsg *tcm = NLMSG_DATA(h);
	int len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*tcm));

	if (h->nlmsg_type != RTM_NEWTCLASS || len < 0 || tcm->tcm_ifindex != ifindex)
		return;

	netlink_parse_rtattr(tb, TCA_MAX, TCA_RTA(tcm), len);
	if (!tb[TCA_STATS2])
		return;

	netlink_parse_rtattr_nested(st, TCA_STATS_MAX, tb[TCA_STATS2]);

	stats.handle = tcm->tcm_handle;
	stats.parent = tcm->tcm_parent;

	if (st[TCA_STATS_BASIC] &&
	    RTA_PAYLOAD(st[TCA_STATS_BASIC]) >= sizeof(struct gnet_stats_basic)) {
		struct gnet_stats_basic basic;

		memcpy(&basic, RTA_DATA(st[TCA_STATS_BASIC]), sizeof(basic));
		stats.bytes = basic.bytes;
		stats.packets = basic.packets;
	}
	if (st[TCA_STATS_PKT64] && RTA_PAYLOAD(st[TCA_STATS_PKT64]) >= sizeof(uint64_t))
		memcpy(&stats.packets, RTA_DATA(st[TCA_STATS_PKT64]), sizeof(uint64_t));

	if (st[TCA_STATS_RATE_EST64] &&
	    RTA_PAYLOAD(st[TCA_STATS_RATE_EST64]) >= sizeof(struct gnet_stats_rate_est64)) {
		struct gnet_stats_rate_est64 est;

		memcpy(&est, RTA_DATA(st[TCA_STATS_RATE_EST64]), sizeof(est));
		stats.rate_valid = true;
		stats.bps = est.bps * 8;
		stats.pps = est.pps;
	} else if (st[TCA_STATS_RATE_EST] &&
		   RTA_PAYLOAD(st[TCA_STATS_RATE_EST]) >= sizeof(struct gnet_stats_rate_est)) {
		struct gnet_stats_rate_est est;

		memcpy(&est, RTA_DATA(st[TCA_STATS_RATE_EST]), sizeof(est));
		stats.rate_valid = true;
		stats.bps = (uint64_t)est.bps * 8;
		stats.pps = est.pps;
	}

	if (st[TCA_STATS_QUEUE] &&
	    RTA_PAYLOAD(st[TCA_STATS_QUEUE]) >= sizeof(struct gnet_stats_queue)) {
		struct gnet_stats_queue q;

		memcpy(&q, RTA_DATA(st[TCA_STATS_QUEUE]), sizeof(q));
		stats.qlen = q.qlen;
		stats.backlog = q.backlog;
		stats.drops = q.drops;
		stats.overlimits = q.overlimits;
	}

	cb(&stats, arg);
}

/*
 * Dump RTM_GETTCLASS/RTM_GETTFILTER objects of @ifindex (and @parent, a full
 * handle, for filters) on a private socket and hand each message to @msg_cb.
 */
static int tc_dump(uint16_t type, ifindex_t ifindex, uint32_t parent,
		   void (*msg_cb)(struct nlmsghdr *h, void *arg), void *arg)
{
	struct {
		struct nlmsghdr n;
		struct tcmsg t;
	} req = {};
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
	struct timeval tv = { .tv_sec = 2 };
	uint32_t seq = (uint32_t)time(NULL);
	char *buf;
	bool done = false;
	int sock, ret = -1;

	sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (sock < 0)
		return -1;

	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.n.nlmsg_type = type;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.n.nlmsg_seq = seq;
	req.t.tcm_family = AF_UNSPEC;
	req.t.tcm_ifindex = ifindex;
	req.t.tcm_parent = parent;

	if (sendto(sock, &req, req.n.nlmsg_len, 0, (struct sockaddr *)&snl, sizeof(snl)) < 0)
		goto out;

	buf = XMALLOC(MTYPE_TMP, NL_RCV_PKT_BUF_SIZE);

	while (!done) {
		ssize_t n = recv(sock, buf, NL_RCV_PKT_BUF_SIZE, 0);
		struct nlmsghdr *h;
		unsigned int len;

		if (n <= 0)
			break;

		len = (unsigned int)n;
		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
			if (h->nlmsg_seq != seq)
				continue;
			if (h->nlmsg_type == NLMSG_DONE) {
				done = true;
				ret = 0;
				break;
			}
			if (h->nlmsg_type == NLMSG_ERROR) {
				done = true;
				break;
			}
			msg_cb(h, arg);
		}
	}

	XFREE(MTYPE_TMP, buf);
out:
	close(sock);
	return ret;
}

struct tc_class_stats_args {
	ifindex_t ifindex;
	void (*cb)(const struct zebra_tc_class_stats *stats, void *arg);
	void *arg;
};

static void tc_class_stats_msg(struct nlmsghdr *h, void *arg)
{
	struct tc_class_stats_args *a = arg;

	tc_class_stats_parse(h, a->ifindex, a->cb, a->arg);
}

int kernel_tc_class_stats(ifindex_t ifindex,
			  void (*cb)(const struct zebra_tc_class_stats *stats, void *arg),
			  void *arg)
{
	struct tc_class_stats_args a = { .ifindex = ifindex, .cb = cb, .arg = arg };

	return tc_dump(RTM_GETTCLASS, ifindex, 0, tc_class_stats_msg, &a);
}

/*
 * Counters of the first action of a filter: TCA_*_ACT { 1 { TCA_ACT_STATS
 * { TCA_STATS_BASIC [TCA_STATS_PKT64] } } }.
 */
static bool tc_action_stats_parse(struct rtattr *acts, uint64_t *bytes, uint64_t *packets)
{
	struct rtattr *prio[TCA_ACT_MAX_PRIO + 1];
	struct rtattr *act[TCA_ACT_MAX + 1];
	struct rtattr *st[TCA_STATS_MAX + 1];
	struct gnet_stats_basic basic;

	netlink_parse_rtattr_nested(prio, TCA_ACT_MAX_PRIO, acts);
	if (!prio[1])
		return false;

	netlink_parse_rtattr_nested(act, TCA_ACT_MAX, prio[1]);
	if (!act[TCA_ACT_STATS])
		return false;

	netlink_parse_rtattr_nested(st, TCA_STATS_MAX, act[TCA_ACT_STATS]);
	if (!st[TCA_STATS_BASIC] || RTA_PAYLOAD(st[TCA_STATS_BASIC]) < sizeof(basic))
		return false;

	memcpy(&basic, RTA_DATA(st[TCA_STATS_BASIC]), sizeof(basic));
	*bytes = basic.bytes;
	*packets = basic.packets;
	if (st[TCA_STATS_PKT64] && RTA_PAYLOAD(st[TCA_STATS_PKT64]) >= sizeof(uint64_t))
		memcpy(packets, RTA_DATA(st[TCA_STATS_PKT64]), sizeof(uint64_t));

	return true;
}

struct tc_filter_stats_args {
	ifindex_t ifindex;
	void (*cb)(const struct zebra_tc_filter_stats *stats, void *arg);
	void *arg;
};

/* Verdict of a gact first action: TCA_*_ACT { 1 { "gact", OPTIONS { PARMS } } } */
static bool tc_action_gact_parse(struct rtattr *acts, int32_t *action)
{
	struct rtattr *prio[TCA_ACT_MAX_PRIO + 1];
	struct rtattr *act[TCA_ACT_MAX + 1];
	struct rtattr *opt[TCA_GACT_MAX + 1];
	struct tc_gact parms;

	netlink_parse_rtattr_nested(prio, TCA_ACT_MAX_PRIO, acts);
	if (!prio[1])
		return false;

	netlink_parse_rtattr_nested(act, TCA_ACT_MAX, prio[1]);
	if (!act[TCA_ACT_KIND] || strcmp(RTA_DATA(act[TCA_ACT_KIND]), "gact") ||
	    !act[TCA_ACT_OPTIONS])
		return false;

	netlink_parse_rtattr_nested(opt, TCA_GACT_MAX, act[TCA_ACT_OPTIONS]);
	if (!opt[TCA_GACT_PARMS] || RTA_PAYLOAD(opt[TCA_GACT_PARMS]) < sizeof(parms))
		return false;

	memcpy(&parms, RTA_DATA(opt[TCA_GACT_PARMS]), sizeof(parms));
	*action = parms.action;

	return true;
}

static void tc_filter_stats_msg(struct nlmsghdr *h, void *arg)
{
	struct tc_filter_stats_args *a = arg;
	struct rtattr *tb[TCA_MAX + 1];
	struct zebra_tc_filter_stats stats = {};
	struct tcmsg *tcm = NLMSG_DATA(h);
	int len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*tcm));

	if (h->nlmsg_type != RTM_NEWTFILTER || len < 0 || tcm->tcm_ifindex != a->ifindex)
		return;

	/* the per priority "header" entries have no handle */
	if (!tcm->tcm_handle)
		return;

	netlink_parse_rtattr(tb, TCA_MAX, TCA_RTA(tcm), len);

	stats.parent = tcm->tcm_parent;
	stats.handle = tcm->tcm_handle;
	stats.priority = TC_H_MAJ(tcm->tcm_info) >> 16;
	stats.protocol = ntohs(TC_H_MIN(tcm->tcm_info));
	if (tb[TCA_CHAIN])
		stats.chain = *(uint32_t *)RTA_DATA(tb[TCA_CHAIN]);
	if (tb[TCA_KIND])
		strlcpy(stats.kind, RTA_DATA(tb[TCA_KIND]), sizeof(stats.kind));

	if (tb[TCA_OPTIONS] && strcmp(stats.kind, "flower") == 0) {
		struct rtattr *opt[TCA_FLOWER_MAX + 1];

		netlink_parse_rtattr_nested(opt, TCA_FLOWER_MAX, tb[TCA_OPTIONS]);
		if (opt[TCA_FLOWER_ACT]) {
			stats.stats_valid = tc_action_stats_parse(opt[TCA_FLOWER_ACT],
								  &stats.bytes, &stats.packets);
			stats.gact_valid = tc_action_gact_parse(opt[TCA_FLOWER_ACT],
								&stats.gact_action);
		}
	}

	a->cb(&stats, a->arg);
}

int kernel_tc_filter_stats(ifindex_t ifindex, uint32_t parent,
			   void (*cb)(const struct zebra_tc_filter_stats *stats, void *arg),
			   void *arg)
{
	struct tc_filter_stats_args a = { .ifindex = ifindex, .cb = cb, .arg = arg };

	return tc_dump(RTM_GETTFILTER, ifindex, parent, tc_filter_stats_msg, &a);
}

struct tc_qdisc_kind_args {
	ifindex_t ifindex;
	uint32_t handle;
	char *kind;
	size_t len;
	bool found;
};

static void tc_qdisc_kind_msg(struct nlmsghdr *h, void *arg)
{
	struct tc_qdisc_kind_args *a = arg;
	struct rtattr *tb[TCA_MAX + 1];
	struct tcmsg *tcm = NLMSG_DATA(h);
	int len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*tcm));

	if (h->nlmsg_type != RTM_NEWQDISC || len < 0 || tcm->tcm_ifindex != a->ifindex ||
	    tcm->tcm_handle != a->handle)
		return;

	netlink_parse_rtattr(tb, TCA_MAX, TCA_RTA(tcm), len);
	if (!tb[TCA_KIND])
		return;

	strlcpy(a->kind, RTA_DATA(tb[TCA_KIND]), a->len);
	a->found = true;
}

int kernel_tc_qdisc_kind(ifindex_t ifindex, uint32_t handle, char *kind, size_t len)
{
	struct tc_qdisc_kind_args a = {
		.ifindex = ifindex,
		.handle = handle,
		.kind = kind,
		.len = len,
	};

	if (tc_dump(RTM_GETQDISC, ifindex, 0, tc_qdisc_kind_msg, &a) < 0 || !a.found)
		return -1;

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
