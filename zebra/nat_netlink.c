// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra stateful NAT - Linux kernel interaction.
 *
 * Two independent pieces live here:
 *
 *  - the dataplane encoder that turns a NAT tc object (struct
 *    dplane_nat_tc) into an rtnetlink qdisc/filter message: a clsact qdisc,
 *    or a flower filter whose action is act_ct ("ct") or act_gact (drop);
 *
 *  - synchronous helpers that read (and flush) the conntrack table and the
 *    conntrack statistics over NETLINK_NETFILTER, for the show and clear
 *    commands.
 */

#include <zebra.h>

#ifdef HAVE_NETLINK
#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/tc_act/tc_ct.h>
#include <linux/tc_act/tc_gact.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <netinet/if_ether.h>
#endif

#include "ns.h"
#include "privs.h"
#include "lib_errors.h"

#include "zebra/zebra_nat.h"
#include "zebra/zebra_dplane.h"

#ifdef HAVE_NETLINK

#include "lib/netlink_parser.h"

#include "zebra/kernel_netlink.h"
#include "zebra/nat_netlink.h"
#include "zebra/zebra_netns_notify.h"

/*
 * Traffic control encoding
 */

static uint16_t nat_ct_state_to_flower(uint8_t state)
{
	uint16_t f = 0;

	if (state & DPLANE_NAT_CT_STATE_NEW)
		f |= TCA_FLOWER_KEY_CT_FLAGS_NEW;
	if (state & DPLANE_NAT_CT_STATE_EST)
		f |= TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED;
	if (state & DPLANE_NAT_CT_STATE_REL)
		f |= TCA_FLOWER_KEY_CT_FLAGS_RELATED;
	if (state & DPLANE_NAT_CT_STATE_TRK)
		f |= TCA_FLOWER_KEY_CT_FLAGS_TRACKED;
	if (state & DPLANE_NAT_CT_STATE_INV)
		f |= TCA_FLOWER_KEY_CT_FLAGS_INVALID;
	if (state & DPLANE_NAT_CT_STATE_RPL)
		f |= TCA_FLOWER_KEY_CT_FLAGS_REPLY;

	return f;
}

static uint16_t nat_ct_flags_to_act(uint8_t flags)
{
	uint16_t f = 0;

	if (flags & DPLANE_NAT_CT_COMMIT)
		f |= TCA_CT_ACT_COMMIT;
	if (flags & (DPLANE_NAT_CT_NAT | DPLANE_NAT_CT_NAT_SRC | DPLANE_NAT_CT_NAT_DST))
		f |= TCA_CT_ACT_NAT;
	if (flags & DPLANE_NAT_CT_NAT_SRC)
		f |= TCA_CT_ACT_NAT_SRC;
	if (flags & DPLANE_NAT_CT_NAT_DST)
		f |= TCA_CT_ACT_NAT_DST;

	return f;
}

/* Encode the single action of a NAT filter (TCA_FLOWER_ACT contents) */
static bool nat_tc_put_action(struct nlmsghdr *n, size_t datalen, const struct dplane_nat_tc *tc)
{
	struct rtattr *acts, *act, *opts;
	int control;

	control = tc->goto_chain ? (int)(TC_ACT_GOTO_CHAIN | tc->goto_chain_index) : TC_ACT_OK;

	acts = nl_attr_nest(n, datalen, TCA_FLOWER_ACT);
	if (!acts)
		return false;

	/* Actions are a list nested by their (1-based) order */
	act = nl_attr_nest(n, datalen, 1);
	if (!act)
		return false;

	switch (tc->action) {
	case DPLANE_NAT_TC_ACT_CT: {
		struct tc_ct parms = { .action = control };

		if (!nl_attr_put(n, datalen, TCA_ACT_KIND, "ct", sizeof("ct")))
			return false;

		opts = nl_attr_nest(n, datalen, TCA_ACT_OPTIONS);
		if (!opts)
			return false;

		if (!nl_attr_put(n, datalen, TCA_CT_PARMS, &parms, sizeof(parms)))
			return false;
		if (!nl_attr_put16(n, datalen, TCA_CT_ACTION, nat_ct_flags_to_act(tc->ct_flags)))
			return false;
		if (tc->ct_zone && !nl_attr_put16(n, datalen, TCA_CT_ZONE, tc->ct_zone))
			return false;
		if (tc->ct_flags & (DPLANE_NAT_CT_NAT_SRC | DPLANE_NAT_CT_NAT_DST)) {
			if (!nl_attr_put32(n, datalen, TCA_CT_NAT_IPV4_MIN, tc->nat_addr.s_addr))
				return false;
			if (!nl_attr_put32(n, datalen, TCA_CT_NAT_IPV4_MAX, tc->nat_addr.s_addr))
				return false;
			if (tc->nat_port &&
			    (!nl_attr_put16(n, datalen, TCA_CT_NAT_PORT_MIN, htons(tc->nat_port)) ||
			     !nl_attr_put16(n, datalen, TCA_CT_NAT_PORT_MAX, htons(tc->nat_port))))
				return false;
		}
		nl_attr_nest_end(n, opts);
		break;
	}
	case DPLANE_NAT_TC_ACT_DROP: {
		struct tc_gact parms = { .action = TC_ACT_SHOT };

		if (!nl_attr_put(n, datalen, TCA_ACT_KIND, "gact", sizeof("gact")))
			return false;

		opts = nl_attr_nest(n, datalen, TCA_ACT_OPTIONS);
		if (!opts)
			return false;
		if (!nl_attr_put(n, datalen, TCA_GACT_PARMS, &parms, sizeof(parms)))
			return false;
		nl_attr_nest_end(n, opts);
		break;
	}
	case DPLANE_NAT_TC_ACT_NONE: {
		struct tc_gact parms = { .action = control };

		if (!nl_attr_put(n, datalen, TCA_ACT_KIND, "gact", sizeof("gact")))
			return false;

		opts = nl_attr_nest(n, datalen, TCA_ACT_OPTIONS);
		if (!opts)
			return false;
		if (!nl_attr_put(n, datalen, TCA_GACT_PARMS, &parms, sizeof(parms)))
			return false;
		nl_attr_nest_end(n, opts);
		break;
	}
	}

	nl_attr_nest_end(n, act);
	nl_attr_nest_end(n, acts);

	return true;
}

static bool nat_tc_put_flower(struct nlmsghdr *n, size_t datalen, const struct dplane_nat_tc *tc)
{
	struct rtattr *opts;
	uint32_t host_mask = 0xffffffff;

	if (!nl_attr_put(n, datalen, TCA_KIND, "flower", sizeof("flower")))
		return false;

	opts = nl_attr_nest(n, datalen, TCA_OPTIONS);
	if (!opts)
		return false;

	if (!nl_attr_put16(n, datalen, TCA_FLOWER_KEY_ETH_TYPE, htons(ETH_P_IP)))
		return false;

	if (tc->match & DPLANE_NAT_TC_MATCH_INDEV) {
		if (!nl_attr_put(n, datalen, TCA_FLOWER_INDEV, tc->indev, strlen(tc->indev) + 1))
			return false;
	}

	if (tc->match & DPLANE_NAT_TC_MATCH_SRC_IP) {
		if (!nl_attr_put32(n, datalen, TCA_FLOWER_KEY_IPV4_SRC, tc->src_ip.s_addr) ||
		    !nl_attr_put32(n, datalen, TCA_FLOWER_KEY_IPV4_SRC_MASK, host_mask))
			return false;
	}

	if (tc->match & DPLANE_NAT_TC_MATCH_DST_IP) {
		if (!nl_attr_put32(n, datalen, TCA_FLOWER_KEY_IPV4_DST, tc->dst_ip.s_addr) ||
		    !nl_attr_put32(n, datalen, TCA_FLOWER_KEY_IPV4_DST_MASK, host_mask))
			return false;
	}

	if (tc->match & DPLANE_NAT_TC_MATCH_IP_PROTO) {
		if (!nl_attr_put8(n, datalen, TCA_FLOWER_KEY_IP_PROTO, tc->ip_proto))
			return false;
	}

	if (tc->match & DPLANE_NAT_TC_MATCH_DST_PORT) {
		int type;

		if (tc->ip_proto == IPPROTO_TCP)
			type = TCA_FLOWER_KEY_TCP_DST;
		else if (tc->ip_proto == IPPROTO_UDP)
			type = TCA_FLOWER_KEY_UDP_DST;
		else
			return false;

		if (!nl_attr_put16(n, datalen, type, htons(tc->dst_port)))
			return false;
	}

	if (tc->match & DPLANE_NAT_TC_MATCH_CT_STATE) {
		if (!nl_attr_put16(n, datalen, TCA_FLOWER_KEY_CT_STATE,
				   nat_ct_state_to_flower(tc->ct_state)) ||
		    !nl_attr_put16(n, datalen, TCA_FLOWER_KEY_CT_STATE_MASK,
				   nat_ct_state_to_flower(tc->ct_state_mask)))
			return false;
	}

	/* conntrack is a software-only feature for us */
	if (!nl_attr_put32(n, datalen, TCA_FLOWER_FLAGS, TCA_CLS_FLAGS_SKIP_HW))
		return false;

	if (!nat_tc_put_action(n, datalen, tc))
		return false;

	nl_attr_nest_end(n, opts);

	return true;
}

static ssize_t netlink_nat_tc_msg_encode(struct zebra_dplane_ctx *ctx, void *data, size_t datalen)
{
	const struct dplane_nat_tc *tc = dplane_ctx_get_nat_tc(ctx);
	bool del = (dplane_ctx_get_op(ctx) == DPLANE_OP_NAT_TC_DELETE);
	struct nlsock *nl;
	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[0];
	} *req = data;

	if (datalen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));
	if (!nl)
		return -1;

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	/*
	 * Installs are idempotent: create the object or replace the one with
	 * the same handle (what "tc ... replace" does).
	 */
	req->n.nlmsg_flags = NLM_F_REQUEST;
	if (!del)
		req->n.nlmsg_flags |= NLM_F_CREATE;
	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->t.tcm_family = AF_UNSPEC;
	req->t.tcm_ifindex = tc->ifindex;

	if (tc->obj == DPLANE_NAT_TC_QDISC) {
		req->n.nlmsg_type = del ? RTM_DELQDISC : RTM_NEWQDISC;
		if (!del)
			req->n.nlmsg_flags |= NLM_F_REPLACE;
		req->t.tcm_parent = TC_H_CLSACT;
		req->t.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);

		if (!nl_attr_put(&req->n, datalen, TCA_KIND, "clsact", sizeof("clsact")))
			return 0;

		return NLMSG_ALIGN(req->n.nlmsg_len);
	}

	req->n.nlmsg_type = del ? RTM_DELTFILTER : RTM_NEWTFILTER;
	req->t.tcm_parent = TC_H_MAKE(TC_H_CLSACT, tc->egress ? TC_H_MIN_EGRESS : TC_H_MIN_INGRESS);
	req->t.tcm_info = TC_H_MAKE((uint32_t)tc->prio << 16, htons(ETH_P_IP));
	req->t.tcm_handle = tc->handle;

	if (!nl_attr_put32(&req->n, datalen, TCA_CHAIN, tc->chain))
		return 0;

	if (!del) {
		if (!nat_tc_put_flower(&req->n, datalen, tc))
			return 0;
	} else if (tc->handle) {
		/* Deleting one filter by handle needs the classifier kind */
		if (!nl_attr_put(&req->n, datalen, TCA_KIND, "flower", sizeof("flower")))
			return 0;
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

enum netlink_msg_status netlink_put_nat_tc_update_msg(struct nl_batch *bth,
						      struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op = dplane_ctx_get_op(ctx);

	if (op != DPLANE_OP_NAT_TC_INSTALL && op != DPLANE_OP_NAT_TC_DELETE)
		return FRR_NETLINK_ERROR;

	return netlink_batch_add_msg(bth, ctx, netlink_nat_tc_msg_encode,
				     dplane_ctx_nat_tc_ignore_errors(ctx));
}

/*
 * Conntrack access over NETLINK_NETFILTER.
 *
 * These are only used to serve operator commands, so a short-lived private
 * socket in the right namespace is used rather than one of zebra's dataplane
 * sockets.
 */

#define NAT_NFNL_BUFSIZE (64 * 1024)

struct nat_nfnl {
	int sock;
	uint32_t seq;
	uint32_t pid;
	uint8_t *buf;
};

static int nat_nfnl_open(struct nat_nfnl *nfnl, ns_id_t ns_id)
{
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
	socklen_t len = sizeof(snl);
	struct timeval tv = { .tv_sec = 2 };
	int rcvbuf = 1024 * 1024;
	int err = 0;

	memset(nfnl, 0, sizeof(*nfnl));

	frr_with_privs (&zserv_privs) {
		nfnl->sock = ns_socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER, ns_id);
		if (nfnl->sock < 0)
			err = errno;
	}
	if (nfnl->sock < 0)
		return -err;

	if (bind(nfnl->sock, (struct sockaddr *)&snl, sizeof(snl)) < 0 ||
	    getsockname(nfnl->sock, (struct sockaddr *)&snl, &len) < 0) {
		err = errno;

		close(nfnl->sock);
		nfnl->sock = -1;
		return -err;
	}

	(void)setsockopt(nfnl->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(nfnl->sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

	nfnl->pid = snl.nl_pid;
	nfnl->seq = (uint32_t)time(NULL);
	nfnl->buf = XMALLOC(MTYPE_TMP, NAT_NFNL_BUFSIZE);

	return 0;
}

static void nat_nfnl_close(struct nat_nfnl *nfnl)
{
	if (nfnl->sock >= 0)
		close(nfnl->sock);
	nfnl->sock = -1;
	XFREE(MTYPE_TMP, nfnl->buf);
}

/* Start a ctnetlink request in 'buf' */
static struct nlmsghdr *nat_nfnl_msg_init(struct nat_nfnl *nfnl, void *buf, size_t buflen,
					  uint16_t msg, uint16_t flags)
{
	struct nlmsghdr *n = buf;
	struct nfgenmsg *nfg;

	memset(buf, 0, buflen);
	n->nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
	n->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | msg;
	n->nlmsg_flags = NLM_F_REQUEST | flags;
	n->nlmsg_seq = ++nfnl->seq;
	n->nlmsg_pid = nfnl->pid;

	nfg = NLMSG_DATA(n);
	nfg->nfgen_family = AF_INET;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = 0;

	return n;
}

/*
 * Send a request and process every answer with 'cb' until the dump is done
 * (or, for non-dump requests, until the ack arrives).
 */
static int nat_nfnl_talk(struct nat_nfnl *nfnl, struct nlmsghdr *req,
			 int (*cb)(struct nlmsghdr *h, void *arg), void *arg)
{
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
	uint32_t seq = req->nlmsg_seq;
	bool stop = false;
	ssize_t ret;
	int err = 0;

	/* nfnetlink checks CAP_NET_ADMIN of the sender at send time */
	frr_with_privs (&zserv_privs) {
		ret = sendto(nfnl->sock, req, req->nlmsg_len, 0, (struct sockaddr *)&snl,
			     sizeof(snl));
		if (ret < 0)
			err = errno;
	}
	if (ret < 0)
		return -err;

	while (true) {
		struct nlmsghdr *h;
		int status;

		ret = recv(nfnl->sock, nfnl->buf, NAT_NFNL_BUFSIZE, 0);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (ret == 0)
			return -EIO;

		status = (int)ret;
		for (h = (struct nlmsghdr *)nfnl->buf; NLMSG_OK(h, (uint32_t)status);
		     h = NLMSG_NEXT(h, status)) {
			if (h->nlmsg_seq != seq || h->nlmsg_pid != nfnl->pid)
				continue;

			if (h->nlmsg_type == NLMSG_DONE)
				return 0;

			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *nlerr = NLMSG_DATA(h);

				/* error 0 is the ack of a non-dump request */
				return nlerr->error;
			}

			/*
			 * Once the caller has seen enough keep draining the
			 * answer so the socket is left in a sane state.
			 */
			if (!stop && cb && cb(h, arg))
				stop = true;
		}
	}
}

static void nat_ct_parse_tuple(struct rtattr *rta, struct zebra_nat_ct_tuple *t)
{
	struct rtattr *tb[CTA_TUPLE_MAX + 1];
	struct rtattr *ip[CTA_IP_MAX + 1];
	struct rtattr *pr[CTA_PROTO_MAX + 1];

	netlink_parse_rtattr_flags(tb, CTA_TUPLE_MAX, RTA_DATA(rta), RTA_PAYLOAD(rta),
				   NLA_F_NESTED);

	if (tb[CTA_TUPLE_IP]) {
		netlink_parse_rtattr_flags(ip, CTA_IP_MAX, RTA_DATA(tb[CTA_TUPLE_IP]),
					   RTA_PAYLOAD(tb[CTA_TUPLE_IP]), NLA_F_NESTED);
		if (ip[CTA_IP_V4_SRC])
			memcpy(&t->src, RTA_DATA(ip[CTA_IP_V4_SRC]), sizeof(t->src));
		if (ip[CTA_IP_V4_DST])
			memcpy(&t->dst, RTA_DATA(ip[CTA_IP_V4_DST]), sizeof(t->dst));
	}

	if (tb[CTA_TUPLE_PROTO]) {
		netlink_parse_rtattr_flags(pr, CTA_PROTO_MAX, RTA_DATA(tb[CTA_TUPLE_PROTO]),
					   RTA_PAYLOAD(tb[CTA_TUPLE_PROTO]), NLA_F_NESTED);
		if (pr[CTA_PROTO_NUM])
			t->proto = *(uint8_t *)RTA_DATA(pr[CTA_PROTO_NUM]);
		if (pr[CTA_PROTO_SRC_PORT])
			t->sport = ntohs(*(uint16_t *)RTA_DATA(pr[CTA_PROTO_SRC_PORT]));
		if (pr[CTA_PROTO_DST_PORT])
			t->dport = ntohs(*(uint16_t *)RTA_DATA(pr[CTA_PROTO_DST_PORT]));
		if (pr[CTA_PROTO_ICMP_ID])
			t->sport = ntohs(*(uint16_t *)RTA_DATA(pr[CTA_PROTO_ICMP_ID]));
		if (pr[CTA_PROTO_ICMP_TYPE])
			t->icmp_type = *(uint8_t *)RTA_DATA(pr[CTA_PROTO_ICMP_TYPE]);
		if (pr[CTA_PROTO_ICMP_CODE])
			t->icmp_code = *(uint8_t *)RTA_DATA(pr[CTA_PROTO_ICMP_CODE]);
	}
}

static void nat_ct_parse_counters(struct rtattr *rta, uint64_t *pkts, uint64_t *bytes)
{
	struct rtattr *tb[CTA_COUNTERS_MAX + 1];
	uint64_t v;

	netlink_parse_rtattr_flags(tb, CTA_COUNTERS_MAX, RTA_DATA(rta), RTA_PAYLOAD(rta),
				   NLA_F_NESTED);

	if (tb[CTA_COUNTERS_PACKETS]) {
		memcpy(&v, RTA_DATA(tb[CTA_COUNTERS_PACKETS]), sizeof(v));
		*pkts = be64toh(v);
	}
	if (tb[CTA_COUNTERS_BYTES]) {
		memcpy(&v, RTA_DATA(tb[CTA_COUNTERS_BYTES]), sizeof(v));
		*bytes = be64toh(v);
	}
}

static uint32_t nat_rta_be32(const struct rtattr *rta)
{
	uint32_t v;

	memcpy(&v, RTA_DATA(rta), sizeof(v));
	return ntohl(v);
}

struct nat_ct_walk_ctx {
	uint16_t zone;
	zebra_nat_ct_walk_cb cb;
	void *arg;
};

static int nat_ct_walk_msg(struct nlmsghdr *h, void *arg)
{
	struct nat_ct_walk_ctx *wctx = arg;
	struct rtattr *tb[CTA_MAX + 1];
	struct zebra_nat_ct_entry e = {};
	struct nfgenmsg *nfg = NLMSG_DATA(h);
	int len;

	if ((h->nlmsg_type >> 8) != NFNL_SUBSYS_CTNETLINK ||
	    (h->nlmsg_type & 0xff) != IPCTNL_MSG_CT_NEW)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct nfgenmsg));
	if (len < 0 || nfg->nfgen_family != AF_INET)
		return 0;

	netlink_parse_rtattr_flags(tb, CTA_MAX,
				   (struct rtattr *)((char *)nfg + NLMSG_ALIGN(sizeof(*nfg))), len,
				   NLA_F_NESTED);

	if (tb[CTA_ZONE]) {
		uint16_t z;

		memcpy(&z, RTA_DATA(tb[CTA_ZONE]), sizeof(z));
		e.zone = ntohs(z);
	}

	/* Older kernels ignore the zone filter in the request */
	if (wctx->zone && e.zone != wctx->zone)
		return 0;

	if (!tb[CTA_TUPLE_ORIG] || !tb[CTA_TUPLE_REPLY])
		return 0;

	nat_ct_parse_tuple(tb[CTA_TUPLE_ORIG], &e.orig);
	nat_ct_parse_tuple(tb[CTA_TUPLE_REPLY], &e.reply);

	if (RTA_LENGTH(RTA_PAYLOAD(tb[CTA_TUPLE_ORIG])) <= sizeof(e.raw_orig)) {
		e.raw_orig_len = RTA_LENGTH(RTA_PAYLOAD(tb[CTA_TUPLE_ORIG]));
		memcpy(e.raw_orig, tb[CTA_TUPLE_ORIG], e.raw_orig_len);
	}

	if (tb[CTA_STATUS])
		e.status = nat_rta_be32(tb[CTA_STATUS]);
	if (tb[CTA_TIMEOUT])
		e.timeout = nat_rta_be32(tb[CTA_TIMEOUT]);
	if (tb[CTA_MARK])
		e.mark = nat_rta_be32(tb[CTA_MARK]);
	if (tb[CTA_ID])
		e.id = nat_rta_be32(tb[CTA_ID]);

	if (tb[CTA_COUNTERS_ORIG] || tb[CTA_COUNTERS_REPLY]) {
		e.has_counters = true;
		if (tb[CTA_COUNTERS_ORIG])
			nat_ct_parse_counters(tb[CTA_COUNTERS_ORIG], &e.pkts_orig, &e.bytes_orig);
		if (tb[CTA_COUNTERS_REPLY])
			nat_ct_parse_counters(tb[CTA_COUNTERS_REPLY], &e.pkts_reply,
					      &e.bytes_reply);
	}

	if (tb[CTA_PROTOINFO]) {
		struct rtattr *pi[CTA_PROTOINFO_MAX + 1];

		netlink_parse_rtattr_flags(pi, CTA_PROTOINFO_MAX, RTA_DATA(tb[CTA_PROTOINFO]),
					   RTA_PAYLOAD(tb[CTA_PROTOINFO]), NLA_F_NESTED);
		if (pi[CTA_PROTOINFO_TCP]) {
			struct rtattr *tcp[CTA_PROTOINFO_TCP_MAX + 1];

			netlink_parse_rtattr_flags(tcp, CTA_PROTOINFO_TCP_MAX,
						   RTA_DATA(pi[CTA_PROTOINFO_TCP]),
						   RTA_PAYLOAD(pi[CTA_PROTOINFO_TCP]),
						   NLA_F_NESTED);
			if (tcp[CTA_PROTOINFO_TCP_STATE]) {
				e.has_tcp_state = true;
				e.tcp_state = *(uint8_t *)RTA_DATA(tcp[CTA_PROTOINFO_TCP_STATE]);
			}
		}
	}

	return wctx->cb(&e, wctx->arg);
}

int kernel_nat_ct_walk(ns_id_t ns_id, uint16_t zone, zebra_nat_ct_walk_cb cb, void *arg)
{
	struct nat_ct_walk_ctx wctx = { .zone = zone, .cb = cb, .arg = arg };
	struct nat_nfnl nfnl;
	uint8_t reqbuf[128];
	struct nlmsghdr *n;
	int ret;

	ret = nat_nfnl_open(&nfnl, ns_id);
	if (ret < 0)
		return ret;

	n = nat_nfnl_msg_init(&nfnl, reqbuf, sizeof(reqbuf), IPCTNL_MSG_CT_GET, NLM_F_DUMP);
	if (zone)
		nl_attr_put16(n, sizeof(reqbuf), CTA_ZONE, htons(zone));

	ret = nat_nfnl_talk(&nfnl, n, nat_ct_walk_msg, &wctx);

	nat_nfnl_close(&nfnl);

	return ret;
}

static int nat_ct_stats_cpu_msg(struct nlmsghdr *h, void *arg)
{
	struct zebra_nat_ct_stats *st = arg;
	struct rtattr *tb[CTA_STATS_MAX + 1];
	struct nfgenmsg *nfg = NLMSG_DATA(h);
	int len;

	if ((h->nlmsg_type & 0xff) != IPCTNL_MSG_CT_GET_STATS_CPU)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct nfgenmsg));
	if (len < 0)
		return 0;

	netlink_parse_rtattr(tb, CTA_STATS_MAX,
			     (struct rtattr *)((char *)nfg + NLMSG_ALIGN(sizeof(*nfg))), len);

	st->cpus++;

#define NAT_STAT_ADD(field, attr)                                                                 \
	do {                                                                                      \
		if (tb[attr])                                                                     \
			st->field += nat_rta_be32(tb[attr]);                                      \
	} while (0)

	NAT_STAT_ADD(found, CTA_STATS_FOUND);
	NAT_STAT_ADD(invalid, CTA_STATS_INVALID);
	NAT_STAT_ADD(insert, CTA_STATS_INSERT);
	NAT_STAT_ADD(insert_failed, CTA_STATS_INSERT_FAILED);
	NAT_STAT_ADD(drop, CTA_STATS_DROP);
	NAT_STAT_ADD(early_drop, CTA_STATS_EARLY_DROP);
	NAT_STAT_ADD(error, CTA_STATS_ERROR);
	NAT_STAT_ADD(search_restart, CTA_STATS_SEARCH_RESTART);
	NAT_STAT_ADD(clash_resolve, CTA_STATS_CLASH_RESOLVE);
	NAT_STAT_ADD(chain_toolong, CTA_STATS_CHAIN_TOOLONG);

#undef NAT_STAT_ADD

	return 0;
}

static int nat_ct_stats_global_msg(struct nlmsghdr *h, void *arg)
{
	struct zebra_nat_ct_stats *st = arg;
	struct rtattr *tb[CTA_STATS_GLOBAL_MAX + 1];
	struct nfgenmsg *nfg = NLMSG_DATA(h);
	int len;

	if ((h->nlmsg_type & 0xff) != IPCTNL_MSG_CT_GET_STATS)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct nfgenmsg));
	if (len < 0)
		return 0;

	netlink_parse_rtattr(tb, CTA_STATS_GLOBAL_MAX,
			     (struct rtattr *)((char *)nfg + NLMSG_ALIGN(sizeof(*nfg))), len);

	if (tb[CTA_STATS_GLOBAL_ENTRIES]) {
		st->has_global = true;
		st->entries = nat_rta_be32(tb[CTA_STATS_GLOBAL_ENTRIES]);
	}
	if (tb[CTA_STATS_GLOBAL_MAX_ENTRIES])
		st->max_entries = nat_rta_be32(tb[CTA_STATS_GLOBAL_MAX_ENTRIES]);

	return 0;
}

int kernel_nat_ct_stats(ns_id_t ns_id, struct zebra_nat_ct_stats *st)
{
	struct nat_nfnl nfnl;
	uint8_t reqbuf[64];
	struct nlmsghdr *n;
	int ret;

	memset(st, 0, sizeof(*st));

	ret = nat_nfnl_open(&nfnl, ns_id);
	if (ret < 0)
		return ret;

	n = nat_nfnl_msg_init(&nfnl, reqbuf, sizeof(reqbuf), IPCTNL_MSG_CT_GET_STATS_CPU,
			      NLM_F_DUMP);
	((struct nfgenmsg *)NLMSG_DATA(n))->nfgen_family = AF_UNSPEC;
	ret = nat_nfnl_talk(&nfnl, n, nat_ct_stats_cpu_msg, st);

	if (ret == 0) {
		n = nat_nfnl_msg_init(&nfnl, reqbuf, sizeof(reqbuf), IPCTNL_MSG_CT_GET_STATS,
				      NLM_F_ACK);
		((struct nfgenmsg *)NLMSG_DATA(n))->nfgen_family = AF_UNSPEC;
		/* Not supported by old kernels; not fatal */
		(void)nat_nfnl_talk(&nfnl, n, nat_ct_stats_global_msg, st);
	}

	nat_nfnl_close(&nfnl);

	return ret;
}

int kernel_nat_ct_delete(ns_id_t ns_id, const struct zebra_nat_ct_entry *entry)
{
	struct nat_nfnl nfnl;
	uint8_t reqbuf[512];
	struct nlmsghdr *n;
	int ret;

	if (entry->raw_orig_len == 0)
		return -EINVAL;

	ret = nat_nfnl_open(&nfnl, ns_id);
	if (ret < 0)
		return ret;

	n = nat_nfnl_msg_init(&nfnl, reqbuf, sizeof(reqbuf), IPCTNL_MSG_CT_DELETE, NLM_F_ACK);

	/* Echo the original tuple back, exactly as the kernel reported it */
	memcpy(NLMSG_TAIL(n), entry->raw_orig, entry->raw_orig_len);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(entry->raw_orig_len);

	nl_attr_put16(n, sizeof(reqbuf), CTA_ZONE, htons(entry->zone));
	if (entry->id)
		nl_attr_put32(n, sizeof(reqbuf), CTA_ID, htonl(entry->id));

	ret = nat_nfnl_talk(&nfnl, n, NULL, NULL);

	nat_nfnl_close(&nfnl);

	return ret;
}

#else /* !HAVE_NETLINK */

int kernel_nat_ct_walk(ns_id_t ns_id, uint16_t zone, zebra_nat_ct_walk_cb cb, void *arg)
{
	return -ENOTSUP;
}

int kernel_nat_ct_stats(ns_id_t ns_id, struct zebra_nat_ct_stats *st)
{
	memset(st, 0, sizeof(*st));
	return -ENOTSUP;
}

int kernel_nat_ct_delete(ns_id_t ns_id, const struct zebra_nat_ct_entry *entry)
{
	return -ENOTSUP;
}

#endif /* HAVE_NETLINK */
