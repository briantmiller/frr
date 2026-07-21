// SPDX-License-Identifier: GPL-2.0-or-later
/* MPLS forwarding table updates using netlink over GNU/Linux system.
 * Copyright (C) 2016  Cumulus Networks, Inc.
 */

#include <zebra.h>
#include <sys/stat.h>

#ifdef HAVE_NETLINK

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_mpls.h"
#include "zebra/kernel_netlink.h"

ssize_t netlink_lsp_msg_encoder(struct zebra_dplane_ctx *ctx, void *buf,
				size_t buflen)
{
	int cmd;

	zlog_info("%s", __func__);
	/* Call to netlink layer based on type of update */
	if (dplane_ctx_get_op(ctx) == DPLANE_OP_LSP_DELETE) {
		cmd = RTM_DELROUTE;
	} else if (dplane_ctx_get_op(ctx) == DPLANE_OP_LSP_INSTALL ||
		   dplane_ctx_get_op(ctx) == DPLANE_OP_LSP_UPDATE) {

		/* Validate */
		if (dplane_ctx_get_best_nhlfe(ctx) == NULL) {
			if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_MPLS)
				zlog_debug("LSP in-label %u: update fails, no best NHLFE",
					   dplane_ctx_get_in_label(ctx));
			return -1;
		}

		cmd = RTM_NEWROUTE;
	} else
		/* Invalid op? */
		return -1;

	return netlink_mpls_multipath_msg_encode(cmd, ctx, buf, buflen);
}

enum netlink_msg_status netlink_put_lsp_update_msg(struct nl_batch *bth,
						   struct zebra_dplane_ctx *ctx)
{
	zlog_info("%s", __func__);
	return netlink_batch_add_msg(bth, ctx, netlink_lsp_msg_encoder, false);
}

void netlink_put_pw_check_mac(struct event *t) {
	struct zebra_dplane_ctx *ctx = EVENT_ARG(t);

	netlink_put_pw_update_msg(NULL, ctx);
}

int netlink_mpls_install_psw(ifindex_t dev, ifindex_t nh_dev, 
			     uint32_t local_label, uint32_t remote_label,
			     struct ethaddr dst, struct ethaddr src) {

	//TODO: Install ingress qdisc on dev and nh_dev

	/*
	struct zebra_tc_filter filter;

	filter.filter.ifindex = dev;
	filter.filter.handle = MPLS_TC_HANDLE;
	filter.filter.priority = 0x1;
	filter.filter.kind = TC_FILTER_FLOWER;
	filter.filter.u.flower.filter_bm = 0;
	filter.filter.u.flower.classid = MPLS_TC_HANDLE & 0xffff;
	*/
	//We need to send a ZAPI msg to do the actual install
	
	return 0;
}

/*
 * Pseudowire update api - not supported by netlink as of 12/18,
 * but note that the default has been to report 'success' for pw updates
 * on unsupported platforms.
 */
enum netlink_msg_status netlink_put_pw_update_msg(struct nl_batch *bth,
						  struct zebra_dplane_ctx *ctx)
{
	mpls_label_t local_label, remote_label;
	struct route_entry *re;
	const struct nexthop *nexthop;
        const struct nexthop_group *nhg;
	const union g_addr *gaddr;
	struct ipaddr ip;
	struct ethaddr mac;
	struct interface *ifp;
	struct event *t_mac_disc;
        char ip_buf[INET6_ADDRSTRLEN];
	char buf_mac[100];
	char buf_nh[100];
	char buf_gw[INET6_ADDRSTRLEN];
	bool mac_found = FALSE;
	snprintfrr(buf_nh, sizeof(buf_nh), "no nexthop");
	snprintfrr(buf_mac, sizeof(buf_mac), "");
        switch (dplane_ctx_get_pw_type(ctx)) {
        case PW_TYPE_ETHERNET:
                break;
        case PW_TYPE_ETHERNET_TAGGED:
                break;
        default:
                zlog_debug("%s: unhandled pseudowire type (%#X)", __func__,
                           dplane_ctx_get_pw_type(ctx));
                return ZEBRA_DPLANE_REQUEST_FAILURE;
        }
	t_mac_disc = dplane_ctx_get_pw_mac_disc_timer(ctx);
	gaddr = dplane_ctx_get_pw_dest(ctx);
        switch (dplane_ctx_get_pw_af(ctx)) {
        case AF_INET:
		inet_ntop(AF_INET, gaddr, buf_gw, sizeof(buf_gw));
		memset(&ip, 0, sizeof(ip));
	        ip.ipa_type = IPADDR_V4;
		ip.ipaddr_v4 = gaddr->ipv4;
                break;
        case AF_INET6:
		inet_ntop(AF_INET6, gaddr, buf_gw, sizeof(buf_gw));
		memset(&ip, 0, sizeof(ip));
	        ip.ipa_type = IPADDR_V6;
		ip.ipaddr_v6 = gaddr->ipv6;
                break;
        default:
                zlog_debug("%s: unhandled pseudowire address-family (%u)",
                           __func__, dplane_ctx_get_pw_af(ctx));
                return ZEBRA_DPLANE_REQUEST_FAILURE;
        }
	local_label = dplane_ctx_get_pw_local_label(ctx);
        remote_label = dplane_ctx_get_pw_remote_label(ctx);
	nhg = dplane_ctx_get_pw_nhg(ctx);
	if (!nhg || !nhg->nexthop) {
		nhg = dplane_ctx_get_pw_primary_nhg(ctx);
		if (!nhg || !nhg->nexthop)
			nhg = dplane_ctx_get_pw_backup_nhg(ctx);
	}
	if (nhg && nhg->nexthop) {
                for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			snprintfrr(buf_nh, sizeof(buf_nh), "%pNHv",
				nexthop);
			ipaddr2str(&ip, ip_buf, sizeof(ip_buf));
			//zlog_info("Looking up MAC for %s",ip_buf);
			if(!zebra_neigh_get_mac(nexthop->ifindex, &ip, &mac)) {
				mac_found = TRUE;
			} else {
				/* Send ARP request for next-hop, then retry this in 1 second */
				ifp = zebra_ns_lookup_ifp(zebra_ns_lookup(NS_DEFAULT), nexthop->ifindex);
				if (ifp) {
					dplane_neigh_discover(ifp, &ip);
					if (t_mac_disc)
						event_cancel(t_mac_disc);
					event_add_timer(zrouter.master, netlink_put_pw_check_mac, ctx, 1, t_mac_disc);
				}
			}
			break;
                }
        }
	if (mac_found) {
		zlog_info("%s %s %d/%d %s %s %pEA", __func__, dplane_ctx_get_ifname(ctx), local_label, remote_label, buf_nh, buf_gw, &mac);
		//TODO: create and set 'struct zebra_tc_filter *filter' and then pass to:
		//zebra_tc_filter_add(*filter) 
		//Look at zebra/zapi_msg.c function zread_tc_filter on how to create filters and add to zebra_
		//Create similar functions create actions within that filter
		//Since filter is declared in the function, that doesn't need to get freed, but the actions will need malloc and free
		//dplane_ctx_get_ifindex(ctx)
	} else
		zlog_info("%s %s %d/%d %s %s", __func__, dplane_ctx_get_ifname(ctx), local_label, remote_label, buf_nh, buf_gw);
	/* TODO: Call zebra_tc.c calls to create qdisc and filters for ingress and egress MPLS  */
	return FRR_NETLINK_SUCCESS;
}

int mpls_kernel_init(void)
{
	struct stat st;
	zlog_info("%s", __func__);
	return 0;

	/*
	 * Check if the MPLS module is loaded in the kernel.
	 */
	if (stat("/proc/sys/net/mpls", &st) != 0)
		return -1;

	return 0;
};

#endif /* HAVE_NETLINK */
