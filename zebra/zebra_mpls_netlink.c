// SPDX-License-Identifier: GPL-2.0-or-later
/* MPLS forwarding table updates using netlink over GNU/Linux system.
 * Copyright (C) 2016  Cumulus Networks, Inc.
 */

#include <zebra.h>
#include <sys/stat.h>

#ifdef HAVE_NETLINK

#include <linux/pkt_sched.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "zebra/debug.h"
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_mpls.h"
#include "zebra/kernel_netlink.h"
#include "zebra/zebra_neigh.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_tc.h"
#include "zebra/interface.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_pw.h"

uint32_t zserv_session = 0;

ssize_t netlink_lsp_msg_encoder(struct zebra_dplane_ctx *ctx, void *buf,
				size_t buflen)
{
	int cmd;

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
	return netlink_batch_add_msg(bth, ctx, netlink_lsp_msg_encoder, false);
}

/*
 * Pseudowire update api - not supported by netlink as of 12/18,
 * but note that the default has been to report 'success' for pw updates
 * on unsupported platforms.
 */
enum netlink_msg_status netlink_put_pw_update_msg(struct nl_batch *bth,
						  struct zebra_dplane_ctx *ctx)
{
	uint32_t flags; 
	mpls_label_t local_label, remote_label, nh_label = 0;
	const struct nexthop *nexthop = NULL;
        const struct nexthop_group *nhg;
	bool mac_found = false;
	ifindex_t pw_ifindex, prev_nh_ifindex;
	
	switch (dplane_ctx_get_pw_type(ctx)) {
        case PW_TYPE_ETHERNET:
                break;
        case PW_TYPE_ETHERNET_TAGGED:
                break;
        default:
                zlog_info("%s: unhandled pseudowire type (%#X)", __func__,
                           dplane_ctx_get_pw_type(ctx));
                return ZEBRA_DPLANE_REQUEST_FAILURE;
        }

	flags = dplane_ctx_get_pw_flags(ctx);
	local_label = dplane_ctx_get_pw_local_label(ctx);
        remote_label = dplane_ctx_get_pw_remote_label(ctx);
	pw_ifindex = dplane_ctx_get_ifindex(ctx);
	prev_nh_ifindex = dplane_ctx_get_pw_prev_nh_ifindex(ctx);

	nhg = dplane_ctx_get_pw_nhg(ctx);
	if (!nhg || !nhg->nexthop) {
		nhg = dplane_ctx_get_pw_primary_nhg(ctx);
		if (!nhg || !nhg->nexthop)
			nhg = dplane_ctx_get_pw_backup_nhg(ctx);
	}
	if (nhg && nhg->nexthop) {
                for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			if (nexthop->nh_label && nexthop->nh_label->num_labels 
				&& nexthop->nh_label->label[0] > 15)
				nh_label = nexthop->nh_label->label[0];
			for (int o=0;o<ETH_ALEN;o++) {
				if (nexthop->rmac.octet[o]) {
					mac_found = true;
					break;
				}
			}
			if (!mac_found)
				nexthop = NULL;
			
			break;
                }
        }
	if (!nexthop)
		return FRR_NETLINK_ERROR;

	zlog_debug("%s %s(%d) %d/%d %pNHv %pEA", __func__, dplane_ctx_get_ifname(ctx), pw_ifindex, local_label, remote_label, nexthop, &nexthop->rmac);
	if (flags & F_PSEUDOWIRE_CWORD) { 
		zlog_warn("%s pseudowire %s(%d) will not be installed, control-word not available on this platform", __func__, dplane_ctx_get_ifname(ctx), pw_ifindex);
		return FRR_NETLINK_SUCCESS;
	}
               
	struct zebra_tc_qdisc qdisc;
	memset(&qdisc, 0, sizeof(qdisc));
	qdisc.qdisc.kind = TC_QDISC_INGRESS;
	qdisc.qdisc.ifindex = pw_ifindex;
	if (!prev_nh_ifindex)
		zebra_tc_qdisc_install(&qdisc);

	qdisc.qdisc.ifindex = nexthop->ifindex;
 	zebra_tc_qdisc_install(&qdisc);
	
	struct zebra_tc_filter filter;

	int aidx = 0;
	memset(&filter, 0, sizeof(filter));
	filter.filter.ifindex = pw_ifindex;
	filter.filter.kind = TC_FILTER_MATCHALL;
	filter.filter.handle = TC_H_MAKE(1,0);
	filter.filter.parent = TC_H_MAKE(TC_H_CLSACT,TC_H_MIN_INGRESS);
	filter.filter.protocol = ETH_P_ALL;
	filter.filter.priority = pw_ifindex;


	filter.filter.action_count++;
	filter.filter.actions[aidx].kind = TC_ACTION_MPLS;
	filter.filter.actions[aidx].u.mpls.mode = TC_MPLS_PUSH_MAC;
	filter.filter.actions[aidx].u.mpls.label = remote_label;
	filter.filter.actions[aidx].u.mpls.ttl = 64;
	filter.filter.actions[aidx].u.mpls.bos = 1;

	if (nh_label) {
		++aidx;
		filter.filter.action_count++;
		filter.filter.actions[aidx].kind = TC_ACTION_MPLS;
		filter.filter.actions[aidx].u.mpls.mode = TC_MPLS_PUSH_MAC;
		filter.filter.actions[aidx].u.mpls.label = nh_label;
		filter.filter.actions[aidx].u.mpls.bos = 0;
		filter.filter.actions[aidx].u.mpls.ttl = 64;
	}
		
	++aidx;
	filter.filter.action_count++;
	filter.filter.actions[aidx].kind = TC_ACTION_VLAN;
	filter.filter.actions[aidx].u.vlan.mode = TC_VLAN_PUSH_ETH;
	memcpy(&filter.filter.actions[aidx].u.vlan.dst,nexthop->rmac.octet,ETH_ALEN);
	memcpy(&filter.filter.actions[aidx].u.vlan.src,nexthop->smac.octet,ETH_ALEN);
		
	++aidx;
	filter.filter.action_count++;
	filter.filter.actions[aidx].kind = TC_ACTION_MIRRED;
	filter.filter.actions[aidx].u.mirred.mode = TC_MIRRED_REDIRECT;
	filter.filter.actions[aidx].u.mirred.direction = TC_MIRRED_EGRESS;
	filter.filter.actions[aidx].u.mirred.ifindex = nexthop->ifindex;

	//if (prev_nh_ifindex)
		zebra_tc_filter_delete(&filter);
	zebra_tc_filter_add(&filter);

	/* 
	 * TODO: Remove the filter from the previous next-hop (if any) 
	 * */

	if (prev_nh_ifindex && prev_nh_ifindex != nexthop->ifindex) {
		memset(&filter, 0, sizeof(filter));
		filter.filter.ifindex = prev_nh_ifindex;
		filter.filter.handle = TC_H_MAKE(1,0);
		filter.filter.parent = TC_H_MAKE(TC_H_CLSACT,TC_H_MIN_INGRESS);
		filter.filter.kind = TC_FILTER_FLOWER;
		filter.filter.protocol = ETH_P_MPLS_UC;
		filter.filter.priority = pw_ifindex;
		filter.filter.u.flower.mpls_label = local_label;
		filter.filter.u.flower.filter_bm = TC_FLOWER_MPLS;
		zebra_tc_filter_delete(&filter);
		//qdisc.qdisc.ifindex = prev_nh_ifindex;
		//zebra_tc_qdisc_uninstall(&qdisc);
	}
	memset(&filter, 0, sizeof(filter));
	filter.filter.ifindex = nexthop->ifindex;
	filter.filter.handle = TC_H_MAKE(1,0);
	filter.filter.parent = TC_H_MAKE(TC_H_CLSACT,TC_H_MIN_INGRESS);
	filter.filter.kind = TC_FILTER_FLOWER;
	filter.filter.protocol = ETH_P_MPLS_UC;
	filter.filter.priority = pw_ifindex;
	filter.filter.u.flower.mpls_label = local_label;
	filter.filter.u.flower.filter_bm = TC_FLOWER_MPLS;

	aidx = 0;
	filter.filter.action_count++;
	filter.filter.actions[aidx].kind = TC_ACTION_VLAN;
	filter.filter.actions[aidx].u.vlan.mode = TC_VLAN_POP_ETH;

	++aidx;
	filter.filter.action_count++;
	filter.filter.actions[aidx].kind = TC_ACTION_MPLS;
	filter.filter.actions[aidx].u.mpls.mode = TC_MPLS_POP;

	++aidx;
	filter.filter.action_count++;
	filter.filter.actions[aidx].kind = TC_ACTION_MIRRED;
	filter.filter.actions[aidx].u.mirred.mode = TC_MIRRED_REDIRECT;
	filter.filter.actions[aidx].u.mirred.direction = TC_MIRRED_EGRESS;
	filter.filter.actions[aidx].u.mirred.ifindex = pw_ifindex;

	//zebra_tc_filter_delete(&filter);
	zebra_tc_filter_add(&filter);

	return FRR_NETLINK_SUCCESS;
}

int mpls_kernel_init(void)
{
	struct stat st;

	/*
	 * Check if the MPLS module is loaded in the kernel.
	 */
	if (stat("/proc/sys/net/mpls", &st) != 0)
		return -1;

	return 0;
};

#endif /* HAVE_NETLINK */
