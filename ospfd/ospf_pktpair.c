// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF packet-pair link speed estimation.
 *
 * See ospf_pktpair.h for an overview and lib/pktpair.c for the
 * measurement method.
 */

#include <zebra.h>

#include <net/if_arp.h>
#include <sys/ioctl.h>
#ifdef GNU_LINUX
#include <linux/if_ether.h>
#endif

#include "if.h"
#include "vrf.h"
#include "vty.h"
#include "json.h"
#include "log.h"
#include "privs.h"
#include "table.h"
#include "pktpair.h"
#include "zclient.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_pktpair.h"

extern struct zebra_privs_t ospfd_privs;

/* ------------------------------------------------------------------ */
/* Configuration                                                      */
/* ------------------------------------------------------------------ */

static bool pp_enabled(struct interface *ifp)
{
	struct ospf_if_params *params = IF_DEF_PARAMS(ifp);

	return OSPF_IF_PARAM_CONFIGURED(params, pp_enable) && params->pp_enable;
}

static void pp_cfg(struct interface *ifp, struct pktpair_cfg *cfg)
{
	struct ospf_if_params *params = IF_DEF_PARAMS(ifp);

	cfg->interval = OSPF_IF_PARAM_CONFIGURED(params, pp_interval)
				? params->pp_interval
				: PKTPAIR_INTERVAL_DEFAULT;
	cfg->probes = OSPF_IF_PARAM_CONFIGURED(params, pp_probes)
			      ? params->pp_probes
			      : PKTPAIR_PROBES_DEFAULT;
	cfg->dscp = OSPF_IF_PARAM_CONFIGURED(params, pp_dscp)
			    ? params->pp_dscp
			    : PKTPAIR_DSCP_DEFAULT;
	cfg->respond_only = OSPF_IF_PARAM_CONFIGURED(params, pp_responder) &&
			    params->pp_responder;
}

/* ------------------------------------------------------------------ */
/* Session callbacks                                                  */
/* ------------------------------------------------------------------ */

static void pp_collect(struct pktpair_session *s, void *arg)
{
	struct ospf_interface *oi = arg;
	struct route_node *rn;

	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		struct ospf_neighbor *nbr = rn->info;

		if (nbr && nbr != oi->nbr_self && nbr->state >= NSM_TwoWay)
			pktpair_target_add(s, nbr->src);
	}
}

static void pp_tx_stack(struct pktpair_tx *tx, const char *reason)
{
	tx->mode = PKTPAIR_TX_STACK;
	tx->path = "ip-stack";
	tx->reason = reason;
	strlcpy(tx->desc, "IP stack, local egress QoS applies",
		sizeof(tx->desc));
}

/*
 * Pick the transmit path for one neighbor for the coming sample.  The
 * bypass path needs the neighbor's MAC address from the kernel ARP cache.
 * If it isn't there yet, this sample goes through the IP stack, which
 * also triggers ARP resolution for the next one.
 */
static bool pp_prepare(struct pktpair_session *s, struct pktpair_target *t,
		       struct pktpair_tx *tx, uint16_t ip_len, void *arg)
{
	struct ospf_interface *oi = arg;
	struct arpreq req = {};
	struct sockaddr_in *sin = (struct sockaddr_in *)&req.arp_pa;
	const char *reason;

	if (!oi->address)
		return false;
	tx->src = oi->address->u.prefix4;

	if (!pktpair_session_bypass_ok(s, &reason)) {
		pp_tx_stack(tx, reason);
		return true;
	}
	if (oi->ifp->ll_type != ZEBRA_LLT_ETHER) {
		pp_tx_stack(tx, "not an Ethernet interface");
		return true;
	}

	sin->sin_family = AF_INET;
	sin->sin_addr = t->dst;
	strlcpy(req.arp_dev, oi->ifp->name, sizeof(req.arp_dev));
	if (ioctl(pktpair_session_fd(s), SIOCGARP, &req) < 0 ||
	    !(req.arp_flags & ATF_COM)) {
		pp_tx_stack(tx, "neighbor MAC not resolved");
		return true;
	}

	tx->mode = PKTPAIR_TX_BYPASS;
	tx->path = "qdisc-bypass";
	tx->reason = NULL;
	strlcpy(tx->desc, "qdisc bypass (local egress QoS excluded)",
		sizeof(tx->desc));
	tx->ifindex = oi->ifp->ifindex;
	tx->protocol = ETH_P_IP;
	tx->halen = ETH_ALEN;
	memcpy(tx->lladdr, req.arp_ha.sa_data, ETH_ALEN);
	return true;
}

/* Measure and report probes only from neighbors on this interface. */
static bool pp_accept(struct pktpair_session *s, struct in_addr src,
		      void *arg)
{
	struct ospf_interface *oi = arg;
	struct route_node *rn;

	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		struct ospf_neighbor *nbr = rn->info;

		if (nbr && nbr != oi->nbr_self && nbr->state >= NSM_Init &&
		    IPV4_ADDR_SAME(&nbr->src, &src)) {
			route_unlock_node(rn);
			return true;
		}
	}
	return false;
}

/* Report a neighbor's detected bandwidth to zebra (or withdraw it). */
static void pp_zebra_send(struct pktpair_session *s, struct in_addr peer,
			  struct ospf_interface *oi, bool withdraw)
{
	struct zapi_detected_bw bw = { .ifindex = oi->ifp->ifindex };

	bw.nexthop.ipa_type = IPADDR_V4;
	bw.nexthop.ipaddr_v4 = peer;
	if (!withdraw)
		pktpair_peer_bw(s, peer, &bw.rtt_kbps, &bw.out_kbps,
				&bw.in_kbps);
	if (!bw.rtt_kbps && !bw.out_kbps && !bw.in_kbps)
		SET_FLAG(bw.flags, ZAPI_DETECTED_BW_DELETE);
	zclient_detected_bw_send(ospf_zclient, oi->ospf->vrf_id, &bw);
}

static void pp_changed(struct pktpair_session *s, struct in_addr peer,
		       void *arg)
{
	pp_zebra_send(s, peer, arg, false);
}

static void pp_withdraw(struct pktpair_session *s, struct in_addr peer,
			void *arg)
{
	pp_zebra_send(s, peer, arg, true);
}

static bool pp_debug(void *arg)
{
	return IS_DEBUG_OSPF_EVENT;
}

static const struct pktpair_ops ospf_pp_ops = {
	.collect = pp_collect,
	.prepare = pp_prepare,
	.accept = pp_accept,
	.changed = pp_changed,
	.debug = pp_debug,
};

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

void ospf_pp_if_up(struct ospf_interface *oi)
{
	struct pktpair_cfg cfg;

	if (!oi || !oi->ifp || !pp_enabled(oi->ifp) ||
	    oi->type == OSPF_IFTYPE_LOOPBACK ||
	    oi->type == OSPF_IFTYPE_VIRTUALLINK || oi->state == ISM_Down) {
		ospf_pp_if_down(oi);
		return;
	}

	pp_cfg(oi->ifp, &cfg);
	if (oi->pp)
		pktpair_session_set_cfg(oi->pp, &cfg);
	else
		oi->pp = pktpair_session_new(master, &ospfd_privs, oi->ifp,
					     oi->ospf->vrf_id, &cfg,
					     &ospf_pp_ops, oi);
}

void ospf_pp_if_down(struct ospf_interface *oi)
{
	if (!oi || !oi->pp)
		return;
	pktpair_session_foreach_peer(oi->pp, pp_withdraw, oi);
	pktpair_session_free(&oi->pp);
}

void ospf_pp_if_config_changed(struct interface *ifp)
{
	struct route_node *rn;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (oi)
			ospf_pp_if_up(oi); /* starts, updates or stops */
	}
}

/* ------------------------------------------------------------------ */
/* Display                                                            */
/* ------------------------------------------------------------------ */

void ospf_pp_show_nbr(struct vty *vty, struct ospf_neighbor *nbr,
		      json_object *json_neigh)
{
	struct ospf_interface *oi = nbr->oi;
	struct pktpair_cfg cfg;

	if (!oi || !oi->ifp || !pp_enabled(oi->ifp))
		return;

	pp_cfg(oi->ifp, &cfg);
	if (json_neigh) {
		json_object *json_pp = json_object_new_object();

		pktpair_show_peer(vty, json_pp, &cfg, oi->pp, nbr->src, NULL);
		json_object_object_add(json_neigh, "packetPair", json_pp);
	} else {
		pktpair_show_peer(vty, NULL, &cfg, oi->pp, nbr->src, "    ");
	}
}

void ospf_pp_show_if(struct vty *vty, struct ospf_interface *oi,
		     json_object *json_iface)
{
	struct pktpair_cfg cfg;
	const char *reason = NULL;
	bool bypass = false;

	if (!oi || !oi->ifp || !pp_enabled(oi->ifp))
		return;

	pp_cfg(oi->ifp, &cfg);
	if (oi->pp) {
		bypass = pktpair_session_bypass_ok(oi->pp, &reason);
		if (bypass && oi->ifp->ll_type != ZEBRA_LLT_ETHER) {
			bypass = false;
			reason = "not an Ethernet interface";
		}
	}

	if (json_iface) {
		json_object *json_pp = json_object_new_object();

		json_object_boolean_true_add(json_pp, "enabled");
		json_object_boolean_add(json_pp, "running", oi->pp != NULL);
		json_object_boolean_add(json_pp, "responder", cfg.respond_only);
		if (oi->pp) {
			json_object_boolean_add(json_pp, "qdiscBypass", bypass);
			if (!bypass && reason)
				json_object_string_add(json_pp,
						       "qdiscBypassReason",
						       reason);
		}
		json_object_int_add(json_pp, "intervalSec", cfg.interval);
		json_object_int_add(json_pp, "pairsPerSample", cfg.probes);
		json_object_int_add(json_pp, "dscp", cfg.dscp);
		pktpair_show_session(vty, json_pp, oi->pp, NULL);
		json_object_object_add(json_iface, "packetPair", json_pp);
	} else if (cfg.respond_only) {
		vty_out(vty,
			"  Packet-pair responder %s: measures neighbors' probes and reports back\n",
			oi->pp ? "active" : "configured");
	} else {
		vty_out(vty,
			"  Packet-pair probing %s: interval %us, %u pairs per sample, DSCP %u\n",
			oi->pp ? "active" : "configured", cfg.interval,
			cfg.probes, cfg.dscp);
		if (oi->pp && bypass)
			vty_out(vty,
				"    Probes bypass the egress qdisc (PACKET_QDISC_BYPASS)\n");
		else if (oi->pp)
			vty_out(vty,
				"    Probes use the IP stack, egress qdisc applies (%s)\n",
				reason ? reason : "unknown");
	}
	if (!json_iface)
		pktpair_show_session(vty, NULL, oi->pp, "    ");
}
