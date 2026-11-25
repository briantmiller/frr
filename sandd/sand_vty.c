// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SAND v2 - configuration and show commands
 */

#include <zebra.h>

#include "command.h"
#include "log.h"
#include "prefix.h"
#include "vrf.h"
#include "json.h"

#include "sandd/sandd.h"

static int sand_config_write(struct vty *vty);

static struct cmd_node sand_node = {
	.name = "sand",
	.node = SAND_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-router)# ",
	.config_write = sand_config_write,
};

static int sand_debug_write(struct vty *vty)
{
	static const struct {
		unsigned long f;
		const char *s;
	} names[] = { { SAND_DEBUG_PACKET, "packet" },
		      { SAND_DEBUG_FLOOD, "flood" },
		      { SAND_DEBUG_SPF, "spf" },
		      { SAND_DEBUG_ZEBRA, "zebra" },
		      { SAND_DEBUG_EVENTS, "events" } };
	unsigned int i;
	int n = 0;

	if (sand_debug == SAND_DEBUG_ALL) {
		vty_out(vty, "debug sand all\n");
		return 1;
	}
	for (i = 0; i < array_size(names); i++)
		if (sand_debug & names[i].f) {
			vty_out(vty, "debug sand %s\n", names[i].s);
			n++;
		}
	return n;
}

static int sand_config_write(struct vty *vty)
{
	struct sand_xpfx *x;
	afi_t afi;
	int t;

	sand_debug_write(vty);
	if (!sand->configured)
		return 0;

	vty_out(vty, "router sand\n");
	if (sand->rid_cfg.s_addr)
		vty_out(vty, " router-id %pI4\n", &sand->rid_cfg);
	if (sand->lifetime != SAND_DEFAULT_LIFETIME)
		vty_out(vty, " lifetime %u\n", sand->lifetime);
	if (sand->summary_interval != SAND_DEFAULT_SUMMARY)
		vty_out(vty, " summary-interval %u\n", sand->summary_interval);
	frr_each (sand_xpfx, &sand->xpfx, x) {
		if (!(x->src & SAND_XP_NETWORK))
			continue;
		if (x->metric)
			vty_out(vty, " network %pFX metric %u\n", &x->p,
				x->metric);
		else
			vty_out(vty, " network %pFX\n", &x->p);
	}
	for (afi = AFI_IP; afi <= AFI_IP6; afi++)
		for (t = 0; t < ZEBRA_ROUTE_MAX; t++)
			if (sand_redist_get(afi, t))
				vty_out(vty, " redistribute %s %s\n",
					afi == AFI_IP ? "ipv4" : "ipv6",
					zebra_route_string(t));
	if (sand->silent)
		vty_out(vty, " silent hold %u\n", sand->silent_hold);
	vty_out(vty, "exit\n!\n");
	return 1;
}

/* ------------------------------------------------------------------ */
/* router sand                                                          */
/* ------------------------------------------------------------------ */

DEFUN_NOSH (router_sand,
	    router_sand_cmd,
	    "router sand",
	    "Enable a routing process\n"
	    "SAND (unidirectional link routing)\n")
{
	if (!sand->configured) {
		sand->configured = true;
		sand_start();
	}
	VTY_PUSH_CONTEXT_NULL(SAND_NODE);
	return CMD_SUCCESS;
}

DEFUN (no_router_sand,
       no_router_sand_cmd,
       "no router sand",
       NO_STR
       "Disable a routing process\n"
       "SAND (unidirectional link routing)\n")
{
	sand_stop(true);
	sand->configured = false;
	return CMD_SUCCESS;
}

DEFUN (sand_router_id,
       sand_router_id_cmd,
       "[no] router-id [A.B.C.D]",
       NO_STR
       "Router ID for this router\n"
       "Router ID in IPv4 address form\n")
{
	struct in_addr a = {};

	if (strmatch(argv[0]->text, "no"))
		a.s_addr = 0;
	else if (argc < 2 || !inet_aton(argv[1]->arg, &a)) {
		vty_out(vty, "%% Malformed router-id\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	sand->rid_cfg = a;
	sand_rid_update();
	return CMD_SUCCESS;
}

DEFUN (sand_network,
       sand_network_cmd,
       "[no] network <A.B.C.D/M|X:X::X:X/M> [metric (0-65535)]",
       NO_STR
       "Advertise a prefix\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "Metric added to the path cost\n"
       "Metric value\n")
{
	bool no = strmatch(argv[0]->text, "no");
	int idx = no ? 2 : 1;
	struct prefix p;
	uint16_t metric = 0;

	if (!str2prefix(argv[idx]->arg, &p)) {
		vty_out(vty, "%% Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (argc > idx + 2)
		metric = strtoul(argv[idx + 2]->arg, NULL, 10);
	sand_network_set(&p, !no, metric);
	return CMD_SUCCESS;
}

DEFUN (sand_redistribute,
       sand_redistribute_cmd,
       "[no] redistribute <ipv4|ipv6> <connected|static|kernel>",
       NO_STR
       "Advertise routes from another source\n"
       "IPv4 routes\n"
       "IPv6 routes\n"
       "Connected routes\n"
       "Static routes\n"
       "Kernel routes\n")
{
	bool no = strmatch(argv[0]->text, "no");
	int idx = no ? 2 : 1;
	afi_t afi = strmatch(argv[idx]->text, "ipv4") ? AFI_IP : AFI_IP6;
	int type = proto_redistnum(afi, argv[idx + 1]->text);

	if (type < 0)
		return CMD_WARNING_CONFIG_FAILED;
	sand_zebra_redistribute(afi, type, !no);
	return CMD_SUCCESS;
}

DEFUN (sand_lifetime,
       sand_lifetime_cmd,
       "lifetime (300-65535)",
       "Record lifetime\n"
       "Seconds\n")
{
	sand->lifetime = strtoul(argv[1]->arg, NULL, 10);
	return CMD_SUCCESS;
}

DEFUN (no_sand_lifetime,
       no_sand_lifetime_cmd,
       "no lifetime [(300-65535)]",
       NO_STR
       "Record lifetime\n"
       "Seconds\n")
{
	sand->lifetime = SAND_DEFAULT_LIFETIME;
	return CMD_SUCCESS;
}

DEFUN (sand_summary_interval,
       sand_summary_interval_cmd,
       "summary-interval (5-6553)",
       "Interval between database summaries\n"
       "Seconds\n")
{
	sand->summary_interval = strtoul(argv[1]->arg, NULL, 10);
	return CMD_SUCCESS;
}

DEFUN (no_sand_summary_interval,
       no_sand_summary_interval_cmd,
       "no summary-interval [(5-6553)]",
       NO_STR
       "Interval between database summaries\n"
       "Seconds\n")
{
	sand->summary_interval = SAND_DEFAULT_SUMMARY;
	return CMD_SUCCESS;
}

DEFUN (sand_silent,
       sand_silent_cmd,
       "silent [hold (60-65535)]",
       "Stop transmitting (emissions control); others keep routes to us\n"
       "How long others keep our records\n"
       "Seconds\n")
{
	uint16_t hold = argc > 2 ? strtoul(argv[2]->arg, NULL, 10) : 3600;

	sand_set_silent(true, hold);
	return CMD_SUCCESS;
}

DEFUN (no_sand_silent,
       no_sand_silent_cmd,
       "no silent [hold (60-65535)]",
       NO_STR
       "Resume transmitting\n"
       "How long others keep our records\n"
       "Seconds\n")
{
	sand_set_silent(false, sand->silent_hold);
	return CMD_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* interface                                                            */
/* ------------------------------------------------------------------ */

DEFUN (sand_if_enable,
       sand_if_enable_cmd,
       "[no] sand",
       NO_STR
       "Run SAND on this interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct sand_if *sif = ifp->info;

	sif->enabled = !strmatch(argv[0]->text, "no");
	sand_if_update(ifp);
	sand_schedule_orig();
	return CMD_SUCCESS;
}

DEFUN (sand_if_cost,
       sand_if_cost_cmd,
       "sand cost (1-65535)",
       "SAND interface settings\n"
       "Cost of links heard on this interface\n"
       "Cost\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct sand_if *sif = ifp->info;

	sif->cost = strtoul(argv[2]->arg, NULL, 10);
	sand_schedule_orig();
	return CMD_SUCCESS;
}

DEFUN (no_sand_if_cost,
       no_sand_if_cost_cmd,
       "no sand cost [(1-65535)]",
       NO_STR
       "SAND interface settings\n"
       "Cost of links heard on this interface\n"
       "Cost\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct sand_if *sif = ifp->info;

	sif->cost = SAND_DEFAULT_COST;
	sand_schedule_orig();
	return CMD_SUCCESS;
}

DEFUN (sand_if_hello,
       sand_if_hello_cmd,
       "sand hello-interval (1-6553)",
       "SAND interface settings\n"
       "Interval between hellos\n"
       "Seconds\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct sand_if *sif = ifp->info;

	sif->hello_interval = strtoul(argv[2]->arg, NULL, 10);
	return CMD_SUCCESS;
}

DEFUN (no_sand_if_hello,
       no_sand_if_hello_cmd,
       "no sand hello-interval [(1-6553)]",
       NO_STR
       "SAND interface settings\n"
       "Interval between hellos\n"
       "Seconds\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct sand_if *sif = ifp->info;

	sif->hello_interval = SAND_DEFAULT_HELLO;
	return CMD_SUCCESS;
}

DEFUN (sand_if_hold,
       sand_if_hold_cmd,
       "sand hold-time (3-6553)",
       "SAND interface settings\n"
       "Time without packets before a heard link is dropped\n"
       "Seconds\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct sand_if *sif = ifp->info;

	sif->hold_time = strtoul(argv[2]->arg, NULL, 10);
	return CMD_SUCCESS;
}

DEFUN (no_sand_if_hold,
       no_sand_if_hold_cmd,
       "no sand hold-time [(3-6553)]",
       NO_STR
       "SAND interface settings\n"
       "Time without packets before a heard link is dropped\n"
       "Seconds\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct sand_if *sif = ifp->info;

	sif->hold_time = SAND_DEFAULT_HOLD;
	return CMD_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* show                                                                 */
/* ------------------------------------------------------------------ */

#define SAND_STR "SAND information\n"

DEFUN (show_sand,
       show_sand_cmd,
       "show sand [json]",
       SHOW_STR
       SAND_STR
       JSON_STR)
{
	char buf[INET_ADDRSTRLEN];
	struct sand_rec *r;
	unsigned int own = 0, total = 0;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	frr_each (sand_lsdb, &sand->lsdb, r) {
		if (r->placeholder)
			continue;
		total++;
		if (r->key.orig == sand->rid)
			own++;
	}

	if (uj) {
		json = json_object_new_object();
		json_object_boolean_add(json, "configured", sand->configured);
		json_object_boolean_add(json, "running", sand->running);
		if (sand->running) {
			json_object_string_add(json, "routerId",
					       sand_rid2str(sand->rid, buf,
							    sizeof(buf)));
			json_object_int_add(json, "bootId", sand->boot_id);
			json_object_boolean_add(json, "silent", sand->silent);
			json_object_int_add(json, "records", total);
			json_object_int_add(json, "ownRecords", own);
			json_object_string_addf(json, "digest", "%08x",
						sand_lsdb_digest());
			json_object_int_add(json, "routes",
					    sand_rt_count(&sand->routes));
			json_object_int_add(json, "spfRuns", sand->spf_runs);
			json_object_int_add(json, "originations",
					    sand->originations);
			json_object_int_add(json, "lifetime", sand->lifetime);
			json_object_int_add(json, "summaryInterval",
					    sand->summary_interval);
		}
		return vty_json(vty, json);
	}

	if (!sand->running) {
		vty_out(vty, "SAND is %s\n",
			sand->configured ? "waiting for a router-id"
					 : "not configured");
		return CMD_SUCCESS;
	}
	vty_out(vty, "SAND v2, router-id %s, boot id %u%s\n",
		sand_rid2str(sand->rid, buf, sizeof(buf)), sand->boot_id,
		sand->silent ? ", SILENT" : "");
	vty_out(vty, "  Records: %u (%u own), digest %08x\n", total, own,
		sand_lsdb_digest());
	vty_out(vty, "  Routes installed: %zu, route computations: %" PRIu64 "\n",
		sand_rt_count(&sand->routes), sand->spf_runs);
	vty_out(vty, "  Originations: %" PRIu64 ", lifetime %u s, summary every %u s\n",
		sand->originations, sand->lifetime, sand->summary_interval);
	vty_out(vty, "  Sent: hello %" PRIu64 "/%" PRIu64 ", update %" PRIu64 "/%" PRIu64
		", summary %" PRIu64 "/%" PRIu64 ", request %" PRIu64 "/%" PRIu64 " (packets/bytes)\n",
		sand->tx_type_pkts[1], sand->tx_type_bytes[1],
		sand->tx_type_pkts[2], sand->tx_type_bytes[2],
		sand->tx_type_pkts[3], sand->tx_type_bytes[3],
		sand->tx_type_pkts[4], sand->tx_type_bytes[4]);
	return CMD_SUCCESS;
}

DEFUN (show_sand_interface,
       show_sand_interface_cmd,
       "show sand interface [json]",
       SHOW_STR
       SAND_STR
       "Interfaces\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	json_object *json = NULL, *jifs = NULL;
	int i;

	if (uj) {
		json = json_object_new_object();
		jifs = json_object_new_object();
		json_object_object_add(json, "interfaces", jifs);
	} else
		vty_out(vty, "%-16s %3s %-5s %-15s %5s %5s %8s %10s %8s %10s\n",
			"Interface", "Idx", "State", "IPv4", "Cost", "Hello",
			"Tx pkts", "Tx bytes", "Rx pkts", "Rx bytes");
	for (i = 0; i < SAND_MAX_IFACES; i++) {
		struct sand_if *sif = sand_if_by_idx(i);

		if (!sif)
			continue;
		if (uj) {
			json_object *j = json_object_new_object();

			json_object_int_add(j, "index", sif->idx);
			json_object_string_add(j, "state",
					       sif->running ? "up" : "down");
			json_object_string_addf(j, "ipv4", "%pI4", &sif->ipv4);
			json_object_int_add(j, "cost", sif->cost);
			json_object_int_add(j, "helloInterval",
					    sif->hello_interval);
			json_object_int_add(j, "holdTime", sif->hold_time);
			json_object_int_add(j, "listeners",
					    sif->n_listeners == 0xff
						    ? SAND_MAX_ECMP + 1
						    : sif->n_listeners);
			json_object_int_add(j, "txPackets", sif->tx_pkts);
			json_object_int_add(j, "txBytes", sif->tx_bytes);
			json_object_int_add(j, "rxPackets", sif->rx_pkts);
			json_object_int_add(j, "rxBytes", sif->rx_bytes);
			json_object_object_add(jifs, sif->ifp->name, j);
			continue;
		}
		vty_out(vty, "%-16s %3d %-5s %-15pI4 %5u %5u %8" PRIu64 " %10" PRIu64 " %8" PRIu64 " %10" PRIu64 "\n",
			sif->ifp->name, sif->idx,
			sif->running ? "up" : "down", &sif->ipv4, sif->cost,
			sif->hello_interval, sif->tx_pkts, sif->tx_bytes,
			sif->rx_pkts, sif->rx_bytes);
	}
	if (uj)
		return vty_json(vty, json);
	return CMD_SUCCESS;
}

DEFUN (show_sand_neighbor,
       show_sand_neighbor_cmd,
       "show sand neighbor [json]",
       SHOW_STR
       SAND_STR
       "Links this router hears\n"
       JSON_STR)
{
	char buf[INET_ADDRSTRLEN];
	time_t now = monotime(NULL);
	bool uj = use_json(argc, argv);
	json_object *json = NULL, *jlinks = NULL;
	int i;

	if (uj) {
		json = json_object_new_object();
		jlinks = json_object_new_array();
		json_object_object_add(json, "links", jlinks);
	} else {
		vty_out(vty, "Links heard (sender -> local interface):\n");
		vty_out(vty, "%-15s %6s  %-16s %8s %7s %6s %10s\n", "Sender",
			"If", "Local interface", "Deliver%", "Metric", "Age",
			"Boot id");
	}
	for (i = 0; i < SAND_MAX_IFACES; i++) {
		struct sand_if *sif = sand_if_by_idx(i);
		struct sand_nbr *n;

		if (!sif)
			continue;
		for (n = sif->nbrs; n; n = n->next) {
			unsigned int pct = (uint64_t)n->ratio * 100 /
					   SAND_RATIO_ONE;

			sand_rid2str(n->rid, buf, sizeof(buf));
			if (uj) {
				json_object *j = json_object_new_object();

				json_object_string_add(j, "sender", buf);
				json_object_int_add(j, "senderInterface",
						    n->ifidx);
				json_object_string_add(j, "interface",
						       sif->ifp->name);
				json_object_int_add(j, "deliveryPercent", pct);
				json_object_int_add(j, "metric",
						    sand_nbr_metric(n));
				json_object_int_add(j, "ageSeconds",
						    now - n->last_heard);
				json_object_int_add(j, "bootId", n->boot_id);
				json_object_array_add(jlinks, j);
				continue;
			}
			vty_out(vty, "%-15s %6u  %-16s %7u%% %7u %5lds %10u\n",
				buf, n->ifidx, sif->ifp->name, pct,
				sand_nbr_metric(n), (long)(now - n->last_heard),
				n->boot_id);
		}
	}
	if (uj)
		return vty_json(vty, json);
	return CMD_SUCCESS;
}

static void sand_show_rec_body(struct vty *vty, struct sand_rec *r)
{
	const uint8_t *p = r->data + SAND_REC_HDR_LEN, *end = r->data + r->len;
	char buf[INET_ADDRSTRLEN];

	switch (r->key.type) {
	case SAND_REC_ROUTER:
		if (end - p < 4)
			return;
		vty_out(vty, "    interfaces: %u\n", sand_get16(p));
		for (p += 4; p + SAND_RTR_ENTRY_LEN <= end;
		     p += SAND_RTR_ENTRY_LEN)
			vty_out(vty, "    hears %s/%u on %u, metric %u, %u%%\n",
				sand_rid2str(sand_get32(p + 2), buf, sizeof(buf)),
				sand_get16(p + 6), sand_get16(p),
				sand_get16(p + 8), p[10]);
		break;
	case SAND_REC_IFACE:
		while (end - p >= 4) {
			uint8_t hl = p[3];
			struct in_addr v4;
			struct in6_addr v6;
			char mac[64] = "";
			int j;

			if (end - p < 24 + hl)
				break;
			for (j = 0; j < hl && j < 20; j++)
				snprintf(mac + strlen(mac),
					 sizeof(mac) - strlen(mac), "%s%02x",
					 j ? ":" : "", p[4 + j]);
			memcpy(&v4, p + 4 + hl, 4);
			memcpy(&v6, p + 8 + hl, 16);
			vty_out(vty, "    if %u %s mac %s %pI4 %pI6\n",
				sand_get16(p), (p[2] & 1) ? "up" : "down", mac,
				&v4, &v6);
			p += 24 + hl;
		}
		break;
	case SAND_REC_PFX4:
	case SAND_REC_PFX6:
		while (end - p >= 4) {
			struct prefix pfx = {};
			unsigned int nb = (p[3] + 7) / 8;

			if (end - p < 4 + (int)nb)
				break;
			pfx.family = r->key.type == SAND_REC_PFX4 ? AF_INET
								  : AF_INET6;
			pfx.prefixlen = p[3];
			memcpy(&pfx.u.prefix, p + 4, nb);
			vty_out(vty, "    %pFX metric %u\n", &pfx,
				sand_get16(p));
			p += 4 + nb;
		}
		break;
	}
}

/* JSON body: the parts tests and tools look at */
static void sand_json_rec_body(json_object *j, struct sand_rec *r)
{
	const uint8_t *p = r->data + SAND_REC_HDR_LEN, *end = r->data + r->len;
	char buf[INET_ADDRSTRLEN];
	json_object *a = json_object_new_array();

	switch (r->key.type) {
	case SAND_REC_ROUTER:
		if (end - p >= 4) {
			json_object_int_add(j, "interfaceCount", sand_get16(p));
			for (p += 4; p + SAND_RTR_ENTRY_LEN <= end;
			     p += SAND_RTR_ENTRY_LEN) {
				json_object *e = json_object_new_object();

				json_object_int_add(e, "localInterface",
						    sand_get16(p));
				json_object_string_add(e, "sender",
						       sand_rid2str(sand_get32(p + 2),
								    buf,
								    sizeof(buf)));
				json_object_int_add(e, "senderInterface",
						    sand_get16(p + 6));
				json_object_int_add(e, "metric",
						    sand_get16(p + 8));
				json_object_array_add(a, e);
			}
		}
		json_object_object_add(j, "hears", a);
		return;
	case SAND_REC_PFX4:
	case SAND_REC_PFX6:
		while (end - p >= 4) {
			struct prefix pfx = {};
			unsigned int nb = (p[3] + 7) / 8;

			if (end - p < 4 + (int)nb)
				break;
			pfx.family = r->key.type == SAND_REC_PFX4 ? AF_INET
								  : AF_INET6;
			pfx.prefixlen = p[3];
			memcpy(&pfx.u.prefix, p + 4, nb);
			json_array_string_addf(a, "%pFX", &pfx);
			p += 4 + nb;
		}
		json_object_object_add(j, "prefixes", a);
		return;
	}
	json_object_free(a);
}

DEFUN (show_sand_database,
       show_sand_database_cmd,
       "show sand database [detail] [json]",
       SHOW_STR
       SAND_STR
       "Record database\n"
       "Show record contents\n"
       JSON_STR)
{
	int idx = 0;
	bool detail = argv_find(argv, argc, "detail", &idx);
	bool uj = use_json(argc, argv);
	json_object *json = NULL, *jrecs = NULL;
	struct sand_rec *r;
	char buf[INET_ADDRSTRLEN];

	if (uj) {
		json = json_object_new_object();
		jrecs = json_object_new_array();
		json_object_object_add(json, "records", jrecs);
	} else
		vty_out(vty, "%-15s %-12s %4s %10s %6s %6s %5s %s\n",
			"Originator", "Type", "Frag", "Seq", "Life", "Cksum",
			"Len", "Flags");
	frr_each (sand_lsdb, &sand->lsdb, r) {
		if (r->placeholder)
			continue;
		sand_rid2str(r->key.orig, buf, sizeof(buf));
		if (uj) {
			json_object *j = json_object_new_object();

			json_object_string_add(j, "originator", buf);
			json_object_string_add(j, "type",
					       sand_rec_type2str(r->key.type));
			json_object_int_add(j, "fragment", r->key.frag);
			json_object_int_add(j, "sequence", r->seq);
			json_object_int_add(j, "lifetime",
					    sand_rec_remaining(r));
			json_object_string_addf(j, "checksum", "%04x",
						r->cksum);
			json_object_int_add(j, "length", r->len);
			json_object_boolean_add(j, "purged", r->purge);
			json_object_boolean_add(j, "expired",
						r->expired_at && !r->purge);
			json_object_boolean_add(j, "silent",
						CHECK_FLAG(r->flags,
							   SAND_RFLAG_SILENT));
			if (detail && !r->purge)
				sand_json_rec_body(j, r);
			json_object_array_add(jrecs, j);
			continue;
		}
		vty_out(vty, "%-15s %-12s %4u %10u %6u  %04x %5u %s%s%s\n",
			buf, sand_rec_type2str(r->key.type), r->key.frag,
			r->seq, sand_rec_remaining(r), r->cksum, r->len,
			r->purge ? "purged " : "",
			r->expired_at && !r->purge ? "expired " : "",
			CHECK_FLAG(r->flags, SAND_RFLAG_SILENT) ? "silent" : "");
		if (detail && !r->purge)
			sand_show_rec_body(vty, r);
	}
	if (uj)
		return vty_json(vty, json);
	return CMD_SUCCESS;
}

DEFUN (show_sand_topology,
       show_sand_topology_cmd,
       "show sand topology [json]",
       SHOW_STR
       SAND_STR
       "Result of the last route computation\n"
       JSON_STR)
{
	char buf[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];
	bool uj = use_json(argc, argv);
	json_object *json = NULL, *jr = NULL;
	size_t i;
	uint8_t j;

	if (uj) {
		json = json_object_new_object();
		jr = json_object_new_object();
		json_object_object_add(json, "routers", jr);
	} else
		vty_out(vty, "%-15s %-5s %-6s %8s  %s\n", "Router", "Live",
			"Silent", "Cost", "First hops (local if -> neighbor/if)");
	for (i = 0; i < sand->spf_n; i++) {
		struct sand_spf_node *n = &sand->spf[i];

		sand_rid2str(n->rid, buf, sizeof(buf));
		if (uj) {
			json_object *jn = json_object_new_object();
			json_object *jh = json_object_new_array();

			json_object_boolean_add(jn, "live", n->live);
			json_object_boolean_add(jn, "silent", n->silent);
			json_object_boolean_add(jn, "reachable",
						n->cost != UINT32_MAX);
			if (n->cost != UINT32_MAX)
				json_object_int_add(jn, "cost", n->cost);
			for (j = 0; j < n->n_nh; j++) {
				struct sand_if *sif =
					sand_if_by_idx(n->nh[j].local_if);
				json_object *h = json_object_new_object();

				json_object_string_add(h, "interface",
						       sif ? sif->ifp->name
							   : "?");
				json_object_string_add(h, "neighbor",
						       sand_rid2str(n->nh[j].nbr,
								    buf2,
								    sizeof(buf2)));
				json_object_int_add(h, "neighborInterface",
						    n->nh[j].nbr_if);
				json_object_array_add(jh, h);
			}
			json_object_object_add(jn, "firstHops", jh);
			json_object_object_add(jr, buf, jn);
			continue;
		}
		vty_out(vty, "%-15s %-5s %-6s ", buf, n->live ? "yes" : "no",
			n->silent ? "yes" : "no");
		if (n->cost == UINT32_MAX)
			vty_out(vty, "%8s ", "-");
		else
			vty_out(vty, "%8u ", n->cost);
		for (j = 0; j < n->n_nh; j++) {
			struct sand_if *sif = sand_if_by_idx(n->nh[j].local_if);

			vty_out(vty, " %s->%s/%u",
				sif ? sif->ifp->name : "?",
				sand_rid2str(n->nh[j].nbr, buf2, sizeof(buf2)),
				n->nh[j].nbr_if);
		}
		vty_out(vty, "\n");
	}
	if (uj)
		return vty_json(vty, json);
	return CMD_SUCCESS;
}

DEFUN (show_sand_route,
       show_sand_route_cmd,
       "show sand route [json]",
       SHOW_STR
       SAND_STR
       "Routes computed by SAND\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	json_object *json = NULL;
	struct sand_route *rt;
	char pbuf[PREFIX_STRLEN];
	uint8_t i;

	if (uj)
		json = json_object_new_object();
	frr_each (sand_rt, &sand->routes, rt) {
		json_object *jrt = NULL, *jnh = NULL;

		if (uj) {
			jrt = json_object_new_object();
			jnh = json_object_new_array();
			json_object_int_add(jrt, "cost", rt->cost);
			json_object_object_add(jrt, "nexthops", jnh);
			prefix2str(&rt->p, pbuf, sizeof(pbuf));
			json_object_object_add(json, pbuf, jrt);
		} else
			vty_out(vty, "%-24pFX cost %u\n", &rt->p, rt->cost);
		for (i = 0; i < rt->n_nh; i++) {
			struct interface *ifp =
				if_lookup_by_index(rt->nh[i].ifindex,
						   VRF_DEFAULT);
			const char *ifn = ifp ? ifp->name : "?";

			if (uj) {
				json_object *h = json_object_new_object();

				if (rt->p.family == AF_INET)
					json_object_string_addf(h, "ip", "%pI4",
								&rt->nh[i].gate.ipv4);
				else
					json_object_string_addf(h, "ip", "%pI6",
								&rt->nh[i].gate.ipv6);
				json_object_string_add(h, "interface", ifn);
				json_object_array_add(jnh, h);
			} else if (rt->p.family == AF_INET)
				vty_out(vty, "    via %pI4 dev %s onlink\n",
					&rt->nh[i].gate.ipv4, ifn);
			else
				vty_out(vty, "    via %pI6 dev %s onlink\n",
					&rt->nh[i].gate.ipv6, ifn);
		}
	}
	if (uj)
		return vty_json(vty, json);
	return CMD_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* debug                                                                */
/* ------------------------------------------------------------------ */

DEFUN (debug_sand,
       debug_sand_cmd,
       "[no] debug sand <packet|flood|spf|zebra|events|all>",
       NO_STR
       DEBUG_STR
       "SAND\n"
       "Packets sent and received\n"
       "Flooding, summaries and requests\n"
       "Route computation\n"
       "Route and neighbor installation\n"
       "Events\n"
       "Everything\n")
{
	bool no = strmatch(argv[0]->text, "no");
	const char *w = argv[argc - 1]->text;
	unsigned long f = 0;

	if (strmatch(w, "packet"))
		f = SAND_DEBUG_PACKET;
	else if (strmatch(w, "flood"))
		f = SAND_DEBUG_FLOOD;
	else if (strmatch(w, "spf"))
		f = SAND_DEBUG_SPF;
	else if (strmatch(w, "zebra"))
		f = SAND_DEBUG_ZEBRA;
	else if (strmatch(w, "events"))
		f = SAND_DEBUG_EVENTS;
	else
		f = SAND_DEBUG_ALL;
	if (no)
		sand_debug &= ~f;
	else
		sand_debug |= f;
	return CMD_SUCCESS;
}

DEFUN_NOSH (show_debugging_sand,
	    show_debugging_sand_cmd,
	    "show debugging [sand]",
	    SHOW_STR
	    DEBUG_STR
	    "SAND\n")
{
	vty_out(vty, "SAND debugging status:\n");
	sand_debug_write(vty);
	cmd_show_lib_debugs(vty);
	return CMD_SUCCESS;
}

void sand_vty_init(void)
{
	install_node(&sand_node);
	install_default(SAND_NODE);

	install_element(CONFIG_NODE, &router_sand_cmd);
	install_element(CONFIG_NODE, &no_router_sand_cmd);
	install_element(SAND_NODE, &sand_router_id_cmd);
	install_element(SAND_NODE, &sand_network_cmd);
	install_element(SAND_NODE, &sand_redistribute_cmd);
	install_element(SAND_NODE, &sand_lifetime_cmd);
	install_element(SAND_NODE, &no_sand_lifetime_cmd);
	install_element(SAND_NODE, &sand_summary_interval_cmd);
	install_element(SAND_NODE, &no_sand_summary_interval_cmd);
	install_element(SAND_NODE, &sand_silent_cmd);
	install_element(SAND_NODE, &no_sand_silent_cmd);

	if_cmd_init(sand_if_config_write);
	install_element(INTERFACE_NODE, &sand_if_enable_cmd);
	install_element(INTERFACE_NODE, &sand_if_cost_cmd);
	install_element(INTERFACE_NODE, &no_sand_if_cost_cmd);
	install_element(INTERFACE_NODE, &sand_if_hello_cmd);
	install_element(INTERFACE_NODE, &no_sand_if_hello_cmd);
	install_element(INTERFACE_NODE, &sand_if_hold_cmd);
	install_element(INTERFACE_NODE, &no_sand_if_hold_cmd);

	install_element(VIEW_NODE, &show_sand_cmd);
	install_element(VIEW_NODE, &show_sand_interface_cmd);
	install_element(VIEW_NODE, &show_sand_neighbor_cmd);
	install_element(VIEW_NODE, &show_sand_database_cmd);
	install_element(VIEW_NODE, &show_sand_topology_cmd);
	install_element(VIEW_NODE, &show_sand_route_cmd);
	install_element(ENABLE_NODE, &show_debugging_sand_cmd);
	install_element(ENABLE_NODE, &debug_sand_cmd);
	install_element(CONFIG_NODE, &debug_sand_cmd);

	vrf_cmd_init(NULL);
}
