// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SAND v2 - interfaces, the protocol socket and heard links
 * (design doc section 5)
 */

#include <zebra.h>

#include "log.h"
#include "network.h"
#include "sockopt.h"

#include "sandd/sandd.h"

DEFINE_MTYPE_STATIC(SANDD, SAND_IF, "SAND interface");
DEFINE_MTYPE_STATIC(SANDD, SAND_NBR, "SAND heard link");
DEFINE_MTYPE_STATIC(SANDD, SAND_FQ, "SAND flood queue entry");

static struct sand_if *sand_ifs_by_idx[SAND_MAX_IFACES];

struct sand_if *sand_if_get(struct interface *ifp)
{
	return ifp->info;
}

struct sand_if *sand_if_by_idx(int idx)
{
	if (idx < 0 || idx >= SAND_MAX_IFACES)
		return NULL;
	return sand_ifs_by_idx[idx];
}

/* Number of SAND interface indexes in use: highest index + 1 */
int sand_if_count(void)
{
	int i, n = 0;

	for (i = 0; i < SAND_MAX_IFACES; i++)
		if (sand_ifs_by_idx[i])
			n = i + 1;
	return n;
}

static int sand_if_new_hook(struct interface *ifp)
{
	struct sand_if *sif = XCALLOC(MTYPE_SAND_IF, sizeof(*sif));

	sif->ifp = ifp;
	sif->idx = -1;
	sif->cost = SAND_DEFAULT_COST;
	sif->hello_interval = SAND_DEFAULT_HELLO;
	sif->hold_time = SAND_DEFAULT_HOLD;
	ifp->info = sif;
	return 0;
}

static int sand_if_delete_hook(struct interface *ifp)
{
	struct sand_if *sif = ifp->info;

	if (!sif)
		return 0;
	sand_if_stop(sif);
	if (sif->idx >= 0)
		sand_ifs_by_idx[sif->idx] = NULL;
	XFREE(MTYPE_SAND_IF, sif);
	ifp->info = NULL;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Socket                                                               */
/* ------------------------------------------------------------------ */

int sand_sock_open(void)
{
	struct sockaddr_in sin = {};
	int sock, on = 1, off = 0, ttl = 1;

	if (sand->sock >= 0)
		return 0;

	frr_with_privs (&sandd_privs) {
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock < 0) {
			zlog_err("SAND: socket: %s", safe_strerror(errno));
			return -1;
		}
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(sand->port);
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
		if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
			zlog_err("SAND: bind port %u: %s", sand->port,
				 safe_strerror(errno));
			close(sock);
			return -1;
		}
	}

	setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
	setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &off, sizeof(off));
	setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
	set_nonblocking(sock);
	setsockopt_so_recvbuf(sock, 1 << 20);

	sand->sock = sock;
	event_add_read(master, sand_pkt_read, NULL, sock, &sand->t_read);
	return 0;
}

void sand_sock_close(void)
{
	event_cancel(&sand->t_read);
	if (sand->sock >= 0)
		close(sand->sock);
	sand->sock = -1;
}

static void sand_if_group(struct sand_if *sif, bool join)
{
	struct ip_mreqn mreq = {};

	if (sand->sock < 0)
		return;
	mreq.imr_multiaddr = sand->group;
	mreq.imr_ifindex = sif->ifp->ifindex;
	if (setsockopt(sand->sock, IPPROTO_IP,
		       join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, &mreq,
		       sizeof(mreq)) < 0 &&
	    join)
		zlog_warn("SAND: join group on %s: %s", sif->ifp->name,
			  safe_strerror(errno));
}

/* ------------------------------------------------------------------ */
/* Timers                                                               */
/* ------------------------------------------------------------------ */

static long sand_jitter_msec(unsigned int secs, unsigned int pct)
{
	long base = (long)secs * 1000;
	long span = base * pct / 100;

	if (span <= 0)
		return base;
	return base - span + (frr_weak_random() % (2 * span + 1));
}

static void sand_if_hello_timer(struct event *t)
{
	struct sand_if *sif = EVENT_ARG(t);

	sand_send_hello(sif);
	event_add_timer_msec(master, sand_if_hello_timer, sif,
			     sand_jitter_msec(sif->hello_interval, 20),
			     &sif->t_hello);
}

static void sand_if_summary_timer(struct event *t)
{
	struct sand_if *sif = EVENT_ARG(t);

	sand_send_summary(sif);
	event_add_timer_msec(master, sand_if_summary_timer, sif,
			     sand_jitter_msec(sand->summary_interval, 20),
			     &sif->t_summary);
}

/* Send a Summary soon, at most once a second per interface (5.5, 8.3) */
void sand_if_trigger_summary(struct sand_if *sif)
{
	time_t now = monotime(NULL);

	if (!sif->running || sif->last_summary_trigger == now)
		return;
	sif->last_summary_trigger = now;
	event_cancel(&sif->t_summary);
	event_add_timer_msec(master, sand_if_summary_timer, sif, 100,
			     &sif->t_summary);
}

void sand_if_trigger_summary_all(void)
{
	int i;

	for (i = 0; i < SAND_MAX_IFACES; i++)
		if (sand_ifs_by_idx[i])
			sand_if_trigger_summary(sand_ifs_by_idx[i]);
}

/* ------------------------------------------------------------------ */
/* Heard links                                                          */
/* ------------------------------------------------------------------ */

uint16_t sand_nbr_metric(struct sand_nbr *n)
{
	uint64_t m;
	uint32_t ratio = n->ratio;

	if (ratio < SAND_RATIO_ONE / 100)
		ratio = SAND_RATIO_ONE / 100;
	m = (uint64_t)n->sif->cost * SAND_RATIO_ONE / ratio;
	if (m > SAND_METRIC_MAX)
		m = SAND_METRIC_MAX;
	if (m < 1)
		m = 1;
	return m;
}

static void sand_nbr_free(struct sand_if *sif, struct sand_nbr *n)
{
	struct sand_nbr **pp;

	for (pp = &sif->nbrs; *pp; pp = &(*pp)->next)
		if (*pp == n) {
			*pp = n->next;
			break;
		}
	event_cancel(&n->t_expire);
	XFREE(MTYPE_SAND_NBR, n);
}

static void sand_nbr_expire(struct event *t)
{
	struct sand_nbr *n = EVENT_ARG(t);
	struct sand_if *sif = n->sif;
	char buf[INET_ADDRSTRLEN];

	zlog_info("SAND: lost link %s/%u -> %s",
		  sand_rid2str(n->rid, buf, sizeof(buf)), n->ifidx,
		  sif->ifp->name);
	sand_nbr_free(sif, n);
	sand_schedule_orig();
}

static void sand_nbr_rearm(struct sand_nbr *n)
{
	uint16_t hold = n->hold ? n->hold : n->sif->hold_time;

	event_cancel(&n->t_expire);
	event_add_timer(master, sand_nbr_expire, n, hold, &n->t_expire);
}

static struct sand_nbr *sand_nbr_find(struct sand_if *sif, uint32_t rid,
				      uint16_t ifidx)
{
	struct sand_nbr *n;

	for (n = sif->nbrs; n; n = n->next)
		if (n->rid == rid && n->ifidx == ifidx)
			return n;
	return NULL;
}

void sand_if_heard(struct sand_if *sif, uint32_t rid, uint16_t ifidx,
		   uint32_t pkt_seq)
{
	struct sand_nbr *n = sand_nbr_find(sif, rid, ifidx);
	char buf[INET_ADDRSTRLEN];

	if (!n) {
		n = XCALLOC(MTYPE_SAND_NBR, sizeof(*n));
		n->rid = rid;
		n->ifidx = ifidx;
		n->sif = sif;
		n->ratio = SAND_RATIO_ONE;
		n->last_pkt_seq = pkt_seq;
		n->next = sif->nbrs;
		sif->nbrs = n;
		n->last_heard = monotime(NULL);
		n->adv_metric = sand_nbr_metric(n);
		zlog_info("SAND: new link %s/%u -> %s",
			  sand_rid2str(rid, buf, sizeof(buf)), ifidx,
			  sif->ifp->name);
		sand_nbr_rearm(n);
		sand_schedule_orig();
		return;
	}

	{
		uint32_t gap = pkt_seq - n->last_pkt_seq;

		if (gap >= 1 && gap < 0x10000) {
			uint32_t sample = SAND_RATIO_ONE / gap;

			n->ratio = n->ratio - n->ratio / 8 + sample / 8;
		}
		/* gap 0: duplicate; huge gap: sender restarted, skip */
		if (gap != 0)
			n->last_pkt_seq = pkt_seq;
	}
	n->last_heard = monotime(NULL);
	sand_nbr_rearm(n);

	{
		uint16_t m = sand_nbr_metric(n);
		uint32_t diff = m > n->adv_metric ? m - n->adv_metric
						  : n->adv_metric - m;

		if (diff * 100 >= (uint32_t)n->adv_metric *
					  SAND_METRIC_THRESH_PCT)
			sand_schedule_orig();
	}
}

void sand_if_hello_rx(struct sand_if *sif, uint32_t rid, uint16_t ifidx,
		      uint32_t boot_id, uint16_t hold_ds)
{
	struct sand_nbr *n = sand_nbr_find(sif, rid, ifidx);
	char buf[INET_ADDRSTRLEN];

	if (!n)
		return;
	if (n->boot_id && n->boot_id != boot_id) {
		zlog_info("SAND: %s restarted (boot id %u -> %u)",
			  sand_rid2str(rid, buf, sizeof(buf)), n->boot_id,
			  boot_id);
		n->ratio = SAND_RATIO_ONE;
		sand_if_trigger_summary_all();
	} else if (!n->boot_id) {
		/* First hello from a new link: help it sync quickly */
		sand_if_trigger_summary_all();
	}
	n->boot_id = boot_id;
	n->hold = (hold_ds + 9) / 10;
	if (n->hold < 3)
		n->hold = 3;
	sand_nbr_rearm(n);
}

/* ------------------------------------------------------------------ */
/* Bring interfaces up and down                                         */
/* ------------------------------------------------------------------ */

static void sand_if_addrs(struct sand_if *sif)
{
	struct connected *c;

	sif->ipv4.s_addr = 0;
	memset(&sif->ipv6ll, 0, sizeof(sif->ipv6ll));
	frr_each (if_connected, sif->ifp->connected, c) {
		struct prefix *p = c->address;

		if (p->family == AF_INET && !sif->ipv4.s_addr &&
		    !CHECK_FLAG(c->flags, ZEBRA_IFA_SECONDARY))
			sif->ipv4 = p->u.prefix4;
		else if (p->family == AF_INET6 &&
			 IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6) &&
			 IN6_IS_ADDR_UNSPECIFIED(&sif->ipv6ll))
			sif->ipv6ll = p->u.prefix6;
	}
}

static void sand_if_start(struct sand_if *sif)
{
	sif->running = true;
	sand_if_group(sif, true);
	zlog_info("SAND: interface %s up (index %d, %pI4)", sif->ifp->name,
		  sif->idx, &sif->ipv4);
	event_add_timer_msec(master, sand_if_hello_timer, sif,
			     frr_weak_random() % 500, &sif->t_hello);
	event_add_timer_msec(master, sand_if_summary_timer, sif,
			     2000 + frr_weak_random() % 1000, &sif->t_summary);
}

void sand_if_stop(struct sand_if *sif)
{
	struct sand_fq *q, *qn;

	if (!sif->running)
		return;
	zlog_info("SAND: interface %s down", sif->ifp->name);
	sif->running = false;
	sand_if_group(sif, false);
	event_cancel(&sif->t_hello);
	event_cancel(&sif->t_flood);
	event_cancel(&sif->t_summary);
	while (sif->nbrs)
		sand_nbr_free(sif, sif->nbrs);
	for (q = sif->fq_head; q; q = qn) {
		qn = q->next;
		XFREE(MTYPE_SAND_FQ, q);
	}
	sif->fq_head = sif->fq_tail = NULL;
}

/* Re-evaluate one interface after a config, state or address change */
void sand_if_update(struct interface *ifp)
{
	struct sand_if *sif = ifp->info;
	struct in_addr old4;
	struct in6_addr old6;
	bool want;

	if (!sif)
		return;

	/* index assignment follows configuration, not link state */
	if (sif->enabled && sif->idx < 0) {
		int i;

		for (i = 0; i < SAND_MAX_IFACES; i++)
			if (!sand_ifs_by_idx[i]) {
				sand_ifs_by_idx[i] = sif;
				sif->idx = i;
				break;
			}
	} else if (!sif->enabled && sif->idx >= 0) {
		sand_if_stop(sif);
		sand_ifs_by_idx[sif->idx] = NULL;
		sif->idx = -1;
	}

	old4 = sif->ipv4;
	old6 = sif->ipv6ll;
	sand_if_addrs(sif);

	want = sif->enabled && sif->idx >= 0 && sand && sand->running &&
	       if_is_operative(ifp) && sif->ipv4.s_addr;

	if (want && sif->running && old4.s_addr != sif->ipv4.s_addr) {
		/* primary address changed: rejoin with the new one */
		sand_if_stop(sif);
	}
	if (want && !sif->running)
		sand_if_start(sif);
	else if (!want && sif->running)
		sand_if_stop(sif);

	if (old4.s_addr != sif->ipv4.s_addr ||
	    memcmp(&old6, &sif->ipv6ll, sizeof(old6)))
		sand_schedule_orig();
	if (sif->enabled)
		sand_schedule_orig();
}

void sand_if_update_all(void)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;

	if (!vrf)
		return;
	FOR_ALL_INTERFACES (vrf, ifp)
		sand_if_update(ifp);
}

static int sand_ifp_change(struct interface *ifp)
{
	sand_if_update(ifp);
	return 0;
}

static int sand_ifp_destroy(struct interface *ifp)
{
	struct sand_if *sif = ifp->info;

	if (sif)
		sand_if_stop(sif);
	sand_schedule_orig();
	return 0;
}

int sand_if_config_write(struct vty *vty)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;
	int write = 0;

	if (!vrf)
		return 0;
	FOR_ALL_INTERFACES (vrf, ifp) {
		struct sand_if *sif = ifp->info;
		bool any;

		if (!sif)
			continue;
		any = sif->enabled || sif->cost != SAND_DEFAULT_COST ||
		      sif->hello_interval != SAND_DEFAULT_HELLO ||
		      sif->hold_time != SAND_DEFAULT_HOLD || ifp->desc;
		if (!any)
			continue;
		if_vty_config_start(vty, ifp);
		if (ifp->desc)
			vty_out(vty, " description %s\n", ifp->desc);
		if (sif->enabled)
			vty_out(vty, " sand\n");
		if (sif->cost != SAND_DEFAULT_COST)
			vty_out(vty, " sand cost %u\n", sif->cost);
		if (sif->hello_interval != SAND_DEFAULT_HELLO)
			vty_out(vty, " sand hello-interval %u\n",
				sif->hello_interval);
		if (sif->hold_time != SAND_DEFAULT_HOLD)
			vty_out(vty, " sand hold-time %u\n", sif->hold_time);
		if_vty_config_end(vty);
		write++;
	}
	return write;
}

/* ------------------------------------------------------------------ */
/* Flood queue storage helpers live here to share the MTYPE            */
/* ------------------------------------------------------------------ */

void sand_flood_queue(struct sand_if *sif, const struct sand_key *k)
{
	struct sand_fq *q;

	if (!sif->running)
		return;
	for (q = sif->fq_head; q; q = q->next)
		if (!sand_key_cmp(&q->key, k))
			return;
	q = XCALLOC(MTYPE_SAND_FQ, sizeof(*q));
	q->key = *k;
	if (sif->fq_tail)
		sif->fq_tail->next = q;
	else
		sif->fq_head = q;
	sif->fq_tail = q;
	if (!sif->t_flood)
		event_add_timer_msec(master, sand_flood_run, sif,
				     SAND_FLOOD_DELAY_MSEC, &sif->t_flood);
}

/* Pop the next queued key; returns false when empty */
bool sand_flood_pop(struct sand_if *sif, struct sand_key *k)
{
	struct sand_fq *q = sif->fq_head;

	if (!q)
		return false;
	*k = q->key;
	sif->fq_head = q->next;
	if (!sif->fq_head)
		sif->fq_tail = NULL;
	XFREE(MTYPE_SAND_FQ, q);
	return true;
}

void sand_if_init(void)
{
	hook_register_prio(if_add, 0, sand_if_new_hook);
	hook_register_prio(if_del, 0, sand_if_delete_hook);
	hook_register_prio(if_real, 0, sand_ifp_change);
	hook_register_prio(if_up, 0, sand_ifp_change);
	hook_register_prio(if_down, 0, sand_ifp_change);
	hook_register_prio(if_unreal, 0, sand_ifp_destroy);
}
