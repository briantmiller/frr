// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SAND v2 - route computation on the directed graph
 * (design doc sections 9.2 and 11)
 */

#include <zebra.h>

#include "log.h"

#include "sandd/sandd.h"

DEFINE_MTYPE_STATIC(SANDD, SAND_SPF, "SAND SPF data");
DEFINE_MTYPE_STATIC(SANDD, SAND_ROUTE, "SAND route");
DEFINE_MTYPE_STATIC(SANDD, SAND_NEIGH, "SAND neighbor entry");

int sand_route_cmp(const struct sand_route *a, const struct sand_route *b)
{
	return prefix_cmp(&a->p, &b->p);
}

struct sand_edge {
	uint32_t from, to; /* node indexes */
	uint16_t from_if, to_if;
	uint16_t metric;
};

/* ------------------------------------------------------------------ */
/* Helpers over the LSDB                                                */
/* ------------------------------------------------------------------ */

/* Walk the usable records of one originator and type */
#define FOREACH_REC_OF(r, rid, rtype)                                          \
	for (struct sand_rec ref_##r =                                         \
		     { .key = { .orig = (rid), .type = (rtype), .frag = 0 } }, \
	     *r = sand_lsdb_find_gteq(&sand->lsdb, &ref_##r);                 \
	     r && r->key.orig == (rid) && r->key.type == (rtype);              \
	     r = sand_lsdb_next(&sand->lsdb, r))

int sand_rtr_hears(uint32_t listener, uint32_t sender, int16_t *sender_ifs,
		   int max)
{
	int n = 0;

	FOREACH_REC_OF (r, listener, SAND_REC_ROUTER) {
		const uint8_t *p, *end;

		if (!sand_rec_usable(r) || r->len < SAND_REC_HDR_LEN + 4)
			continue;
		end = r->data + r->len;
		for (p = r->data + SAND_REC_HDR_LEN + 4;
		     p + SAND_RTR_ENTRY_LEN <= end; p += SAND_RTR_ENTRY_LEN) {
			int16_t sif = sand_get16(p + 6);
			int i;
			bool dup = false;

			if (sand_get32(p + 2) != sender)
				continue;
			for (i = 0; i < n; i++)
				if (sender_ifs[i] == sif)
					dup = true;
			if (!dup && n < max)
				sender_ifs[n++] = sif;
		}
	}
	return n;
}

/* Find (rid, ifidx) in rid's Interface records */
static bool sand_iface_lookup(uint32_t rid, uint16_t ifidx,
			      struct in_addr *v4, struct in6_addr *v6,
			      uint8_t *mac, uint8_t *maclen)
{
	FOREACH_REC_OF (r, rid, SAND_REC_IFACE) {
		const uint8_t *p, *end;

		if (!sand_rec_usable(r))
			continue;
		end = r->data + r->len;
		p = r->data + SAND_REC_HDR_LEN;
		while (end - p >= 4) {
			uint8_t hl = p[3];

			if (end - p < 24 + hl)
				break;
			if (sand_get16(p) == ifidx) {
				*maclen = hl;
				memcpy(mac, p + 4, hl);
				memcpy(v4, p + 4 + hl, 4);
				memcpy(v6, p + 8 + hl, 16);
				return true;
			}
			p += 24 + hl;
		}
	}
	return false;
}

/* ------------------------------------------------------------------ */
/* Graph and Dijkstra                                                   */
/* ------------------------------------------------------------------ */

static int u32_cmp(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

static int node_cmp(const void *a, const void *b)
{
	const struct sand_spf_node *x = a, *y = b;

	return x->rid < y->rid ? -1 : x->rid > y->rid;
}

static long node_index(struct sand_spf_node *nodes, size_t n, uint32_t rid)
{
	struct sand_spf_node key = { .rid = rid }, *f;

	f = bsearch(&key, nodes, n, sizeof(*nodes), node_cmp);
	return f ? f - nodes : -1;
}

struct sand_spf_node *sand_spf_lookup(uint32_t rid)
{
	long i;

	if (!sand->spf)
		return NULL;
	i = node_index(sand->spf, sand->spf_n, rid);
	return i < 0 ? NULL : &sand->spf[i];
}

static int edge_from_cmp(const void *a, const void *b)
{
	const struct sand_edge *x = a, *y = b;

	return x->from < y->from ? -1 : x->from > y->from;
}

static void nh_merge(struct sand_spf_node *dst, const struct sand_nh *nh,
		     uint8_t n)
{
	uint8_t i, j;

	for (i = 0; i < n && dst->n_nh < SAND_MAX_ECMP; i++) {
		bool dup = false;

		for (j = 0; j < dst->n_nh; j++)
			if (dst->nh[j].local_if == nh[i].local_if &&
			    dst->nh[j].nbr == nh[i].nbr &&
			    dst->nh[j].nbr_if == nh[i].nbr_if)
				dup = true;
		if (!dup)
			dst->nh[dst->n_nh++] = nh[i];
	}
}

static void sand_spf_compute(void)
{
	struct sand_rec *r;
	uint32_t *rids = NULL;
	size_t nr = 0, cap = 0, i, ne = 0, ecap = 0;
	struct sand_spf_node *nodes;
	struct sand_edge *edges = NULL;
	size_t *estart;
	long self;
	bool changed;

	/* 1. Vertices: us, plus every originator and sender we know of */
#define ADD_RID(x)                                                             \
	do {                                                                   \
		if (nr == cap) {                                               \
			cap = cap ? cap * 2 : 64;                              \
			rids = XREALLOC(MTYPE_SAND_SPF, rids,                  \
					cap * sizeof(*rids));                  \
		}                                                              \
		rids[nr++] = (x);                                              \
	} while (0)

	ADD_RID(sand->rid);
	frr_each (sand_lsdb, &sand->lsdb, r) {
		const uint8_t *p, *end;

		if (!sand_rec_usable(r))
			continue;
		ADD_RID(r->key.orig);
		if (r->key.type != SAND_REC_ROUTER ||
		    r->len < SAND_REC_HDR_LEN + 4)
			continue;
		end = r->data + r->len;
		for (p = r->data + SAND_REC_HDR_LEN + 4;
		     p + SAND_RTR_ENTRY_LEN <= end; p += SAND_RTR_ENTRY_LEN)
			ADD_RID(sand_get32(p + 2));
	}
	qsort(rids, nr, sizeof(*rids), u32_cmp);
	{
		size_t w = 0;

		for (i = 0; i < nr; i++)
			if (!w || rids[w - 1] != rids[i])
				rids[w++] = rids[i];
		nr = w;
	}

	nodes = XCALLOC(MTYPE_SAND_SPF, nr * sizeof(*nodes));
	for (i = 0; i < nr; i++) {
		nodes[i].rid = rids[i];
		nodes[i].cost = UINT32_MAX;
	}
	XFREE(MTYPE_SAND_SPF, rids);
	self = node_index(nodes, nr, sand->rid);

	/* 2. Edges: each Router record entry is a link its originator hears */
	frr_each (sand_lsdb, &sand->lsdb, r) {
		const uint8_t *p, *end;
		long to;

		if (!sand_rec_usable(r))
			continue;
		to = node_index(nodes, nr, r->key.orig);
		if (CHECK_FLAG(r->flags, SAND_RFLAG_SILENT))
			nodes[to].silent = true;
		if (r->key.type != SAND_REC_ROUTER ||
		    r->len < SAND_REC_HDR_LEN + 4)
			continue;
		end = r->data + r->len;
		for (p = r->data + SAND_REC_HDR_LEN + 4;
		     p + SAND_RTR_ENTRY_LEN <= end; p += SAND_RTR_ENTRY_LEN) {
			long from = node_index(nodes, nr, sand_get32(p + 2));

			if (from < 0 || from == to)
				continue;
			if (ne == ecap) {
				ecap = ecap ? ecap * 2 : 128;
				edges = XREALLOC(MTYPE_SAND_SPF, edges,
						 ecap * sizeof(*edges));
			}
			edges[ne].from = from;
			edges[ne].to = to;
			edges[ne].to_if = sand_get16(p);
			edges[ne].from_if = sand_get16(p + 6);
			edges[ne].metric = sand_get16(p + 8);
			ne++;
		}
	}

	/* 3. Liveness (9.2): live if we are it, it is silent, or a live
	 * router hears it.  Fixpoint over the "hears" relation. */
	nodes[self].live = true;
	for (i = 0; i < nr; i++)
		if (nodes[i].silent)
			nodes[i].live = true;
	do {
		changed = false;
		for (i = 0; i < ne; i++)
			if (nodes[edges[i].to].live && !nodes[edges[i].from].live) {
				nodes[edges[i].from].live = true;
				changed = true;
			}
	} while (changed);

	/* 4. Dijkstra from us over live vertices */
	if (ne)
		qsort(edges, ne, sizeof(*edges), edge_from_cmp);
	estart = XCALLOC(MTYPE_SAND_SPF, (nr + 1) * sizeof(*estart));
	for (i = 0; i < ne; i++)
		estart[edges[i].from + 1]++;
	for (i = 0; i < nr; i++)
		estart[i + 1] += estart[i];

	nodes[self].cost = 0;
	for (;;) {
		long u = -1;
		size_t e;

		for (i = 0; i < nr; i++)
			if (!nodes[i].done && nodes[i].live &&
			    nodes[i].cost != UINT32_MAX &&
			    (u < 0 || nodes[i].cost < nodes[u].cost))
				u = i;
		if (u < 0)
			break;
		nodes[u].done = true;

		for (e = estart[u]; e < estart[u + 1]; e++) {
			struct sand_edge *ed = &edges[e];
			struct sand_spf_node *v = &nodes[ed->to];
			uint32_t c = nodes[u].cost + ed->metric;

			if (!v->live || v->done)
				continue;
			if (u == self) {
				struct sand_if *sif = sand_if_by_idx(ed->from_if);
				struct sand_nh nh = { .local_if = ed->from_if,
						      .nbr = v->rid,
						      .nbr_if = ed->to_if };

				if (!sif || !sif->running)
					continue;
				if (c < v->cost) {
					v->cost = c;
					v->n_nh = 0;
				}
				if (c == v->cost)
					nh_merge(v, &nh, 1);
			} else {
				if (c < v->cost) {
					v->cost = c;
					v->n_nh = 0;
				}
				if (c == v->cost)
					nh_merge(v, nodes[u].nh, nodes[u].n_nh);
			}
		}
	}

	/* Who hears each of our interfaces (for flood suppression) */
	for (i = 0; i < SAND_MAX_IFACES; i++) {
		struct sand_if *sif = sand_if_by_idx(i);

		if (sif)
			sif->n_listeners = 0;
	}
	for (i = estart[self]; i < estart[self + 1]; i++) {
		struct sand_if *sif = sand_if_by_idx(edges[i].from_if);
		uint32_t l = nodes[edges[i].to].rid;
		uint8_t j;
		bool dup = false;

		if (!sif || sif->n_listeners == 0xff ||
		    !nodes[edges[i].to].live)
			continue;
		for (j = 0; j < sif->n_listeners; j++)
			if (sif->listeners[j] == l)
				dup = true;
		if (dup)
			continue;
		if (sif->n_listeners < SAND_MAX_ECMP)
			sif->listeners[sif->n_listeners++] = l;
		else
			sif->n_listeners = 0xff;
	}

	XFREE(MTYPE_SAND_SPF, estart);
	XFREE(MTYPE_SAND_SPF, edges);
	XFREE(MTYPE_SAND_SPF, sand->spf);
	sand->spf = nodes;
	sand->spf_n = nr;
	sand->spf_runs++;
}

/* ------------------------------------------------------------------ */
/* Routes and neighbor entries                                          */
/* ------------------------------------------------------------------ */

static bool sand_nh_resolve(const struct sand_nh *h, int family,
			    struct sand_zebra_nh *out)
{
	struct sand_if *sif = sand_if_by_idx(h->local_if);
	struct in_addr v4;
	struct in6_addr v6;
	uint8_t mac[32], maclen = 0;

	if (!sif || !sif->running)
		return false;
	if (!sand_iface_lookup(h->nbr, h->nbr_if, &v4, &v6, mac, &maclen))
		return false;
	memset(out, 0, sizeof(*out));
	out->ifindex = sif->ifp->ifindex;
	if (maclen > sizeof(out->mac))
		maclen = sizeof(out->mac);
	memcpy(out->mac, mac, maclen);
	out->mac_len = maclen;
	if (family == AF_INET) {
		if (!v4.s_addr)
			return false;
		out->gate.ipv4 = v4;
	} else {
		if (IN6_IS_ADDR_UNSPECIFIED(&v6))
			return false;
		out->gate.ipv6 = v6;
	}
	return true;
}

static void sand_route_offer(struct sand_rt_head *tbl, const struct prefix *p,
			     uint32_t cost, const struct sand_spf_node *d)
{
	struct sand_route ref, *rt;
	struct sand_zebra_nh znh[SAND_MAX_ECMP];
	uint8_t nz = 0, i, j;

	for (i = 0; i < d->n_nh; i++)
		if (sand_nh_resolve(&d->nh[i], p->family, &znh[nz]))
			nz++;
	if (!nz)
		return;

	ref.p = *p;
	apply_mask(&ref.p);
	rt = sand_rt_find(tbl, &ref);
	if (rt && cost > rt->cost)
		return;
	if (!rt) {
		rt = XCALLOC(MTYPE_SAND_ROUTE, sizeof(*rt));
		rt->p = ref.p;
		rt->cost = cost;
		sand_rt_add(tbl, rt);
	} else if (cost < rt->cost) {
		rt->cost = cost;
		rt->n_nh = 0;
	}
	for (i = 0; i < nz && rt->n_nh < SAND_MAX_ECMP; i++) {
		bool dup = false;

		for (j = 0; j < rt->n_nh; j++)
			if (rt->nh[j].ifindex == znh[i].ifindex &&
			    !memcmp(&rt->nh[j].gate, &znh[i].gate,
				    sizeof(znh[i].gate)))
				dup = true;
		if (!dup)
			rt->nh[rt->n_nh++] = znh[i];
	}
}

static bool sand_route_same(const struct sand_route *a,
			    const struct sand_route *b)
{
	uint8_t i;

	if (a->n_nh != b->n_nh || a->cost != b->cost)
		return false;
	for (i = 0; i < a->n_nh; i++)
		if (a->nh[i].ifindex != b->nh[i].ifindex ||
		    memcmp(&a->nh[i].gate, &b->nh[i].gate,
			   sizeof(a->nh[i].gate)))
			return false;
	return true;
}

static void sand_neighs_sync(struct sand_rt_head *tbl)
{
	struct sand_route *rt;
	struct sand_neigh *n, **pp;
	uint8_t i;

	for (n = sand->neighs; n; n = n->next)
		n->mark = false;

	frr_each (sand_rt, tbl, rt) {
		for (i = 0; i < rt->n_nh; i++) {
			struct sand_zebra_nh *z = &rt->nh[i];
			int fam = rt->p.family;

			/* point-to-point devices have no link-layer address
			 * and need no neighbor entry */
			if (!z->mac_len)
				continue;

			for (n = sand->neighs; n; n = n->next)
				if (n->ifindex == z->ifindex &&
				    n->family == fam &&
				    !memcmp(&n->addr, &z->gate, sizeof(z->gate)))
					break;
			if (n && (n->mac_len != z->mac_len ||
				  memcmp(n->mac, z->mac, z->mac_len))) {
				memcpy(n->mac, z->mac, z->mac_len);
				n->mac_len = z->mac_len;
				sand_neigh_set(true, n);
			}
			if (!n) {
				n = XCALLOC(MTYPE_SAND_NEIGH, sizeof(*n));
				n->ifindex = z->ifindex;
				n->family = fam;
				n->addr = z->gate;
				memcpy(n->mac, z->mac, z->mac_len);
				n->mac_len = z->mac_len;
				n->next = sand->neighs;
				sand->neighs = n;
				sand_neigh_set(true, n);
			}
			n->mark = true;
		}
	}

	for (pp = &sand->neighs; *pp;) {
		n = *pp;
		if (!n->mark) {
			sand_neigh_set(false, n);
			*pp = n->next;
			XFREE(MTYPE_SAND_NEIGH, n);
		} else
			pp = &n->next;
	}
}

static void sand_routes_compute(void)
{
	struct sand_rt_head tbl;
	struct sand_route *rt, *old;
	size_t i;

	sand_rt_init(&tbl);

	for (i = 0; i < sand->spf_n; i++) {
		struct sand_spf_node *d = &sand->spf[i];
		uint32_t rid = d->rid;

		if (rid == sand->rid || !d->live || d->cost == UINT32_MAX ||
		    !d->n_nh)
			continue;

		/* Prefix records */
		for (uint8_t t = SAND_REC_PFX4; t <= SAND_REC_PFX6; t++) {
			FOREACH_REC_OF (r, rid, t) {
				const uint8_t *p, *end;

				if (!sand_rec_usable(r))
					continue;
				end = r->data + r->len;
				p = r->data + SAND_REC_HDR_LEN;
				while (end - p >= 4) {
					struct prefix pfx = {};
					unsigned int nb = (p[3] + 7) / 8;

					if (end - p < 4 + (int)nb)
						break;
					pfx.family = t == SAND_REC_PFX4 ? AF_INET
									: AF_INET6;
					pfx.prefixlen = p[3];
					memcpy(&pfx.u.prefix, p + 4, nb);
					sand_route_offer(&tbl, &pfx,
							 d->cost + sand_get16(p),
							 d);
					p += 4 + nb;
				}
			}
		}

		/* Host routes to interface addresses (11.5) */
		FOREACH_REC_OF (r, rid, SAND_REC_IFACE) {
			const uint8_t *p, *end;

			if (!sand_rec_usable(r))
				continue;
			end = r->data + r->len;
			p = r->data + SAND_REC_HDR_LEN;
			while (end - p >= 4) {
				uint8_t hl = p[3];
				struct prefix pfx = {};

				if (end - p < 24 + hl)
					break;
				pfx.family = AF_INET;
				pfx.prefixlen = 32;
				memcpy(&pfx.u.prefix4, p + 4 + hl, 4);
				if (pfx.u.prefix4.s_addr)
					sand_route_offer(&tbl, &pfx, d->cost, d);
				p += 24 + hl;
			}
		}
	}

	/* Neighbor entries first, so routes resolve as soon as installed */
	sand_neighs_sync(&tbl);

	/* Diff against what is installed */
	frr_each (sand_rt, &sand->routes, old)
		old->mark = false;
	frr_each (sand_rt, &tbl, rt) {
		old = sand_rt_find(&sand->routes, rt);
		if (old) {
			old->mark = true;
			if (sand_route_same(old, rt))
				continue;
		}
		SAND_DBG(SAND_DEBUG_ZEBRA, "install %pFX cost %u (%u nexthops)",
			 &rt->p, rt->cost, rt->n_nh);
		sand_zebra_route(true, rt);
	}
	frr_each (sand_rt, &sand->routes, old) {
		if (!old->mark) {
			SAND_DBG(SAND_DEBUG_ZEBRA, "withdraw %pFX", &old->p);
			sand_zebra_route(false, old);
		}
	}

	while ((old = sand_rt_pop(&sand->routes)))
		XFREE(MTYPE_SAND_ROUTE, old);
	while ((rt = sand_rt_pop(&tbl)))
		sand_rt_add(&sand->routes, rt);
	sand_rt_fini(&tbl);
}

void sand_spf_run(void)
{
	struct timeval tv;

	event_cancel(&sand->t_spf);
	if (!sand->running || !sand->rid)
		return;
	monotime(&tv);
	sand->last_spf_msec = tv.tv_sec * 1000 + tv.tv_usec / 1000;
	sand_spf_compute();
	sand_routes_compute();
	SAND_DBG(SAND_DEBUG_SPF, "route computation %" PRIu64 ": %zu routers, %zu routes",
		 sand->spf_runs, sand->spf_n, sand_rt_count(&sand->routes));
}

static void sand_spf_timer(struct event *t)
{
	sand_spf_run();
}

void sand_spf_schedule(void)
{
	struct timeval tv;
	long now, delay = SAND_SPF_DELAY_MSEC;

	if (!sand || !sand->running || sand->t_spf)
		return;
	monotime(&tv);
	now = tv.tv_sec * 1000 + tv.tv_usec / 1000;
	if (now - sand->last_spf_msec < SAND_SPF_HOLD_MSEC) {
		long wait = SAND_SPF_HOLD_MSEC - (now - sand->last_spf_msec);

		if (wait > delay)
			delay = wait;
	}
	event_add_timer_msec(master, sand_spf_timer, NULL, delay, &sand->t_spf);
}

/* Withdraw everything (shutdown) */
void sand_routes_flush(void)
{
	struct sand_route *rt;
	struct sand_neigh *n;

	while ((rt = sand_rt_pop(&sand->routes))) {
		sand_zebra_route(false, rt);
		XFREE(MTYPE_SAND_ROUTE, rt);
	}
	while ((n = sand->neighs)) {
		sand->neighs = n->next;
		sand_neigh_set(false, n);
		XFREE(MTYPE_SAND_NEIGH, n);
	}
	XFREE(MTYPE_SAND_SPF, sand->spf);
	sand->spf_n = 0;
}
