// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SAND v2 - records, origination, aging, flooding and repair
 * (design doc sections 6 - 10)
 */

#include <zebra.h>

#include "log.h"
#include "network.h"

#include "sandd/sandd.h"

DEFINE_MTYPE_STATIC(SANDD, SAND_REC, "SAND record");
DEFINE_MTYPE_STATIC(SANDD, SAND_REC_DATA, "SAND record data");
DEFINE_MTYPE_STATIC(SANDD, SAND_PREQ, "SAND pending request");

int sand_key_cmp(const struct sand_key *a, const struct sand_key *b)
{
	if (a->orig != b->orig)
		return a->orig < b->orig ? -1 : 1;
	if (a->type != b->type)
		return a->type < b->type ? -1 : 1;
	if (a->frag != b->frag)
		return a->frag < b->frag ? -1 : 1;
	return 0;
}

const char *sand_rec_type2str(uint8_t type)
{
	switch (type) {
	case SAND_REC_ROUTER:
		return "router";
	case SAND_REC_IFACE:
		return "interface";
	case SAND_REC_PFX4:
		return "ipv4-prefix";
	case SAND_REC_PFX6:
		return "ipv6-prefix";
	}
	return "unknown";
}

uint16_t sand_fletcher16(const uint8_t *data, size_t len)
{
	uint32_t c0 = 0, c1 = 0;
	size_t i;

	for (i = 0; i < len; i++) {
		c0 = (c0 + data[i]) % 255;
		c1 = (c1 + c0) % 255;
	}
	return (uint16_t)((c1 << 8) | c0);
}

/* Checksum over the record with lifetime and checksum fields zeroed */
static uint16_t sand_rec_cksum(const uint8_t *data, size_t len)
{
	uint8_t tmp[SAND_MAX_PKT];

	memcpy(tmp, data, len);
	memset(tmp + 12, 0, 4);
	return sand_fletcher16(tmp, len);
}

/* ------------------------------------------------------------------ */
/* Basic record handling                                                */
/* ------------------------------------------------------------------ */

struct sand_rec *sand_rec_lookup(const struct sand_key *k)
{
	struct sand_rec ref = { .key = *k };

	return sand_lsdb_find(&sand->lsdb, &ref);
}

uint16_t sand_rec_remaining(const struct sand_rec *r)
{
	time_t age;

	if (r->purge || r->expired_at)
		return 0;
	age = monotime(NULL) - r->rcvd;
	if (age >= r->lifetime)
		return 0;
	return r->lifetime - age;
}

/* A record routing may use: not purged, not expired */
bool sand_rec_usable(const struct sand_rec *r)
{
	return !r->purge && !r->expired_at && sand_rec_remaining(r) > 0;
}

/* Is this record worth listing and flooding? (purges yes, expired no) */
static bool sand_rec_advertisable(const struct sand_rec *r)
{
	if (r->placeholder || !r->data)
		return false;
	return r->purge ? (monotime(NULL) - r->rcvd < SAND_ZERO_AGE_HOLD)
			: sand_rec_usable(r);
}

/*
 * Version comparison, design doc 6.3.  Returns >0 if a is newer than b,
 * <0 if older, 0 if the same.
 */
static int sand_ver_cmp(uint32_t seq_a, bool purge_a, uint16_t ck_a,
			uint32_t seq_b, bool purge_b, uint16_t ck_b)
{
	if (seq_a != seq_b)
		return seq_a > seq_b ? 1 : -1;
	if (purge_a != purge_b)
		return purge_a ? 1 : -1;
	if (ck_a != ck_b)
		return ck_a > ck_b ? 1 : -1;
	return 0;
}

static void sand_rec_free(struct sand_rec *r)
{
	XFREE(MTYPE_SAND_REC_DATA, r->data);
	XFREE(MTYPE_SAND_REC, r);
}

static bool sand_type_affects_spf(uint8_t type)
{
	return type >= SAND_REC_ROUTER && type <= SAND_REC_MAX;
}

/* Install a record (data in wire format) replacing any older copy */
static struct sand_rec *sand_rec_install(const uint8_t *data, uint16_t len)
{
	struct sand_key k;
	struct sand_rec *r;

	k.type = data[0];
	k.frag = sand_get16(data + 2);
	k.orig = sand_get32(data + 4);

	r = sand_rec_lookup(&k);
	if (!r) {
		r = XCALLOC(MTYPE_SAND_REC, sizeof(*r));
		r->key = k;
		sand_lsdb_add(&sand->lsdb, r);
	} else {
		XFREE(MTYPE_SAND_REC_DATA, r->data);
	}
	r->data = XMALLOC(MTYPE_SAND_REC_DATA, len);
	memcpy(r->data, data, len);
	r->len = len;
	r->flags = data[1];
	r->seq = sand_get32(data + 8);
	r->lifetime = sand_get16(data + 12);
	r->cksum = sand_get16(data + 14);
	r->rcvd = monotime(NULL);
	r->purge = (r->lifetime == 0);
	r->expired_at = r->purge ? r->rcvd : 0;
	r->force_new = false;
	r->placeholder = false;

	if (sand_type_affects_spf(k.type))
		sand_spf_schedule();
	return r;
}

/* Basic sanity of a record body; returns false if malformed */
static bool sand_rec_body_ok(const uint8_t *d, uint16_t len)
{
	const uint8_t *p = d + SAND_REC_HDR_LEN, *end = d + len;

	if (d[0] != SAND_REC_ROUTER && sand_get16(d + 12) == 0 &&
	    p == end)
		return true; /* empty purge */

	switch (d[0]) {
	case SAND_REC_ROUTER:
		if (p == end)
			return true;
		if (end - p < 4)
			return false;
		return ((end - p - 4) % SAND_RTR_ENTRY_LEN) == 0;
	case SAND_REC_IFACE:
		while (p < end) {
			if (end - p < 4)
				return false;
			if (end - p < 4 + p[3] + 20)
				return false;
			p += 4 + p[3] + 20;
		}
		return true;
	case SAND_REC_PFX4:
	case SAND_REC_PFX6: {
		unsigned int maxlen = d[0] == SAND_REC_PFX4 ? 32 : 128;

		while (p < end) {
			unsigned int plen, nb;

			if (end - p < 4)
				return false;
			plen = p[3];
			if (plen > maxlen)
				return false;
			nb = (plen + 7) / 8;
			if (end - p < 4 + (int)nb)
				return false;
			p += 4 + nb;
		}
		return true;
	}
	}
	return false;
}

/* Copy a record for sending, with its current remaining lifetime */
static size_t sand_rec_encode(const struct sand_rec *r, uint8_t *out)
{
	memcpy(out, r->data, r->len);
	sand_put16(out + 12, r->purge ? 0 : sand_rec_remaining(r));
	return r->len;
}

uint32_t sand_lsdb_digest(void)
{
	struct sand_rec *r;
	uint32_t d = 0;

	frr_each (sand_lsdb, &sand->lsdb, r) {
		if (!sand_rec_advertisable(r))
			continue;
		d ^= (r->seq * 2654435761U) ^ r->cksum ^ r->key.orig ^
		     ((uint32_t)r->key.type << 24 | r->key.frag);
	}
	return d;
}

/* ------------------------------------------------------------------ */
/* Flooding (8.1, 8.2)                                                  */
/* ------------------------------------------------------------------ */

void sand_flood_all(const struct sand_key *k)
{
	int i;

	for (i = 0; i < SAND_MAX_IFACES; i++) {
		struct sand_if *sif = sand_if_by_idx(i);

		if (sif && sif->running)
			sand_flood_queue(sif, k);
	}
}

/* Flood a record learned from `from`, skipping interfaces whose only known
 * listener is `from` itself (it already has the record). */
void sand_flood_except(const struct sand_key *k, uint32_t from)
{
	int i;

	for (i = 0; i < SAND_MAX_IFACES; i++) {
		struct sand_if *sif = sand_if_by_idx(i);

		if (!sif || !sif->running)
			continue;
		if (sif->n_listeners == 1 && sif->listeners[0] == from)
			continue;
		sand_flood_queue(sif, k);
	}
}

static void sand_flood_send(struct sand_if *sif)
{
	uint8_t body[SAND_MAX_PKT];
	size_t max = sand_if_payload_max(sif), blen = 0;
	struct sand_key k;
	unsigned int nrec = 0;

	while (sand_flood_pop(sif, &k)) {
		struct sand_rec *r = sand_rec_lookup(&k);

		if (!r || !sand_rec_advertisable(r))
			continue;
		if (blen + r->len > max) {
			sand_pkt_send(sif, SAND_PKT_UPDATE, body, blen);
			blen = 0;
		}
		blen += sand_rec_encode(r, body + blen);
		nrec++;
	}
	if (blen)
		sand_pkt_send(sif, SAND_PKT_UPDATE, body, blen);
	if (nrec)
		SAND_DBG(SAND_DEBUG_FLOOD, "flooded %u records on %s", nrec,
			 sif->ifp->name);
}

void sand_flood_run(struct event *t)
{
	struct sand_if *sif = EVENT_ARG(t);

	sand_flood_send(sif);
}

/* Send every queued record now (shutdown, entering silence) */
void sand_flood_flush_all(void)
{
	int i;

	for (i = 0; i < SAND_MAX_IFACES; i++) {
		struct sand_if *sif = sand_if_by_idx(i);

		if (sif && sif->running) {
			event_cancel(&sif->t_flood);
			sand_flood_send(sif);
		}
	}
}

/* Queue a record on the interfaces that `listener` is known to hear */
static int sand_queue_to_listener(uint32_t listener, const struct sand_key *k,
				  bool all_if_unknown)
{
	int16_t ifs[SAND_MAX_IFACES];
	int n, i;

	n = sand_rtr_hears(listener, sand->rid, ifs, SAND_MAX_IFACES);
	for (i = 0; i < n; i++) {
		struct sand_if *sif = sand_if_by_idx(ifs[i]);

		if (sif && sif->running)
			sand_flood_queue(sif, k);
	}
	if (n == 0 && all_if_unknown)
		sand_flood_all(k);
	return n;
}

/* ------------------------------------------------------------------ */
/* Own records: conflict handling (10.2, 10.4)                          */
/* ------------------------------------------------------------------ */

/* Somebody holds a version of our own record. */
static void sand_self_seen(const struct sand_key *k, uint32_t seq, bool purge,
			   uint16_t cksum)
{
	struct sand_rec *r = sand_rec_lookup(k);
	time_t now = monotime(NULL);
	char buf[INET_ADDRSTRLEN];

	if (r && sand_ver_cmp(seq, purge, cksum, r->seq, r->purge,
			      r->cksum) <= 0) {
		/* ours is newer or the same: make sure they get it */
		if (sand_ver_cmp(seq, purge, cksum, r->seq, r->purge,
				 r->cksum) < 0 &&
		    now - r->last_push >= SAND_MIN_ORIG_INTERVAL &&
		    sand_rec_advertisable(r)) {
			r->last_push = now;
			sand_flood_all(k);
		}
		return;
	}

	/* Theirs is newer than anything we have: 10.2 */
	if (now < sand->duprid_block_until)
		return;
	if (now - sand->duprid_window_start > SAND_DUPRID_WINDOW) {
		sand->duprid_window_start = now;
		sand->duprid_count = 0;
	}
	/* After a restart every key comes back once; count only repeats */
	if (r && r->seq > 1 && ++sand->duprid_count > SAND_DUPRID_LIMIT) {
		zlog_err("SAND: router-id %s appears to be in use by another router (own %s record keeps coming back newer); pausing re-origination",
			 sand_rid2str(sand->rid, buf, sizeof(buf)),
			 sand_rec_type2str(k->type));
		sand->duprid_block_until = now + SAND_ZERO_AGE_HOLD;
		return;
	}

	SAND_DBG(SAND_DEBUG_FLOOD,
		 "own %s/%u seen newer (seq %u), re-originating above it",
		 sand_rec_type2str(k->type), k->frag, seq);

	if (!r) {
		/* placeholder: holds the sequence floor, never sent */
		uint8_t hdr[SAND_REC_HDR_LEN] = {};

		hdr[0] = k->type;
		sand_put16(hdr + 2, k->frag);
		sand_put32(hdr + 4, k->orig);
		sand_put16(hdr + 16, SAND_REC_HDR_LEN);
		r = sand_rec_install(hdr, SAND_REC_HDR_LEN);
		r->placeholder = true;
	}
	r->seq = seq;
	r->force_new = true;
	sand_originate_now();
}

/* ------------------------------------------------------------------ */
/* Receiving records (8.1)                                              */
/* ------------------------------------------------------------------ */

/* Did a Router record update add a link from us?  Then that router just
 * started hearing one of our interfaces: send it a Summary (8.3). */
static void sand_check_new_listener(const uint8_t *old, uint16_t oldlen,
				    const uint8_t *new, uint16_t newlen)
{
	const uint8_t *p, *q;

	if (newlen <= SAND_REC_HDR_LEN + 4)
		return;
	for (p = new + SAND_REC_HDR_LEN + 4; p + SAND_RTR_ENTRY_LEN <= new + newlen;
	     p += SAND_RTR_ENTRY_LEN) {
		bool found = false;
		uint16_t sif_idx;

		if (sand_get32(p + 2) != sand->rid)
			continue;
		sif_idx = sand_get16(p + 6);
		if (old && oldlen > SAND_REC_HDR_LEN + 4)
			for (q = old + SAND_REC_HDR_LEN + 4;
			     q + SAND_RTR_ENTRY_LEN <= old + oldlen;
			     q += SAND_RTR_ENTRY_LEN)
				if (sand_get32(q + 2) == sand->rid &&
				    sand_get16(q + 6) == sif_idx)
					found = true;
		if (!found) {
			struct sand_if *sif = sand_if_by_idx(sif_idx);

			if (sif)
				sand_if_trigger_summary(sif);
		}
	}
}

void sand_rx_update(struct sand_if *sif, uint32_t sender, const uint8_t *body,
		    size_t len)
{
	const uint8_t *p = body, *end = body + len;
	time_t now = monotime(NULL);

	while (end - p >= SAND_REC_HDR_LEN) {
		uint16_t rlen = sand_get16(p + 16);
		struct sand_key k;
		uint32_t seq;
		uint16_t lifetime, cksum;
		bool purge;
		struct sand_rec *r;
		int cmp;

		if (rlen < SAND_REC_HDR_LEN || rlen > end - p ||
		    rlen > SAND_MAX_REC_LEN + 512)
			return;
		k.type = p[0];
		k.frag = sand_get16(p + 2);
		k.orig = sand_get32(p + 4);
		seq = sand_get32(p + 8);
		lifetime = sand_get16(p + 12);
		cksum = sand_get16(p + 14);
		purge = (lifetime == 0);

		if (k.type < 1 || k.type > SAND_REC_MAX || seq == 0 ||
		    k.orig == 0 || cksum != sand_rec_cksum(p, rlen) ||
		    !sand_rec_body_ok(p, rlen)) {
			SAND_DBG(SAND_DEBUG_FLOOD,
				 "dropping bad record from %pI4 on %s",
				 &(struct in_addr){htonl(sender)},
				 sif->ifp->name);
			p += rlen;
			continue;
		}

		if (k.orig == sand->rid) {
			sand_self_seen(&k, seq, purge, cksum);
			p += rlen;
			continue;
		}

		r = sand_rec_lookup(&k);
		if (!r)
			cmp = 1;
		else
			cmp = sand_ver_cmp(seq, purge, cksum, r->seq, r->purge,
					   r->cksum);

		if (cmp > 0) {
			uint8_t *old = NULL;
			uint16_t oldlen = 0;

			if (!r && purge) {
				/* nothing to withdraw; just pass it on */
			}
			if (r && k.type == SAND_REC_ROUTER && r->data) {
				old = XMALLOC(MTYPE_TMP, r->len);
				memcpy(old, r->data, r->len);
				oldlen = r->len;
			}
			SAND_DBG(SAND_DEBUG_FLOOD,
				 "install %s/%u from %pI4 seq %u%s",
				 sand_rec_type2str(k.type), k.frag,
				 &(struct in_addr){htonl(k.orig)}, seq,
				 purge ? " (purge)" : "");
			sand_rec_install(p, rlen);
			sand_flood_except(&k, sender);
			if (k.type == SAND_REC_ROUTER && !purge)
				sand_check_new_listener(old, oldlen, p, rlen);
			XFREE(MTYPE_TMP, old);
		} else if (cmp < 0 && now - r->last_push >= SAND_MIN_ORIG_INTERVAL &&
			   sand_rec_advertisable(r)) {
			/* sender is behind: push our newer copy (8.1 step 4) */
			r->last_push = now;
			sand_flood_all(&k);
		}
		p += rlen;
	}
}

/* ------------------------------------------------------------------ */
/* Pending requests: wait, then ask only for what is still missing     */
/* ------------------------------------------------------------------ */

struct sand_preq {
	struct sand_preq *next;
	uint32_t target;
	struct event *t;
	uint16_t n;
	struct {
		struct sand_key k;
		uint32_t want_seq;
	} e[SAND_REQ_MAX_ENTRIES];
};

static struct sand_preq *sand_preqs;

static void sand_preq_fire(struct event *t)
{
	struct sand_preq *pq = EVENT_ARG(t), **pp;
	uint8_t buf[SAND_REQ_MAX_ENTRIES * SAND_REQ_ENTRY_LEN];
	size_t n = 0;
	uint16_t i;

	for (pp = &sand_preqs; *pp; pp = &(*pp)->next)
		if (*pp == pq) {
			*pp = pq->next;
			break;
		}
	for (i = 0; i < pq->n; i++) {
		struct sand_rec *r = sand_rec_lookup(&pq->e[i].k);

		if (r && !r->placeholder && r->seq >= pq->e[i].want_seq)
			continue; /* arrived meanwhile through flooding */
		sand_key_put(buf + n * SAND_REQ_ENTRY_LEN, &pq->e[i].k);
		sand_put32(buf + n * SAND_REQ_ENTRY_LEN + 8, r ? r->seq : 0);
		n++;
	}
	if (n) {
		SAND_DBG(SAND_DEBUG_FLOOD, "requesting %zu of %u from %pI4", n,
			 pq->n, &(struct in_addr){htonl(pq->target)});
		sand_send_request(pq->target, buf, n);
	}
	XFREE(MTYPE_SAND_PREQ, pq);
}

static void sand_preq_add(uint32_t target, const struct sand_key *k,
			  uint32_t want_seq)
{
	struct sand_preq *pq;
	uint16_t i;

	for (pq = sand_preqs; pq; pq = pq->next)
		if (pq->target == target)
			break;
	if (!pq) {
		pq = XCALLOC(MTYPE_SAND_PREQ, sizeof(*pq));
		pq->target = target;
		pq->next = sand_preqs;
		sand_preqs = pq;
		event_add_timer_msec(master, sand_preq_fire, pq,
				     SAND_REQ_DELAY_MSEC, &pq->t);
	}
	for (i = 0; i < pq->n; i++)
		if (!sand_key_cmp(&pq->e[i].k, k)) {
			if (want_seq > pq->e[i].want_seq)
				pq->e[i].want_seq = want_seq;
			return;
		}
	if (pq->n < SAND_REQ_MAX_ENTRIES) {
		pq->e[pq->n].k = *k;
		pq->e[pq->n].want_seq = want_seq;
		pq->n++;
	}
}

static void sand_preq_flush(void)
{
	struct sand_preq *pq;

	while ((pq = sand_preqs)) {
		sand_preqs = pq->next;
		event_cancel(&pq->t);
		XFREE(MTYPE_SAND_PREQ, pq);
	}
}

/* ------------------------------------------------------------------ */
/* Summaries (8.3)                                                      */
/* ------------------------------------------------------------------ */

static void sand_key_succ(struct sand_key *k)
{
	if (k->frag < 0xffff) {
		k->frag++;
		return;
	}
	k->frag = 0;
	if (k->type < 0xff) {
		k->type++;
		return;
	}
	k->type = 0;
	k->orig++;
}

static void sand_sum_flush(struct sand_if *sif, uint8_t *body, size_t blen,
			   const struct sand_key *start,
			   const struct sand_key *end)
{
	sand_key_put(body, start);
	sand_key_put(body + SAND_KEY_LEN, end);
	sand_pkt_send(sif, SAND_PKT_SUMMARY, body, blen);
}

void sand_send_summary(struct sand_if *sif)
{
	uint8_t body[SAND_MAX_PKT];
	size_t max = sand_if_payload_max(sif);
	size_t blen = 2 * SAND_KEY_LEN;
	struct sand_key start = {}, last = {};
	const struct sand_key maxkey = { .orig = 0xffffffff, .type = 0xff,
					 .frag = 0xffff };
	struct sand_rec *r;
	bool any = false;

	if (!sif->running)
		return;

	frr_each (sand_lsdb, &sand->lsdb, r) {
		uint8_t *e;

		if (!sand_rec_advertisable(r))
			continue;
		if (blen + SAND_SUM_ENTRY_LEN > max) {
			sand_sum_flush(sif, body, blen, &start, &last);
			start = last;
			sand_key_succ(&start);
			blen = 2 * SAND_KEY_LEN;
		}
		e = body + blen;
		memcpy(e, r->data, 12);
		sand_put16(e + 12, r->purge ? 0 : sand_rec_remaining(r));
		sand_put16(e + 14, r->cksum);
		blen += SAND_SUM_ENTRY_LEN;
		last = r->key;
		any = true;
	}
	(void)any;
	sand_sum_flush(sif, body, blen, &start, &maxkey);
	SAND_DBG(SAND_DEBUG_FLOOD, "sent summary on %s", sif->ifp->name);
}

void sand_rx_summary(struct sand_if *sif, uint32_t sender, const uint8_t *body,
		     size_t len)
{
	struct sand_key start, end, k;
	const uint8_t *p, *bend = body + len;
	size_t nwant = 0;
	struct sand_rec ref, *r;
	time_t now = monotime(NULL);
	int16_t ifs[SAND_MAX_IFACES];
	bool sender_hears_us;

	if (len < 2 * SAND_KEY_LEN || (len - 2 * SAND_KEY_LEN) % SAND_SUM_ENTRY_LEN)
		return;
	sand_key_get(body, &start);
	sand_key_get(body + SAND_KEY_LEN, &end);
	sender_hears_us = sand_rtr_hears(sender, sand->rid, ifs,
					 SAND_MAX_IFACES) > 0;

	/* Pass 1: entries the sender lists */
	for (p = body + 2 * SAND_KEY_LEN; p + SAND_SUM_ENTRY_LEN <= bend;
	     p += SAND_SUM_ENTRY_LEN) {
		uint32_t seq = sand_get32(p + 8);
		uint16_t lifetime = sand_get16(p + 12);
		uint16_t cksum = sand_get16(p + 14);
		bool purge = lifetime == 0;
		int cmp;

		k.type = p[0];
		k.frag = sand_get16(p + 2);
		k.orig = sand_get32(p + 4);
		if (k.type < 1 || k.type > SAND_REC_MAX || seq == 0)
			continue;

		if (k.orig == sand->rid) {
			sand_self_seen(&k, seq, purge, cksum);
			continue;
		}
		r = sand_rec_lookup(&k);
		if (!r) {
			if (purge)
				continue; /* nothing to withdraw */
			cmp = 1;
		} else
			cmp = sand_ver_cmp(seq, purge, cksum, r->seq, r->purge,
					   r->cksum);
		if (cmp > 0) {
			sand_preq_add(sender, &k, seq);
			nwant++;
		} else if (cmp < 0 && sender_hears_us &&
			   now - r->last_push >= SAND_MIN_ORIG_INTERVAL &&
			   sand_rec_advertisable(r)) {
			r->last_push = now;
			sand_queue_to_listener(sender, &k, false);
		}
	}

	/* Pass 2: records we hold in the range that the sender lacks */
	if (sender_hears_us) {
		ref.key = start;
		for (r = sand_lsdb_find_gteq(&sand->lsdb, &ref); r;
		     r = sand_lsdb_next(&sand->lsdb, r)) {
			bool listed = false;

			if (sand_key_cmp(&r->key, &end) > 0)
				break;
			if (!sand_rec_usable(r))
				continue;
			for (p = body + 2 * SAND_KEY_LEN;
			     p + SAND_SUM_ENTRY_LEN <= bend;
			     p += SAND_SUM_ENTRY_LEN) {
				sand_key_get(p, &k);
				k.type = p[0];
				if (!sand_key_cmp(&k, &r->key)) {
					listed = true;
					break;
				}
			}
			if (listed || now - r->last_push < SAND_MIN_ORIG_INTERVAL)
				continue;
			r->last_push = now;
			sand_queue_to_listener(sender, &r->key, false);
		}
	}

	if (nwant)
		SAND_DBG(SAND_DEBUG_FLOOD,
			 "summary from %pI4: %zu records newer there",
			 &(struct in_addr){htonl(sender)}, nwant);
}

/* ------------------------------------------------------------------ */
/* Requests (8.4)                                                       */
/* ------------------------------------------------------------------ */

static bool sand_reqcache_check(uint32_t requester, uint32_t nonce)
{
	time_t now = monotime(NULL);
	unsigned int i;
	struct sand_reqcache *c;

	for (i = 0; i < SAND_REQ_CACHE; i++) {
		c = &sand->reqcache[i];
		if (c->requester == requester && c->nonce == nonce &&
		    now - c->when < SAND_REQ_MEMORY)
			return true;
	}
	c = &sand->reqcache[sand->reqcache_next];
	sand->reqcache_next = (sand->reqcache_next + 1) % SAND_REQ_CACHE;
	c->requester = requester;
	c->nonce = nonce;
	c->when = now;
	return false;
}

/* Send (or forward) a request body toward `target` */
static void sand_request_route(uint32_t target, const uint8_t *body,
			       size_t blen)
{
	struct sand_spf_node *n = sand_spf_lookup(target);
	struct sand_if *sif;
	int i;

	if (n && n->cost != UINT32_MAX && n->n_nh) {
		sif = sand_if_by_idx(n->nh[0].local_if);
		if (sif && sif->running) {
			sand_pkt_send(sif, SAND_PKT_REQUEST, body, blen);
			return;
		}
	}
	/* no known path: send everywhere (bootstrap) */
	for (i = 0; i < SAND_MAX_IFACES; i++) {
		sif = sand_if_by_idx(i);
		if (sif && sif->running)
			sand_pkt_send(sif, SAND_PKT_REQUEST, body, blen);
	}
}

void sand_send_request(uint32_t target, const uint8_t *entries,
		       size_t n_entries)
{
	uint8_t body[SAND_MAX_PKT];
	uint32_t nonce = frr_weak_random();
	size_t blen;

	sand_put32(body, sand->rid);
	sand_put32(body + 4, target);
	sand_put32(body + 8, nonce);
	body[12] = SAND_REQ_HOPS;
	body[13] = 0;
	sand_put16(body + 14, n_entries);
	memcpy(body + SAND_REQ_HDR_LEN, entries,
	       n_entries * SAND_REQ_ENTRY_LEN);
	blen = SAND_REQ_HDR_LEN + n_entries * SAND_REQ_ENTRY_LEN;

	sand_reqcache_check(sand->rid, nonce);
	sand_request_route(target, body, blen);
}

void sand_rx_request(struct sand_if *sif, uint32_t sender, const uint8_t *body,
		     size_t len)
{
	uint32_t requester, target, nonce;
	uint8_t hops;
	uint16_t count, i;
	const uint8_t *e;
	int16_t ifs[SAND_MAX_IFACES];
	int nifs;
	bool can_answer = true;

	if (len < SAND_REQ_HDR_LEN)
		return;
	requester = sand_get32(body);
	target = sand_get32(body + 4);
	nonce = sand_get32(body + 8);
	hops = body[12];
	count = sand_get16(body + 14);
	if (len < SAND_REQ_HDR_LEN + (size_t)count * SAND_REQ_ENTRY_LEN)
		return;
	if (requester == sand->rid)
		return;
	if (sand_reqcache_check(requester, nonce))
		return;

	nifs = sand_rtr_hears(requester, sand->rid, ifs, SAND_MAX_IFACES);

	/* Could we answer it all ourselves? (target, or a router the
	 * requester hears directly) */
	for (i = 0, e = body + SAND_REQ_HDR_LEN; i < count;
	     i++, e += SAND_REQ_ENTRY_LEN) {
		struct sand_key k;
		struct sand_rec *r;

		sand_key_get(e, &k);
		r = sand_rec_lookup(&k);
		if (!r || !sand_rec_advertisable(r) ||
		    r->seq <= sand_get32(e + 8)) {
			can_answer = false;
			break;
		}
	}

	if (target == sand->rid || (can_answer && nifs > 0)) {
		unsigned int sent = 0;

		for (i = 0, e = body + SAND_REQ_HDR_LEN; i < count;
		     i++, e += SAND_REQ_ENTRY_LEN) {
			struct sand_key k;
			struct sand_rec *r;

			sand_key_get(e, &k);
			r = sand_rec_lookup(&k);
			if (!r || !sand_rec_advertisable(r) ||
			    r->seq <= sand_get32(e + 8))
				continue;
			sand_queue_to_listener(requester, &k, true);
			sent++;
		}
		SAND_DBG(SAND_DEBUG_FLOOD,
			 "answered request from %pI4 with %u records",
			 &(struct in_addr){htonl(requester)}, sent);
		if (target == sand->rid || can_answer)
			return;
	}

	if (hops == 0)
		return;
	{
		uint8_t fwd[SAND_MAX_PKT];
		size_t flen = SAND_REQ_HDR_LEN +
			      (size_t)count * SAND_REQ_ENTRY_LEN;

		memcpy(fwd, body, flen);
		fwd[12] = hops - 1;
		SAND_DBG(SAND_DEBUG_FLOOD, "forwarding request %pI4 -> %pI4",
			 &(struct in_addr){htonl(requester)},
			 &(struct in_addr){htonl(target)});
		sand_request_route(target, fwd, flen);
	}
}

/* ------------------------------------------------------------------ */
/* Origination (7.1 - 7.4)                                              */
/* ------------------------------------------------------------------ */

static void sand_orig_timer(struct event *t);

struct sand_build {
	uint8_t type;
	uint16_t frag;
	uint8_t body[SAND_MAX_REC_LEN];
	uint16_t blen;
	uint16_t pre; /* per-fragment preamble length */
};

#define SAND_MAX_BUILD 256
static struct sand_build builds[SAND_MAX_BUILD];
static int nbuilds;

static struct sand_build *sand_build_new(uint8_t type, uint16_t frag,
					 const uint8_t *pre, uint16_t prelen)
{
	struct sand_build *b;

	if (nbuilds >= SAND_MAX_BUILD)
		return NULL;
	b = &builds[nbuilds++];
	b->type = type;
	b->frag = frag;
	b->pre = prelen;
	memcpy(b->body, pre, prelen);
	b->blen = prelen;
	return b;
}

/* Append an entry, starting a new fragment when this one is full */
static struct sand_build *sand_build_add(struct sand_build *b,
					 const uint8_t *entry, uint16_t elen)
{
	if (!b)
		return NULL;
	if (SAND_REC_HDR_LEN + b->blen + elen > SAND_MAX_REC_LEN) {
		uint8_t pre[16];

		memcpy(pre, b->body, b->pre);
		b = sand_build_new(b->type, b->frag + 1, pre, b->pre);
		if (!b)
			return NULL;
	}
	memcpy(b->body + b->blen, entry, elen);
	b->blen += elen;
	return b;
}

static void sand_build_router(void)
{
	uint8_t pre[4], e[SAND_RTR_ENTRY_LEN];
	struct sand_build *b;
	int i;

	sand_put16(pre, sand_if_count());
	sand_put16(pre + 2, 0);
	b = sand_build_new(SAND_REC_ROUTER, 0, pre, 4);

	for (i = 0; i < SAND_MAX_IFACES; i++) {
		struct sand_if *sif = sand_if_by_idx(i);
		struct sand_nbr *n;

		if (!sif || !sif->running)
			continue;
		for (n = sif->nbrs; n; n = n->next) {
			uint16_t m = sand_nbr_metric(n);

			n->adv_metric = m;
			sand_put16(e, sif->idx);
			sand_put32(e + 2, n->rid);
			sand_put16(e + 6, n->ifidx);
			sand_put16(e + 8, m);
			e[10] = (uint64_t)n->ratio * 100 / SAND_RATIO_ONE;
			e[11] = 0;
			b = sand_build_add(b, e, sizeof(e));
		}
	}
}

static void sand_build_iface(void)
{
	uint8_t e[64];
	struct sand_build *b = sand_build_new(SAND_REC_IFACE, 0, NULL, 0);
	int i;

	for (i = 0; i < SAND_MAX_IFACES; i++) {
		struct sand_if *sif = sand_if_by_idx(i);
		struct interface *ifp;
		uint8_t hwlen;
		uint16_t elen;

		if (!sif)
			continue;
		ifp = sif->ifp;
		hwlen = ifp->hw_addr_len > 0 && ifp->hw_addr_len <= 20
				? ifp->hw_addr_len
				: 0;
		sand_put16(e, sif->idx);
		e[2] = sif->running ? 0x01 : 0;
		e[3] = hwlen;
		memcpy(e + 4, ifp->hw_addr, hwlen);
		memcpy(e + 4 + hwlen, &sif->ipv4, 4);
		memcpy(e + 8 + hwlen, &sif->ipv6ll, 16);
		elen = 24 + hwlen;
		b = sand_build_add(b, e, elen);
	}
}

static void sand_build_pfx(int family)
{
	uint8_t type = family == AF_INET ? SAND_REC_PFX4 : SAND_REC_PFX6;
	struct sand_build *b = NULL;
	struct sand_xpfx *x;
	uint8_t e[24];

	frr_each (sand_xpfx, &sand->xpfx, x) {
		unsigned int nb;

		if (x->p.family != family)
			continue;
		if (!b)
			b = sand_build_new(type, 0, NULL, 0);
		nb = (x->p.prefixlen + 7) / 8;
		sand_put16(e, x->metric);
		e[2] = 0;
		e[3] = x->p.prefixlen;
		memcpy(e + 4, &x->p.u.prefix, nb);
		b = sand_build_add(b, e, 4 + nb);
	}
}

static struct sand_build *sand_build_find(const struct sand_key *k)
{
	int i;

	for (i = 0; i < nbuilds; i++)
		if (builds[i].type == k->type && builds[i].frag == k->frag)
			return &builds[i];
	return NULL;
}

static void sand_orig_one(const struct sand_key *k, const uint8_t *body,
			  uint16_t blen, bool purge)
{
	uint8_t d[SAND_REC_HDR_LEN + SAND_MAX_REC_LEN];
	struct sand_rec *r = sand_rec_lookup(k);
	uint32_t seq = r ? r->seq + 1 : 1;
	uint16_t len = SAND_REC_HDR_LEN + (purge ? 0 : blen);
	uint16_t lifetime;

	if (seq == 0xffffffff) {
		/* 7.5: purge and start over after the zero-age hold */
		purge = true;
		len = SAND_REC_HDR_LEN;
	}
	lifetime = purge ? 0 : (sand->silent ? sand->silent_hold : sand->lifetime);

	d[0] = k->type;
	d[1] = sand->silent && !purge ? SAND_RFLAG_SILENT : 0;
	sand_put16(d + 2, k->frag);
	sand_put32(d + 4, k->orig);
	sand_put32(d + 8, seq);
	sand_put16(d + 12, lifetime);
	sand_put16(d + 14, 0);
	sand_put16(d + 16, len);
	sand_put16(d + 18, 0);
	if (!purge && blen)
		memcpy(d + SAND_REC_HDR_LEN, body, blen);
	sand_put16(d + 14, sand_rec_cksum(d, len));

	r = sand_rec_install(d, len);
	r->refresh_at = r->rcvd + (lifetime / 2) -
			(lifetime ? frr_weak_random() % (lifetime / 10 + 1) : 0);
	sand->originations++;
	SAND_DBG(SAND_DEBUG_FLOOD, "originate %s/%u seq %u%s",
		 sand_rec_type2str(k->type), k->frag, seq,
		 purge ? " (purge)" : "");
	sand_flood_all(k);
}

void sand_originate_now(void)
{
	struct sand_rec *r;
	struct sand_key k;
	time_t now = monotime(NULL);
	bool defer = false;
	int i;

	event_cancel(&sand->t_orig);
	sand->orig_pending = false;
	if (!sand->running || !sand->rid)
		return;
	if (now < sand->duprid_block_until) {
		event_add_timer(master, sand_orig_timer,
				NULL, sand->duprid_block_until - now,
				&sand->t_orig);
		return;
	}

	nbuilds = 0;
	sand_build_router();
	sand_build_iface();
	sand_build_pfx(AF_INET);
	sand_build_pfx(AF_INET6);

	/* New or changed content */
	for (i = 0; i < nbuilds; i++) {
		struct sand_build *b = &builds[i];
		uint8_t want_flags = sand->silent ? SAND_RFLAG_SILENT : 0;

		k.orig = sand->rid;
		k.type = b->type;
		k.frag = b->frag;
		r = sand_rec_lookup(&k);
		if (r && !r->force_new && sand_rec_usable(r) &&
		    r->flags == want_flags &&
		    r->len == SAND_REC_HDR_LEN + b->blen &&
		    !memcmp(r->data + SAND_REC_HDR_LEN, b->body, b->blen))
			continue;
		if (r && !r->force_new && now - r->rcvd < SAND_MIN_ORIG_INTERVAL &&
		    r->seq) {
			defer = true;
			continue;
		}
		sand_orig_one(&k, b->body, b->blen, false);
	}

	/* Own records no longer produced: purge them */
	frr_each_safe (sand_lsdb, &sand->lsdb, r) {
		if (r->key.orig != sand->rid)
			continue;
		if (sand_build_find(&r->key))
			continue;
		if (r->purge && !r->force_new)
			continue;
		if (!r->force_new && now - r->rcvd < SAND_MIN_ORIG_INTERVAL) {
			defer = true;
			continue;
		}
		k = r->key;
		sand_orig_one(&k, NULL, 0, true);
	}

	if (defer) {
		sand->orig_pending = true;
		event_add_timer(master, sand_orig_timer,
				NULL, SAND_MIN_ORIG_INTERVAL, &sand->t_orig);
	}
}

static void sand_orig_timer(struct event *t)
{
	sand_originate_now();
}

void sand_schedule_orig(void)
{
	if (!sand || !sand->running)
		return;
	if (sand->t_orig)
		return;
	event_add_timer_msec(master, sand_orig_timer, NULL,
			     SAND_ORIG_DELAY_MSEC, &sand->t_orig);
}

/* Graceful shutdown: withdraw everything we originated (7.4, 9.5) */
void sand_purge_own(void)
{
	struct sand_rec *r;
	struct sand_key k;

	frr_each_safe (sand_lsdb, &sand->lsdb, r) {
		if (r->key.orig != sand->rid || r->purge)
			continue;
		k = r->key;
		sand_orig_one(&k, NULL, 0, true);
	}
	sand_flood_flush_all();
}

/* ------------------------------------------------------------------ */
/* Aging (7.2, 7.3)                                                     */
/* ------------------------------------------------------------------ */

void sand_ager(struct event *t)
{
	struct sand_rec *r;
	time_t now = monotime(NULL);
	bool refresh = false;

	event_add_timer(master, sand_ager, NULL, 1, &sand->t_ager);

	frr_each_safe (sand_lsdb, &sand->lsdb, r) {
		bool own = r->key.orig == sand->rid;

		if (own && !r->purge && !sand->silent && r->refresh_at &&
		    now >= r->refresh_at) {
			r->force_new = true;
			refresh = true;
		}
		if (!r->expired_at && sand_rec_remaining(r) == 0) {
			r->expired_at = now;
			SAND_DBG(SAND_DEBUG_FLOOD, "%s/%u from %pI4 expired",
				 sand_rec_type2str(r->key.type), r->key.frag,
				 &(struct in_addr){htonl(r->key.orig)});
			sand_spf_schedule();
		}
		if (r->expired_at && now - r->expired_at >= SAND_ZERO_AGE_HOLD &&
		    !r->force_new) {
			sand_lsdb_del(&sand->lsdb, r);
			sand_rec_free(r);
		}
	}
	if (refresh)
		sand_originate_now();
}

/* ------------------------------------------------------------------ */

void sand_lsdb_init_all(void)
{
	sand_lsdb_init(&sand->lsdb);
}

void sand_lsdb_flush(void)
{
	struct sand_rec *r;

	sand_preq_flush();
	while ((r = sand_lsdb_pop(&sand->lsdb)))
		sand_rec_free(r);
}
