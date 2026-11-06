// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Packet-pair link speed estimation.
 *
 * See pktpair.h for an overview.
 *
 * Measurement method
 * ------------------
 * For every sample (one per configured interval) and every target the
 * daemon supplies, N packet pairs are sent.  A pair is two ICMP echo
 * requests of identical size (the interface MTU) handed to the kernel
 * back-to-back.  When the pair crosses the narrowest link on the
 * round-trip path the second packet has to wait for the first one to be
 * serialized, so the replies come back separated by roughly
 *
 *	dispersion = packet_bits / bottleneck_bandwidth
 *
 * and therefore bandwidth = packet_bits / dispersion.  Cross traffic and
 * interrupt coalescing perturb individual pairs, so the per-sample
 * estimate is the median over all valid pairs, and a smoothed value
 * (EWMA, weight 1/4) is maintained across samples.
 *
 * RTT and jitter are computed from the first packet of each pair only
 * (the second one is delayed by the dispersion itself).  Jitter is the
 * mean absolute difference between consecutive RTTs (IPDV).
 *
 * Receive timestamps come from the kernel (SO_TIMESTAMPNS) so that the
 * dispersion is not affected by event-loop scheduling latency.
 *
 * Pairs to different targets are never sent concurrently: one pair is
 * sent per tick, rotating over the targets, so that replies of one pair
 * are not interleaved with probes towards another target.  The tick is
 * PKTPAIR_PAIR_GAP_MSEC, shortened when needed so that a sample over many
 * targets (an NHRP hub) still fits in the configured interval.
 *
 * One-way measurement
 * -------------------
 * Probes carry the sample id, the pair index and count, the sender's
 * interval and its transmit timestamp.  A receiving session times the
 * arrival of both packets of each pair; the gap between them is set by
 * the bottleneck in the sender -> receiver direction alone.  Once the
 * sample's last pair has arrived (or nothing more arrived for a second)
 * the receiver computes the median one-way bandwidth and the one-way
 * jitter (mean difference between consecutive one-way delays: the
 * unknown clock offset between the two hosts cancels out) and returns
 * them in a report: an ICMP echo reply with the prober's identifier and
 * a report payload, sent through the IP stack.
 */

#include <zebra.h>

#include <math.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#ifdef GNU_LINUX
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif

#include "pktpair.h"
#include "checksum.h"
#include "frrevent.h"
#include "if.h"
#include "jhash.h"
#include "json.h"
#include "log.h"
#include "memory.h"
#include "monotime.h"
#include "network.h"
#include "privs.h"
#include "sockopt.h"
#include "vty.h"

DEFINE_MTYPE_STATIC(LIB, PKTPAIR_SESSION, "Packet-pair session");
DEFINE_MTYPE_STATIC(LIB, PKTPAIR_TARGET, "Packet-pair target");
DEFINE_MTYPE_STATIC(LIB, PKTPAIR_ACTIVE, "Packet-pair active targets");
DEFINE_MTYPE_STATIC(LIB, PKTPAIR_INBOUND, "Packet-pair inbound sender");

#define PKTPAIR_MAGIC	       0x4f505052 /* "OPPR": probe          */
#define PKTPAIR_REPORT_MAGIC   0x4f505054 /* "OPPT": one-way report */
#define PKTPAIR_IP_HDR_LEN     20
#define PKTPAIR_PAIR_GAP_MSEC  50   /* between pairs within a sample */
#define PKTPAIR_TRAIN_GAP_MSEC 1000 /* between trains within a sample */
#define PKTPAIR_REPLY_WAIT_MSEC 1000 /* for the last replies */

/* Receiving side. */
#define PKTPAIR_INBOUND_MAX	   1024 /* senders tracked per session  */
#define PKTPAIR_INBOUND_IDLE_MSEC 1000 /* sample over after this gap   */
#define PKTPAIR_INBOUND_LAST_MSEC 100  /* ... or this after last pair  */
#define PKTPAIR_SWEEP_SEC	   10

/*
 * Wire formats, network byte order.  Every message starts with the magic
 * number and the version; nothing after them is interpreted unless the
 * version is PKTPAIR_VERSION.
 */
struct pktpair_hdr {
	uint32_t magic;
	uint8_t version;
};
#define PKTPAIR_HDR_LEN 5

/* Payload carried (and echoed back) in each probe. */
struct pktpair_payload {
	uint32_t magic;	   /* PKTPAIR_MAGIC          */
	uint8_t version;   /* PKTPAIR_VERSION        */
	uint8_t flags;	   /* reserved, 0            */
	uint16_t interval; /* sender's interval, s   */
	uint32_t sample_id;
	struct in_addr dst;
	uint8_t pair;	 /* pair/train index in the sample */
	uint8_t npairs;	 /* pairs/trains in this sample    */
	uint16_t which;	 /* packet index in the pair/train */
	uint16_t len;	 /* packets in the pair/train (2 = pair) */
	uint16_t skip;	 /* leading packets not timed      */
	uint32_t tx_sec; /* sender's transmit time */
	uint32_t tx_nsec;
};

/* Report sent back by a probed peer. */
struct pktpair_report {
	uint32_t magic;	  /* PKTPAIR_REPORT_MAGIC   */
	uint8_t version;  /* PKTPAIR_VERSION        */
	uint8_t rsvd;
	uint16_t pkt_size;
	uint32_t sample_id; /* the prober's sample   */
	struct in_addr dst; /* reporter's address, as probed */
	uint8_t npairs;
	uint8_t pairs_seen;
	uint8_t pairs_valid;
	uint8_t rsvd2;
	uint16_t pkts_rcvd;
	uint16_t train_len;
	uint32_t bw_kbps;
	uint32_t ipd_avg_usec;
	uint32_t jitter_usec;
};

/* The version must stay where every version's receiver looks for it. */
_Static_assert(offsetof(struct pktpair_payload, version) ==
		       offsetof(struct pktpair_hdr, version),
	       "probe version offset");
_Static_assert(offsetof(struct pktpair_report, version) ==
		       offsetof(struct pktpair_hdr, version),
	       "report version offset");
_Static_assert(offsetof(struct pktpair_hdr, version) + 1 == PKTPAIR_HDR_LEN,
	       "header length");
_Static_assert(sizeof(struct pktpair_payload) == 32, "probe payload size");
_Static_assert(sizeof(struct pktpair_report) == 36, "report payload size");

PREDECL_HASH(pktpair_inbound);

struct pktpair_inbound {
	struct pktpair_inbound_item item;
	struct pktpair_session *s;
	struct in_addr src;   /* the prober               */
	struct in_addr local; /* our address it probed    */

	/* Sample in progress. */
	uint16_t ident;
	uint32_t sample_id;
	uint8_t npairs;
	uint8_t tos;
	uint16_t pkt_size;
	uint16_t train_len;
	uint16_t interval;
	bool pending;
	struct pktpair_pair pairs[PKTPAIR_PROBES_MAX];
	struct event *t_done;

	struct timeval last_rx; /* monotonic */
	struct timeval first_rx; /* first arrival of this sample */
	uint8_t first_pair;	 /* its pair index                */
	struct pktpair_oneway stats;
};

static int pktpair_inbound_cmp(const struct pktpair_inbound *a,
			       const struct pktpair_inbound *b)
{
	return memcmp(&a->src, &b->src, sizeof(a->src));
}

static uint32_t pktpair_inbound_hash(const struct pktpair_inbound *in)
{
	return jhash_1word(in->src.s_addr, 0x5051);
}

DECLARE_HASH(pktpair_inbound, struct pktpair_inbound, item,
	     pktpair_inbound_cmp, pktpair_inbound_hash);

static int pktpair_target_cmp(const struct pktpair_target *a,
			      const struct pktpair_target *b)
{
	return memcmp(&a->dst, &b->dst, sizeof(a->dst));
}

static uint32_t pktpair_target_hash(const struct pktpair_target *t)
{
	return jhash_1word(t->dst.s_addr, 0x5050);
}

DECLARE_HASH(pktpair_targets, struct pktpair_target, item, pktpair_target_cmp,
	     pktpair_target_hash);

struct pktpair_session {
	struct event_loop *loop;
	struct zebra_privs_t *privs;
	struct interface *ifp;
	vrf_id_t vrf_id;
	struct pktpair_cfg cfg;
	const struct pktpair_ops *ops;
	void *arg;

	int fd;		       /* raw ICMP: stack tx (HDRINCL) and all rx */
	int pfd;	       /* AF_PACKET with PACKET_QDISC_BYPASS, -1  */
	const char *pfd_reason; /* why pfd is unavailable                  */

	uint16_t ident;
	uint16_t seq;
	uint32_t sample_id;

	/* Current sample. */
	uint8_t probes;
	uint8_t pair_idx;
	uint64_t sched_waits; /* sends deferred by the schedule */
	unsigned int cursor;
	unsigned int gap_msec;
	struct pktpair_target **active;
	unsigned int nactive;

	struct pktpair_targets_head targets;
	struct pktpair_inbound_head inbound;

	/* Messages from peers using another payload version. */
	uint64_t ver_mismatch;
	struct in_addr ver_last_src;
	uint8_t ver_last;
	struct timeval ver_last_time; /* monotonic */

	struct event *t_read;
	struct event *t_sample;
	struct event *t_pair;
	struct event *t_finish;
	struct event *t_sweep;

	/* Packets of a pair/train, built a batch at a time before sending. */
	uint8_t *txbuf;
	size_t txbuf_stride;
};

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static bool pp_debug(const struct pktpair_session *s)
{
	return s->ops->debug && s->ops->debug(s->arg);
}

static void pp_changed(struct pktpair_session *s, struct in_addr peer)
{
	if (s->ops->changed)
		s->ops->changed(s, peer, s->arg);
}

static int64_t ts_diff_ns(const struct timespec *a, const struct timespec *b)
{
	return (int64_t)(a->tv_sec - b->tv_sec) * 1000000000LL +
	       (a->tv_nsec - b->tv_nsec);
}

/* Fold the arrival of packet idx at ts into a pair/train. */
static void pp_train_arrival(struct pktpair_pair *pr, uint16_t idx,
			     const struct timespec *ts)
{
	if (idx < 2) {
		if (pr->seen01 & (1 << idx))
			return; /* duplicate */
		pr->seen01 |= 1 << idx;
		if (idx == 0)
			pr->rx0 = *ts;
	}
	pr->rcvd++;
	if (idx >= pr->skip) {
		if (!pr->steady || ts_diff_ns(ts, &pr->rx_a) < 0)
			pr->rx_a = *ts;
		if (!pr->steady || ts_diff_ns(ts, &pr->rx_b) > 0)
			pr->rx_b = *ts;
		pr->steady++;
	}
}

/*
 * Rate of a pair/train in kbit/s, 0 if it cannot be timed: the packets
 * after the first timed one, over the time to the last.  Lost packets in
 * between are not counted, so loss can only lower the result.
 */
static uint64_t pp_train_kbps(const struct pktpair_pair *pr, uint16_t size,
			      int64_t *span_ns)
{
	int64_t dt;

	if (pr->steady < 2)
		return 0;
	dt = ts_diff_ns(&pr->rx_b, &pr->rx_a);
	if (dt <= 0)
		return 0;
	*span_ns = dt;
	return (uint64_t)(pr->steady - 1) * size * 8ULL * 1000000ULL /
	       (uint64_t)dt;
}

uint32_t pktpair_sched_delay(uint64_t now_ms, const struct pktpair_sched_cfg *c,
			     uint32_t dur_ms)
{
	uint64_t phase;

	if (!c->period_ms || dur_ms + 2ULL * c->guard_ms >= c->period_ms)
		return 0;
	/* ms since the last boundary */
	phase = (now_ms + c->period_ms - c->offset_ms % c->period_ms) %
		c->period_ms;
	if (phase < c->guard_ms)
		return c->guard_ms - phase;
	if (phase + dur_ms + c->guard_ms > c->period_ms)
		return c->period_ms - phase + c->guard_ms;
	return 0;
}

static uint16_t pp_pkt_size(const struct pktpair_session *s)
{
	unsigned int mtu = s->ifp->mtu;

	if (mtu == 0)
		mtu = PKTPAIR_PKT_DEFAULT;
	if (mtu > PKTPAIR_PKT_MAX)
		mtu = PKTPAIR_PKT_MAX;
	if (mtu < PKTPAIR_PKT_MIN)
		mtu = PKTPAIR_PKT_MIN;
	return mtu;
}

static int uint64_cmp(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return (x > y) - (x < y);
}

/* ------------------------------------------------------------------ */
/* Smoothing                                                          */
/* ------------------------------------------------------------------ */

uint64_t pktpair_smooth_update(struct pktpair_smoother *sm,
			       const struct pktpair_smooth_cfg *cfg,
			       uint64_t sample_kbps)
{
	if (cfg->window >= 2) {
		uint64_t v[PKTPAIR_SMOOTH_WINDOW_MAX];
		unsigned int n, k, pct, w = MIN(cfg->window,
						PKTPAIR_SMOOTH_WINDOW_MAX);

		if (sample_kbps) {
			sm->hist[sm->pos] = sample_kbps;
			sm->pos = (sm->pos + 1) % PKTPAIR_SMOOTH_WINDOW_MAX;
			if (sm->nhist < PKTPAIR_SMOOTH_WINDOW_MAX)
				sm->nhist++;
		}
		n = MIN(sm->nhist, w);
		if (!n)
			return 0;
		for (k = 0; k < n; k++)
			v[k] = sm->hist[(sm->pos + PKTPAIR_SMOOTH_WINDOW_MAX -
					 1 - k) %
					PKTPAIR_SMOOTH_WINDOW_MAX];
		qsort(v, n, sizeof(v[0]), uint64_cmp);
		pct = cfg->percentile ? cfg->percentile
				      : PKTPAIR_SMOOTH_PERCENTILE_DEFAULT;
		/* nearest rank */
		pct = MIN(pct, 100U);
		k = (pct * n + 99) / 100;
		return v[k ? k - 1 : 0];
	}

	double x, w, ratio, limit;
	int8_t dir;

	if (sample_kbps == 0)
		return sm->inv > 0 ? (uint64_t)(1.0 / sm->inv + 0.5) : 0;

	x = 1.0 / (double)sample_kbps;
	w = (cfg->weight ? MIN(cfg->weight, 100) : PKTPAIR_SMOOTH_WEIGHT_DEFAULT) /
	    100.0;

	if (sm->inv <= 0) {
		/* First sample. */
		sm->inv = x;
		goto out;
	}

	/*
	 * Step detection, symmetric in ratio: with a 30% threshold a sample
	 * deviates when it is 1.3 times faster or slower than the average.
	 */
	if (cfg->step_threshold) {
		ratio = sm->inv / x; /* sample / smoothed */
		limit = 1.0 + cfg->step_threshold / 100.0;
		dir = ratio > limit ? 1 : (ratio < 1.0 / limit ? -1 : 0);

		if (dir == 0 || dir != sm->step_dir) {
			sm->step_count = 0;
			sm->step_inv_sum = 0;
			sm->step_dir = dir;
		}
		if (dir) {
			sm->step_count++;
			sm->step_inv_sum += x;
			if (sm->step_count >=
			    MAX(cfg->step_samples, PKTPAIR_STEP_SAMPLES_MIN)) {
				/* Sustained change: restart from it. */
				sm->inv = sm->step_inv_sum / sm->step_count;
				sm->step_count = 0;
				sm->step_inv_sum = 0;
				sm->step_dir = 0;
				sm->resets++;
				goto out;
			}
		}
	}

	sm->inv = (1.0 - w) * sm->inv + w * x;
out:
	return (uint64_t)(1.0 / sm->inv + 0.5);
}

/* ------------------------------------------------------------------ */
/* Loss                                                               */
/* ------------------------------------------------------------------ */

void pktpair_loss_update(struct pktpair_loss *l,
			 const struct pktpair_loss_cfg *cfg, unsigned int sent,
			 unsigned int lost, bool valid)
{
	double w, f;

	if (valid)
		l->empty_run = 0;
	else if (l->empty_run < UINT8_MAX)
		l->empty_run++;

	if (sent == 0)
		return;
	if (lost > sent)
		lost = sent;
	l->last_sent = MIN(sent, UINT16_MAX);
	l->last_lost = MIN(lost, UINT16_MAX);
	l->pkts_sent += sent;
	l->pkts_lost += lost;

	f = (double)lost / sent;
	w = (cfg->weight ? cfg->weight : PKTPAIR_LOSS_WEIGHT_DEFAULT) / 100.0;
	if (l->samples == 0)
		l->rate = f;
	else
		l->rate += w * (f - l->rate);
	l->samples++;
}

uint64_t pktpair_loss_adjust(uint64_t kbps, double loss, uint32_t rtt_usec,
			     uint16_t pkt_size, enum pktpair_loss_adjust mode)
{
	double tcp;
	unsigned int mss;

	if (kbps == 0 || loss <= 0 || mode == PKTPAIR_LOSS_ADJUST_NONE)
		return kbps;
	if (loss >= 1)
		return 0;

	if (mode == PKTPAIR_LOSS_ADJUST_TCP && rtt_usec) {
		/* MSS / RTT * 1.22 / sqrt(p); bits per usec = Mbit/s. */
		mss = pkt_size > 40 ? pkt_size - 40 : PKTPAIR_PKT_DEFAULT - 40;
		tcp = (double)mss * 8.0 / rtt_usec * 1000.0 * 1.22 / sqrt(loss);
		return tcp < (double)kbps ? (uint64_t)tcp : kbps;
	}

	return (uint64_t)((double)kbps * (1.0 - loss) + 0.5);
}

const char *pktpair_loss_adjust_str(enum pktpair_loss_adjust mode)
{
	switch (mode) {
	case PKTPAIR_LOSS_ADJUST_DELIVERY:
		return "delivery";
	case PKTPAIR_LOSS_ADJUST_TCP:
		return "tcp";
	case PKTPAIR_LOSS_ADJUST_NONE:
		break;
	}
	return "none";
}

/* ------------------------------------------------------------------ */
/* Sample evaluation                                                  */
/* ------------------------------------------------------------------ */

static void pp_target_finalize(struct pktpair_session *s,
			       struct pktpair_target *t)
{
	struct pktpair_stats *st = &t->stats;
	uint64_t bw[PKTPAIR_PROBES_MAX], best = 0;
	uint64_t rtt_sum = 0, ipd_sum = 0, jit_sum = 0;
	int64_t prev_rtt = -1, best_span = 0;
	uint32_t rtt_min = UINT32_MAX, rtt_max = 0;
	unsigned int nrtt = 0, nbw = 0, njit = 0, sent = 0, lost = 0;
	unsigned int pkts_sent = 0;
	unsigned int i;

	if (t->npairs == 0)
		return;

	for (i = 0; i < t->npairs; i++) {
		struct pktpair_pair *pr = &t->pairs[i];
		int64_t span = 0;
		uint64_t kbps;

		if (pr->sent == 0)
			continue;
		sent++;
		pkts_sent += pr->sent;
		lost += pr->sent - MIN(pr->rcvd, pr->sent);

		/* RTT and jitter from the leading packet. */
		if (pr->seen01 & 0x1) {
			int64_t rtt = ts_diff_ns(&pr->rx0, &pr->tx0) / 1000;

			if (rtt >= 0) {
				rtt_sum += rtt;
				if (rtt < rtt_min)
					rtt_min = rtt;
				if (rtt > rtt_max)
					rtt_max = rtt;
				nrtt++;
				if (prev_rtt >= 0) {
					jit_sum += llabs(rtt - prev_rtt);
					njit++;
				}
				prev_rtt = rtt;
			}
		}

		/* Dispersion of the replies. */
		kbps = pp_train_kbps(pr, t->pkt_size, &span);
		if (kbps) {
			ipd_sum += span / (pr->steady - 1);
			bw[nbw++] = kbps;
			if (kbps > best) {
				best = kbps;
				best_span = span;
			}
		}
	}

	/* Mark the sample consumed so late replies are ignored. */
	t->npairs = 0;

	/* Forget the peer's report once it stops sending them. */
	if (t->outbound.samples &&
	    monotime_since(&t->outbound.last_update, NULL) >
		    (int64_t)(3 * s->cfg.interval + 2) * 1000000)
		memset(&t->outbound, 0, sizeof(t->outbound));

	if (sent == 0) {
		pp_changed(s, t->dst);
		return;
	}

	st->pkt_size = t->pkt_size;
	st->train_len = t->train_len;
	st->tx = t->tx;
	st->pairs_sent = sent;
	st->pairs_valid = nbw;
	st->pkts_lost = lost;
	pktpair_loss_update(&st->loss, &s->cfg.loss, pkts_sent, lost, nbw > 0);

	if (nrtt) {
		st->rtt_min_usec = rtt_min;
		st->rtt_max_usec = rtt_max;
		st->rtt_avg_usec = rtt_sum / nrtt;
		st->jitter_usec = njit ? jit_sum / njit : 0;
	} else {
		st->rtt_min_usec = st->rtt_avg_usec = st->rtt_max_usec = 0;
		st->jitter_usec = 0;
	}

	if (nbw) {
		qsort(bw, nbw, sizeof(bw[0]), uint64_cmp);
		/* Pairs: the median.  Trains: the fastest. */
		if (t->train_len > 2)
			st->bw_kbps = best;
		else
			st->bw_kbps = (nbw & 1) ? bw[nbw / 2]
						: (bw[nbw / 2 - 1] + bw[nbw / 2]) /
							  2;
		st->span_usec = best_span / 1000;
		st->ipd_avg_usec = ipd_sum / nbw / 1000;
		st->bw_smooth_kbps = pktpair_smooth_update(
			&st->smoother, &s->cfg.smooth, st->bw_kbps);
	} else {
		st->bw_kbps = 0;
		st->ipd_avg_usec = 0;
		st->span_usec = 0;
	}

	monotime(&st->last_update);
	t->samples++;

	if (pp_debug(s))
		zlog_debug("packet-pair %s: %pI4 via %s: rtt %u/%u/%u us, jitter %u us, ipd %u us, bw %" PRIu64
			   " kbps (%u/%u pairs, %u lost)",
			   s->ifp->name, &t->dst, st->tx.path,
			   st->rtt_min_usec, st->rtt_avg_usec,
			   st->rtt_max_usec, st->jitter_usec, st->ipd_avg_usec,
			   st->bw_kbps, st->pairs_valid, st->pairs_sent,
			   st->pkts_lost);

	pp_changed(s, t->dst);
}

static void pp_finish_timer(struct event *thread)
{
	struct pktpair_session *s = EVENT_ARG(thread);
	unsigned int i;

	for (i = 0; i < s->nactive; i++)
		pp_target_finalize(s, s->active[i]);
}

/* ------------------------------------------------------------------ */
/* Transmit                                                           */
/* ------------------------------------------------------------------ */

/* Build the inner IPv4 + ICMP echo probe at buf. */
static void pp_build_probe(struct pktpair_session *s, struct pktpair_target *t,
			   uint8_t *buf, uint16_t ip_len, uint8_t pair,
			   uint16_t which, const struct timespec *tx_ts)
{
	struct ip *iph = (struct ip *)buf;
	struct icmphdr *icmp = (struct icmphdr *)(buf + PKTPAIR_IP_HDR_LEN);
	struct pktpair_payload *pl =
		(struct pktpair_payload *)((uint8_t *)icmp + sizeof(*icmp));
	size_t icmp_len = ip_len - PKTPAIR_IP_HDR_LEN;

	memset(buf, 0, ip_len);

	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = htons(s->ident);
	icmp->un.echo.sequence = htons(s->seq);
	pl->magic = htonl(PKTPAIR_MAGIC);
	pl->version = PKTPAIR_VERSION;
	pl->sample_id = htonl(s->sample_id);
	pl->dst = t->dst;
	pl->pair = pair;
	pl->npairs = t->npairs;
	pl->which = htons(which);
	pl->len = htons(t->pairs[pair].len);
	pl->skip = htons(t->pairs[pair].skip);
	pl->interval = htons(s->cfg.interval);
	pl->tx_sec = htonl((uint32_t)tx_ts->tv_sec);
	pl->tx_nsec = htonl((uint32_t)tx_ts->tv_nsec);
	icmp->checksum = in_cksum(icmp, icmp_len);

	iph->ip_v = IPVERSION;
	iph->ip_hl = PKTPAIR_IP_HDR_LEN >> 2;
	iph->ip_tos = s->cfg.dscp << 2;
	iph->ip_len = htons(ip_len);
	iph->ip_id = htons(s->seq);
	iph->ip_off = htons(IP_DF);
	iph->ip_ttl = IPDEFTTL;
	iph->ip_p = IPPROTO_ICMP;
	iph->ip_src = t->tx.src;
	iph->ip_dst = t->dst;
	iph->ip_sum = in_cksum(iph, PKTPAIR_IP_HDR_LEN);

	s->seq++;
}

#define PKTPAIR_TX_BATCH 32

/*
 * Send a pair or train.  Packets are built a batch at a time and handed
 * to the kernel in one sendmmsg() call per batch, so nothing runs between
 * the packets of a batch: building and checksumming each packet after the
 * previous one had left put 15-75us between them, more than the gap being
 * measured on a fast link (12us for 1500 bytes at 1 Gbit/s).  A train
 * stops early if the socket or driver queue is full; unsent packets count
 * as neither sent nor lost.
 */
static void pp_send_pair(struct pktpair_session *s, struct pktpair_target *t,
			 uint8_t idx)
{
	struct pktpair_pair *pr = &t->pairs[idx];
	struct pktpair_tx *tx = &t->tx;
	uint16_t ip_len = t->pkt_size;
	struct mmsghdr msgs[PKTPAIR_TX_BATCH];
	struct iovec iov[PKTPAIR_TX_BATCH];
	struct sockaddr_in to = {};
#ifdef PACKET_QDISC_BYPASS
	struct sockaddr_ll sll = {};
#endif
	size_t off = 0, stride;
	void *name;
	socklen_t namelen;
	struct timespec now;
	int fd, i, n, ret = 0;

#ifdef PACKET_QDISC_BYPASS
	if (tx->mode == PKTPAIR_TX_BYPASS) {
		sll.sll_family = AF_PACKET;
		sll.sll_protocol = htons(tx->protocol);
		sll.sll_ifindex = tx->ifindex;
		sll.sll_halen = tx->halen;
		memcpy(sll.sll_addr, tx->lladdr, tx->halen);
		fd = s->pfd;
		off = tx->encap_len;
		name = &sll;
		namelen = sizeof(sll);
	} else
#endif
	{
		to.sin_family = AF_INET;
		to.sin_addr = t->dst;
		fd = s->fd;
		name = &to;
		namelen = sizeof(to);
	}

	stride = off + ip_len;
	if (s->txbuf_stride < stride) {
		XFREE(MTYPE_TMP, s->txbuf);
		s->txbuf = XMALLOC(MTYPE_TMP, PKTPAIR_TX_BATCH * stride);
		s->txbuf_stride = stride;
	}
	stride = s->txbuf_stride;

	clock_gettime(CLOCK_REALTIME, &pr->tx0);
	now = pr->tx0;
	while (pr->sent < pr->len) {
		n = MIN(pr->len - pr->sent, PKTPAIR_TX_BATCH);
		memset(msgs, 0, sizeof(msgs[0]) * n);
		for (i = 0; i < n; i++) {
			uint8_t *b = s->txbuf + i * stride;

			if (off)
				memcpy(b, tx->encap, off);
			pp_build_probe(s, t, b + off, ip_len, idx,
				       pr->sent + i, &now);
			iov[i].iov_base = b;
			iov[i].iov_len = off + ip_len;
			msgs[i].msg_hdr.msg_iov = &iov[i];
			msgs[i].msg_hdr.msg_iovlen = 1;
			msgs[i].msg_hdr.msg_name = name;
			msgs[i].msg_hdr.msg_namelen = namelen;
		}
		ret = sendmmsg(fd, msgs, n, MSG_DONTWAIT);
		if (ret > 0)
			pr->sent += ret;
		if (ret < n)
			break;
		clock_gettime(CLOCK_REALTIME, &now);
	}
	if (pr->sent < pr->len && pp_debug(s))
		zlog_debug("packet-pair %s: send to %pI4 via %s: %u of %u sent: %s",
			   s->ifp->name, &t->dst, tx->path, pr->sent, pr->len,
			   ret < 0 ? safe_strerror(errno) : "queue full");
}

/* How long a pair/train to t is in flight, for the schedule. */
static uint32_t pp_flight_ms(const struct pktpair_session *s,
			     const struct pktpair_target *t)
{
	uint32_t ms = t->stats.rtt_avg_usec / 1000 + 1;

	if (t->train_len > 2)
		ms += s->cfg.train.span_ms;
	return ms;
}

static void pp_pair_timer(struct event *thread)
{
	struct pktpair_session *s = EVENT_ARG(thread);

	if (s->cursor >= s->nactive) {
		/* Went round all targets: next pair index. */
		s->cursor = 0;
		s->pair_idx++;
		if (s->pair_idx >= s->probes) {
			event_add_timer_msec(s->loop, pp_finish_timer, s,
					     PKTPAIR_REPLY_WAIT_MSEC,
					     &s->t_finish);
			return;
		}
	}

	if (s->cfg.sched.period_ms) {
		struct timespec now;
		uint32_t delay;

		clock_gettime(CLOCK_REALTIME, &now);
		delay = pktpair_sched_delay((uint64_t)now.tv_sec * 1000 +
						    now.tv_nsec / 1000000,
					    &s->cfg.sched,
					    pp_flight_ms(s, s->active[s->cursor]));
		if (delay) {
			s->sched_waits++;
			event_add_timer_msec(s->loop, pp_pair_timer, s, delay,
					     &s->t_pair);
			return;
		}
	}

	pp_send_pair(s, s->active[s->cursor++], s->pair_idx);

	event_add_timer_msec(s->loop, pp_pair_timer, s, s->gap_msec,
			     &s->t_pair);
}

static void pp_target_free(struct pktpair_target *t)
{
	XFREE(MTYPE_PKTPAIR_TARGET, t);
}

void pktpair_target_add(struct pktpair_session *s, struct in_addr dst)
{
	struct pktpair_target key = { .dst = dst }, *t;

	if (dst.s_addr == INADDR_ANY)
		return;

	t = pktpair_targets_find(&s->targets, &key);
	if (!t) {
		t = XCALLOC(MTYPE_PKTPAIR_TARGET, sizeof(*t));
		t->dst = dst;
		pktpair_targets_add(&s->targets, t);
	}
	t->seen = true;
}

/*
 * Packets per pair/train: 2 for pairs; for trains, enough to take
 * span_ms at the current estimate (the outbound one-way result if the
 * target reports one, else the round-trip one).
 */
static uint16_t pp_train_len(const struct pktpair_session *s,
			     const struct pktpair_target *t, uint16_t size)
{
	const struct pktpair_train_cfg *c = &s->cfg.train;
	uint64_t est = 0, len;
	uint16_t max = c->max_len ? c->max_len : PKTPAIR_TRAIN_MAXLEN_DEFAULT;

	if (!c->span_ms)
		return 2;
	if (t->outbound.samples && t->outbound.bw_smooth_kbps)
		est = t->outbound.bw_smooth_kbps;
	else if (t->samples && t->stats.bw_smooth_kbps)
		est = t->stats.bw_smooth_kbps;
	if (!est)
		return MIN(4 * PKTPAIR_TRAIN_LEN_MIN, max);
	/* kbit/s * ms = bit */
	len = est * c->span_ms / (size * 8ULL) + 1;
	len = MAX(len, PKTPAIR_TRAIN_LEN_MIN);
	len = MIN(len, max);
	return len;
}

static void pp_sample_timer(struct event *thread)
{
	struct pktpair_session *s = EVENT_ARG(thread);
	struct pktpair_target *t;
	unsigned int count, budget_msec, i;
	uint16_t size = pp_pkt_size(s);

	/* A previous sample is still running: skip this round. */
	if (event_is_scheduled(s->t_pair) || event_is_scheduled(s->t_finish)) {
		event_add_timer(s->loop, pp_sample_timer, s, s->cfg.interval,
				&s->t_sample);
		return;
	}

	XFREE(MTYPE_PKTPAIR_ACTIVE, s->active);
	s->nactive = 0;

	/* Refresh the target set from the daemon. */
	frr_each (pktpair_targets, &s->targets, t)
		t->seen = false;
	s->ops->collect(s, s->arg);
	frr_each_safe (pktpair_targets, &s->targets, t) {
		if (!t->seen) {
			struct in_addr dst = t->dst;

			pktpair_targets_del(&s->targets, t);
			pp_target_free(t);
			pp_changed(s, dst);
		}
	}

	s->sample_id++;
	s->pair_idx = 0;
	s->cursor = 0;
	s->probes = s->cfg.train.span_ms
			    ? (s->cfg.train.count ? s->cfg.train.count
						  : PKTPAIR_TRAIN_COUNT_DEFAULT)
			    : s->cfg.probes;

	count = pktpair_targets_count(&s->targets);
	if (count)
		s->active = XCALLOC(MTYPE_PKTPAIR_ACTIVE,
				    count * sizeof(*s->active));

	frr_each (pktpair_targets, &s->targets, t) {
		struct pktpair_tx tx = {};

		t->npairs = 0;
		if (!s->ops->prepare(s, t, &tx, size, s->arg))
			continue;
		t->tx = tx;
		memset(t->pairs, 0, sizeof(t->pairs));
		t->prev_sample_id = t->sample_id;
		t->sample_id = s->sample_id;
		t->npairs = s->probes;
		t->pkt_size = size;
		t->train_len = pp_train_len(s, t, size);
		for (i = 0; i < t->npairs; i++) {
			t->pairs[i].len = t->train_len;
			t->pairs[i].skip =
				t->train_len > 2
					? MIN(t->train_len *
						      s->cfg.train.skip_pct / 100,
					      t->train_len - 2)
					: 0;
		}
		s->active[s->nactive++] = t;
	}

	if (s->nactive == 0) {
		/* Nothing to probe yet: retry soon, not a full interval. */
		event_add_timer(s->loop, pp_sample_timer, s,
				MIN(s->cfg.interval, 5U), &s->t_sample);
		return;
	}

	/*
	 * Spread the pairs so the whole sample takes at most 3/4 of the
	 * interval, but never send them closer than 1 ms apart.
	 */
	budget_msec = s->cfg.interval * 750;
	s->gap_msec = budget_msec / (s->probes * s->nactive);
	s->gap_msec = MIN(s->gap_msec, s->cfg.train.span_ms
					       ? PKTPAIR_TRAIN_GAP_MSEC
					       : PKTPAIR_PAIR_GAP_MSEC);
	s->gap_msec = MAX(s->gap_msec, 1U);

	event_add_timer_msec(s->loop, pp_pair_timer, s, 0, &s->t_pair);
	event_add_timer(s->loop, pp_sample_timer, s, s->cfg.interval,
			&s->t_sample);
}

/* ------------------------------------------------------------------ */
/* Receive                                                            */
/* ------------------------------------------------------------------ */

/* Reply from a target to one of our probes. */
static void pp_handle_reply(struct pktpair_session *s, struct ip *iph,
			    const struct pktpair_payload *pl,
			    const struct timespec *rx_ts)
{
	struct pktpair_target key = {}, *t;
	struct pktpair_pair *pr;
	uint16_t which = ntohs(pl->which);

	if (pl->pair >= PKTPAIR_PROBES_MAX ||
	    !IPV4_ADDR_SAME(&pl->dst, &iph->ip_src))
		return;

	key.dst = iph->ip_src;
	t = pktpair_targets_find(&s->targets, &key);
	if (!t || t->sample_id != ntohl(pl->sample_id) || pl->pair >= t->npairs)
		return;

	pr = &t->pairs[pl->pair];
	if (which >= pr->sent)
		return;

	pp_train_arrival(pr, which, rx_ts);
}

/* A target's report of how our probes arrived: our outbound direction. */
static void pp_handle_report(struct pktpair_session *s, struct ip *iph,
			     const struct pktpair_report *rp)
{
	struct pktpair_target key = {}, *t;
	struct pktpair_oneway *ow;
	uint32_t sample_id = ntohl(rp->sample_id);

	if (!IPV4_ADDR_SAME(&rp->dst, &iph->ip_src))
		return;
	key.dst = iph->ip_src;
	t = pktpair_targets_find(&s->targets, &key);
	/*
	 * Only for the sample just sent, or the one before it: when the end
	 * of a sample is lost, the peer reports only after a timeout, which
	 * can be after our next sample started.  Dropping those reports
	 * would hide exactly the lossy samples.  Each sample counts once,
	 * and never after a newer one.
	 */
	if (!t ||
	    (t->sample_id != sample_id &&
	     (t->prev_sample_id == 0 || t->prev_sample_id != sample_id)) ||
	    (t->outbound.samples &&
	     (int32_t)(sample_id - t->outbound_sample_id) <= 0))
		return;

	ow = &t->outbound;
	t->outbound_sample_id = sample_id;
	ow->npairs = rp->npairs;
	ow->pairs_seen = rp->pairs_seen;
	ow->pairs_valid = rp->pairs_valid;
	ow->pkts_rcvd = ntohs(rp->pkts_rcvd);
	ow->train_len = MAX(ntohs(rp->train_len), 2);
	ow->pkt_size = ntohs(rp->pkt_size);
	ow->bw_kbps = ntohl(rp->bw_kbps);
	ow->ipd_avg_usec = ntohl(rp->ipd_avg_usec);
	ow->jitter_usec = ntohl(rp->jitter_usec);
	if (ow->pairs_valid) {
		ow->bw_smooth_kbps = pktpair_smooth_update(
			&ow->smoother, &s->cfg.smooth, ow->bw_kbps);
	}
	pktpair_loss_update(&ow->loss, &s->cfg.loss,
			    ow->npairs * ow->train_len,
			    ow->npairs * ow->train_len -
				    MIN(ow->pkts_rcvd,
					ow->npairs * ow->train_len),
			    ow->pairs_valid > 0);
	ow->samples++;
	monotime(&ow->last_update);

	if (pp_debug(s))
		zlog_debug("packet-pair %s: %pI4 reports outbound %" PRIu64
			   " kbps, jitter %u us (%u/%u pairs)",
			   s->ifp->name, &t->dst, ow->bw_kbps, ow->jitter_usec,
			   ow->pairs_valid, ow->npairs);

	pp_changed(s, t->dst);
}

/* Tell the prober how its sample arrived. */
static void pp_send_report(struct pktpair_session *s,
			   struct pktpair_inbound *in)
{
	uint8_t buf[PKTPAIR_IP_HDR_LEN + sizeof(struct icmphdr) +
		    sizeof(struct pktpair_report)] = {};
	struct ip *iph = (struct ip *)buf;
	struct icmphdr *icmp = (struct icmphdr *)(buf + PKTPAIR_IP_HDR_LEN);
	struct pktpair_report *rp =
		(struct pktpair_report *)((uint8_t *)icmp + sizeof(*icmp));
	const struct pktpair_oneway *ow = &in->stats;
	struct sockaddr_in to = {};

	icmp->type = ICMP_ECHOREPLY;
	icmp->code = 0;
	icmp->un.echo.id = htons(in->ident);
	icmp->un.echo.sequence = 0;
	rp->magic = htonl(PKTPAIR_REPORT_MAGIC);
	rp->version = PKTPAIR_VERSION;
	rp->sample_id = htonl(in->sample_id);
	rp->dst = in->local;
	rp->pkt_size = htons(ow->pkt_size);
	rp->npairs = ow->npairs;
	rp->pairs_seen = ow->pairs_seen;
	rp->pairs_valid = ow->pairs_valid;
	rp->pkts_rcvd = htons(ow->pkts_rcvd);
	rp->train_len = htons(ow->train_len);
	rp->bw_kbps = htonl(MIN(ow->bw_kbps, UINT32_MAX));
	rp->ipd_avg_usec = htonl(ow->ipd_avg_usec);
	rp->jitter_usec = htonl(ow->jitter_usec);
	icmp->checksum = in_cksum(icmp, sizeof(*icmp) + sizeof(*rp));

	iph->ip_v = IPVERSION;
	iph->ip_hl = PKTPAIR_IP_HDR_LEN >> 2;
	iph->ip_tos = in->tos; /* same class as the probes */
	iph->ip_len = htons(sizeof(buf));
	iph->ip_ttl = IPDEFTTL;
	iph->ip_p = IPPROTO_ICMP;
	iph->ip_src = in->local;
	iph->ip_dst = in->src;
	iph->ip_sum = in_cksum(iph, PKTPAIR_IP_HDR_LEN);

	to.sin_family = AF_INET;
	to.sin_addr = in->src;
	if (sendto(s->fd, buf, sizeof(buf), 0, (struct sockaddr *)&to,
		   sizeof(to)) < 0 &&
	    pp_debug(s))
		zlog_debug("packet-pair %s: report to %pI4: %s", s->ifp->name,
			   &in->src, safe_strerror(errno));
}

/* The sender's sample is over: evaluate it and report back. */
static void pp_inbound_finalize(struct pktpair_session *s,
				struct pktpair_inbound *in)
{
	struct pktpair_oneway *ow = &in->stats;
	uint64_t bw[PKTPAIR_PROBES_MAX], best = 0;
	uint64_t ipd_sum = 0, jit_sum = 0;
	unsigned int expect = in->npairs * in->train_len;
	int64_t prev_owd = 0;
	bool have_prev = false;
	unsigned int i, seen = 0, rcvd = 0, nbw = 0, njit = 0;

	event_cancel(&in->t_done);
	if (!in->pending)
		return;
	in->pending = false;

	for (i = 0; i < in->npairs; i++) {
		struct pktpair_pair *pr = &in->pairs[i];
		int64_t span = 0;
		uint64_t kbps;

		if (!pr->rcvd)
			continue;
		seen++;
		rcvd += pr->rcvd;

		/*
		 * One-way delay includes the unknown clock offset between
		 * the hosts; its variation from pair to pair does not.
		 */
		if (pr->seen01 & 0x1) {
			int64_t owd = ts_diff_ns(&pr->rx0, &pr->tx0);

			if (have_prev) {
				jit_sum += llabs(owd - prev_owd);
				njit++;
			}
			prev_owd = owd;
			have_prev = true;
		}

		kbps = pp_train_kbps(pr, in->pkt_size, &span);
		if (kbps) {
			ipd_sum += span / (pr->steady - 1);
			bw[nbw++] = kbps;
			best = MAX(best, kbps);
		}
	}

	ow->pkt_size = in->pkt_size;
	ow->npairs = in->npairs;
	ow->pairs_seen = seen;
	ow->pairs_valid = nbw;
	ow->pkts_rcvd = MIN(rcvd, UINT16_MAX);
	ow->train_len = in->train_len;
	ow->jitter_usec = njit ? jit_sum / njit / 1000 : 0;
	if (nbw) {
		qsort(bw, nbw, sizeof(bw[0]), uint64_cmp);
		if (in->train_len > 2)
			ow->bw_kbps = best;
		else
			ow->bw_kbps = (nbw & 1) ? bw[nbw / 2]
						: (bw[nbw / 2 - 1] + bw[nbw / 2]) /
							  2;
		ow->ipd_avg_usec = ipd_sum / nbw / 1000;
		ow->bw_smooth_kbps = pktpair_smooth_update(
			&ow->smoother, &s->cfg.smooth, ow->bw_kbps);
	} else {
		ow->bw_kbps = 0;
		ow->ipd_avg_usec = 0;
	}
	pktpair_loss_update(&ow->loss, &s->cfg.loss, expect,
			    expect - MIN(rcvd, expect), nbw > 0);
	ow->samples++;
	monotime(&ow->last_update);

	if (pp_debug(s))
		zlog_debug("packet-pair %s: inbound from %pI4: %" PRIu64
			   " kbps, jitter %u us (%u/%u pairs, %u pkts)",
			   s->ifp->name, &in->src, ow->bw_kbps,
			   ow->jitter_usec, nbw, in->npairs, rcvd);

	pp_send_report(s, in);
	pp_changed(s, in->src);
}

static void pp_inbound_done(struct event *thread)
{
	struct pktpair_inbound *in = EVENT_ARG(thread);

	pp_inbound_finalize(in->s, in);
}

static void pp_inbound_free(struct pktpair_inbound *in)
{
	event_cancel(&in->t_done);
	XFREE(MTYPE_PKTPAIR_INBOUND, in);
}

/* Drop senders that stopped probing us. */
static void pp_sweep_timer(struct event *thread)
{
	struct pktpair_session *s = EVENT_ARG(thread);
	struct pktpair_inbound *in;

	frr_each_safe (pktpair_inbound, &s->inbound, in) {
		int64_t idle = monotime_since(&in->last_rx, NULL) / 1000000;

		if (!in->pending &&
		    idle > 3 * MAX(in->interval, 1) + PKTPAIR_SWEEP_SEC) {
			struct in_addr src = in->src;

			pktpair_inbound_del(&s->inbound, in);
			pp_inbound_free(in);
			pp_changed(s, src);
		}
	}
	if (pktpair_inbound_count(&s->inbound))
		event_add_timer(s->loop, pp_sweep_timer, s, PKTPAIR_SWEEP_SEC,
				&s->t_sweep);
}

/* A probe from a peer: we are the measured end. */
static void pp_handle_probe(struct pktpair_session *s, struct ip *iph,
			    struct icmphdr *icmp,
			    const struct pktpair_payload *pl, size_t ip_len,
			    const struct timespec *rx_ts)
{
	struct pktpair_inbound key = {}, *in;
	struct pktpair_pair *pr;
	uint32_t sample_id = ntohl(pl->sample_id);
	uint16_t ident = ntohs(icmp->un.echo.id);
	uint16_t which = ntohs(pl->which), len = ntohs(pl->len),
		 skip = ntohs(pl->skip);
	int64_t wait;
	bool last;

	if (len < 2 || len > PKTPAIR_TRAIN_LEN_MAX || which >= len ||
	    skip > len - 2 || pl->npairs == 0 ||
	    pl->npairs > PKTPAIR_PROBES_MAX || pl->pair >= pl->npairs ||
	    !IPV4_ADDR_SAME(&pl->dst, &iph->ip_dst))
		return;

	key.src = iph->ip_src;
	in = pktpair_inbound_find(&s->inbound, &key);
	if (!in) {
		if (s->ops->accept && !s->ops->accept(s, iph->ip_src, s->arg))
			return;
		if (pktpair_inbound_count(&s->inbound) >= PKTPAIR_INBOUND_MAX)
			return;
		in = XCALLOC(MTYPE_PKTPAIR_INBOUND, sizeof(*in));
		in->s = s;
		in->src = iph->ip_src;
		pktpair_inbound_add(&s->inbound, in);
		if (!event_is_scheduled(s->t_sweep))
			event_add_timer(s->loop, pp_sweep_timer, s,
					PKTPAIR_SWEEP_SEC, &s->t_sweep);
	}

	if (!in->pending || in->ident != ident || in->sample_id != sample_id) {
		/* A new sample: close the previous one first. */
		if (in->pending)
			pp_inbound_finalize(s, in);
		else if (in->stats.samples && in->ident == ident &&
			 in->sample_id == sample_id)
			return; /* straggler from a sample already reported */
		memset(in->pairs, 0, sizeof(in->pairs));
		in->ident = ident;
		in->sample_id = sample_id;
		in->npairs = pl->npairs;
		in->train_len = len;
		in->pkt_size = ip_len;
		in->interval = ntohs(pl->interval);
		in->tos = iph->ip_tos;
		in->local = iph->ip_dst;
		in->pending = true;
		monotime(&in->first_rx);
		in->first_pair = pl->pair;
	}
	if (pl->pair >= in->npairs)
		return;

	if (len != in->train_len)
		return;
	pr = &in->pairs[pl->pair];
	if (!pr->rcvd) {
		pr->len = len;
		pr->skip = skip;
	}
	if (which == 0 && !(pr->seen01 & 0x1)) {
		pr->tx0.tv_sec = ntohl(pl->tx_sec);
		pr->tx0.tv_nsec = ntohl(pl->tx_nsec);
	}
	pp_train_arrival(pr, which, rx_ts);
	monotime(&in->last_rx);

	/*
	 * Report shortly after the final pair (even if its second packet is
	 * missing), or once arrivals stop.  "Stop" is judged from the pair
	 * spacing seen so far: a few missed pairs' worth of silence, so a
	 * sample whose tail was lost is reported before the sender's next
	 * sample begins rather than after a fixed second.
	 */
	last = pl->pair == in->npairs - 1;
	if (last) {
		wait = PKTPAIR_INBOUND_LAST_MSEC;
	} else if (pl->pair > in->first_pair) {
		wait = monotime_since(&in->first_rx, NULL) / 1000 /
		       (pl->pair - in->first_pair);
		wait = 4 * wait + PKTPAIR_INBOUND_LAST_MSEC;
		wait = MIN(wait, PKTPAIR_INBOUND_IDLE_MSEC);
	} else {
		wait = PKTPAIR_INBOUND_IDLE_MSEC;
	}
	event_cancel(&in->t_done);
	event_add_timer_msec(s->loop, pp_inbound_done, in, wait, &in->t_done);
}

/*
 * A message from a known peer in a payload version we don't speak: count
 * it so the operator can see why that peer's one-way results are missing.
 */
static void pp_version_mismatch(struct pktpair_session *s, struct in_addr src,
				uint8_t version, const char *what)
{
	bool changed = s->ver_mismatch == 0 || s->ver_last != version ||
		       !IPV4_ADDR_SAME(&s->ver_last_src, &src);

	s->ver_mismatch++;
	s->ver_last_src = src;
	s->ver_last = version;
	monotime(&s->ver_last_time);

	if (changed && pp_debug(s))
		zlog_debug("packet-pair %s: ignoring %s from %pI4: version %u, we use %u",
			   s->ifp->name, what, &src, version, PKTPAIR_VERSION);
}

static void pp_handle_icmp(struct pktpair_session *s, uint8_t *buf,
			   ssize_t len, struct timespec *rx_ts)
{
	struct ip *iph = (struct ip *)buf;
	struct icmphdr *icmp;
	struct pktpair_hdr hdr;
	uint8_t *data;
	size_t hlen, dlen;
	uint32_t magic;

	if (len < (ssize_t)sizeof(struct ip))
		return;
	hlen = iph->ip_hl << 2;
	if ((size_t)len < hlen + sizeof(*icmp) + PKTPAIR_HDR_LEN)
		return;
	icmp = (struct icmphdr *)(buf + hlen);
	data = (uint8_t *)icmp + sizeof(*icmp);
	dlen = len - hlen - sizeof(*icmp);
	memcpy(&hdr.magic, data, sizeof(hdr.magic));
	hdr.version = data[offsetof(struct pktpair_hdr, version)];
	magic = ntohl(hdr.magic);

	if (icmp->type == ICMP_ECHO && magic == PKTPAIR_MAGIC) {
		/* A peer's probe: we are the measured end. */
		if (hdr.version != PKTPAIR_VERSION) {
			if (!s->ops->accept ||
			    s->ops->accept(s, iph->ip_src, s->arg))
				pp_version_mismatch(s, iph->ip_src,
						    hdr.version, "probe");
			return;
		}
		if (dlen >= sizeof(struct pktpair_payload))
			pp_handle_probe(s, iph, icmp,
					(struct pktpair_payload *)data, len,
					rx_ts);
		return;
	}

	if (icmp->type != ICMP_ECHOREPLY || ntohs(icmp->un.echo.id) != s->ident)
		return;

	if (magic == PKTPAIR_MAGIC) {
		/* Our own probe echoed back by the peer's kernel. */
		if (hdr.version == PKTPAIR_VERSION &&
		    dlen >= sizeof(struct pktpair_payload))
			pp_handle_reply(s, iph, (struct pktpair_payload *)data,
					rx_ts);
	} else if (magic == PKTPAIR_REPORT_MAGIC) {
		if (hdr.version != PKTPAIR_VERSION) {
			if (pktpair_target_lookup(s, iph->ip_src))
				pp_version_mismatch(s, iph->ip_src,
						    hdr.version, "report");
			return;
		}
		if (dlen >= sizeof(struct pktpair_report))
			pp_handle_report(s, iph, (struct pktpair_report *)data);
	}
}

static void pp_read(struct event *thread)
{
	struct pktpair_session *s = EVENT_ARG(thread);
	uint8_t buf[PKTPAIR_PKT_MAX + 64];
	char cbuf[CMSG_SPACE(sizeof(struct timespec)) + 64];
	unsigned int burst = 256;

	event_add_read(s->loop, pp_read, s, s->fd, &s->t_read);

	while (burst--) {
		struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
		struct msghdr msg = {};
		struct cmsghdr *cm;
		struct timespec rx_ts = {};
		bool have_ts = false;
		ssize_t len;

		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);

		len = recvmsg(s->fd, &msg, 0);
		if (len < 0)
			break; /* EAGAIN or error */

		for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
#ifdef SO_TIMESTAMPNS
			if (cm->cmsg_level == SOL_SOCKET &&
			    cm->cmsg_type == SO_TIMESTAMPNS) {
				memcpy(&rx_ts, CMSG_DATA(cm), sizeof(rx_ts));
				have_ts = true;
			}
#endif
		}
		if (!have_ts)
			clock_gettime(CLOCK_REALTIME, &rx_ts);

		pp_handle_icmp(s, buf, len, &rx_ts);
	}
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

static int pp_icmp_socket(struct pktpair_session *s)
{
	int fd = -1;
	int on = 1;

	frr_with_privs (s->privs) {
		fd = vrf_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP, s->vrf_id,
				NULL);
		if (fd < 0) {
			zlog_warn("%s: socket: %s", __func__,
				  safe_strerror(errno));
			return -1;
		}
		if (vrf_bind(s->vrf_id, fd, s->ifp->name) < 0) {
			zlog_warn("%s: can't bind probe socket to %s: %s",
				  __func__, s->ifp->name, safe_strerror(errno));
			close(fd);
			return -1;
		}
	}

	/* Stack-path probes carry our own IP header (DSCP, DF, source). */
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		zlog_warn("%s: IP_HDRINCL: %s", __func__, safe_strerror(errno));
		close(fd);
		return -1;
	}
#ifdef SO_TIMESTAMPNS
	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof(on)) < 0)
		zlog_warn("%s: SO_TIMESTAMPNS: %s", __func__,
			  safe_strerror(errno));
#endif
	/*
	 * A train arrives as a burst of up to PKTPAIR_TRAIN_LEN_MAX packets
	 * (replies, or a peer's probes); the default buffer holds fewer
	 * than a hundred.
	 */
	setsockopt_so_recvbuf(fd, PKTPAIR_TRAIN_LEN_MAX * 2048);
	set_nonblocking(fd);
	return fd;
}

/*
 * Open the AF_PACKET transmit socket with PACKET_QDISC_BYPASS.  It is not
 * bound: every sendto() names the egress interface, which lets a daemon
 * send on an interface other than the session's (e.g. a tunnel's
 * underlay).  Protocol 0 means it receives nothing.
 */
static int pp_packet_socket(struct pktpair_session *s, const char **reason)
{
#ifdef PACKET_QDISC_BYPASS
	int fd = -1;
	int on = 1;

	frr_with_privs (s->privs) {
		fd = vrf_socket(AF_PACKET, SOCK_DGRAM, 0, s->vrf_id, NULL);
	}
	if (fd < 0) {
		zlog_warn("%s: AF_PACKET socket: %s", __func__,
			  safe_strerror(errno));
		*reason = "packet socket unavailable";
		return -1;
	}

	if (setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &on, sizeof(on)) <
	    0) {
		zlog_warn("%s: PACKET_QDISC_BYPASS: %s", __func__,
			  safe_strerror(errno));
		close(fd);
		*reason = "kernel lacks PACKET_QDISC_BYPASS";
		return -1;
	}

	set_nonblocking(fd);
	*reason = NULL;
	return fd;
#else
	*reason = "PACKET_QDISC_BYPASS not supported on this platform";
	return -1;
#endif
}

struct pktpair_session *
pktpair_session_new(struct event_loop *loop, struct zebra_privs_t *privs,
		    struct interface *ifp, vrf_id_t vrf_id,
		    const struct pktpair_cfg *cfg,
		    const struct pktpair_ops *ops, void *arg)
{
	static uint16_t instance;
	struct pktpair_session *s;

	s = XCALLOC(MTYPE_PKTPAIR_SESSION, sizeof(*s));
	s->loop = loop;
	s->privs = privs;
	s->ifp = ifp;
	s->vrf_id = vrf_id;
	s->cfg = *cfg;
	s->ops = ops;
	s->arg = arg;
	pktpair_targets_init(&s->targets);
	pktpair_inbound_init(&s->inbound);

	s->fd = pp_icmp_socket(s);
	if (s->fd < 0) {
		pktpair_targets_fini(&s->targets);
		pktpair_inbound_fini(&s->inbound);
		XFREE(MTYPE_PKTPAIR_SESSION, s);
		return NULL;
	}
	s->pfd = pp_packet_socket(s, &s->pfd_reason);
	s->ident = (uint16_t)((getpid() << 4) ^ ifp->ifindex ^
			      (++instance << 10));

	event_add_read(loop, pp_read, s, s->fd, &s->t_read);
	if (!cfg->respond_only)
		event_add_timer(loop, pp_sample_timer, s, 1, &s->t_sample);

	if (pp_debug(s)) {
		if (cfg->respond_only)
			zlog_debug("packet-pair %s: started as responder",
				   ifp->name);
		else
			zlog_debug("packet-pair %s: started (interval %us, %u pairs, dscp %u, bypass %s)",
				   ifp->name, cfg->interval, cfg->probes,
				   cfg->dscp,
				   s->pfd >= 0 ? "available" : s->pfd_reason);
	}
	return s;
}

void pktpair_session_free(struct pktpair_session **sp)
{
	struct pktpair_session *s = *sp;
	struct pktpair_target *t;
	struct pktpair_inbound *in;

	if (!s)
		return;

	event_cancel(&s->t_read);
	event_cancel(&s->t_sample);
	event_cancel(&s->t_pair);
	event_cancel(&s->t_finish);
	event_cancel(&s->t_sweep);
	if (s->fd >= 0)
		close(s->fd);
	if (s->pfd >= 0)
		close(s->pfd);

	XFREE(MTYPE_TMP, s->txbuf);
	XFREE(MTYPE_PKTPAIR_ACTIVE, s->active);
	while ((t = pktpair_targets_pop(&s->targets)))
		pp_target_free(t);
	pktpair_targets_fini(&s->targets);
	while ((in = pktpair_inbound_pop(&s->inbound)))
		pp_inbound_free(in);
	pktpair_inbound_fini(&s->inbound);

	if (pp_debug(s))
		zlog_debug("packet-pair %s: stopped", s->ifp->name);

	XFREE(MTYPE_PKTPAIR_SESSION, *sp);
}

void pktpair_session_set_cfg(struct pktpair_session *s,
			     const struct pktpair_cfg *cfg)
{
	bool resched = s->cfg.interval != cfg->interval ||
		       s->cfg.respond_only != cfg->respond_only;
	struct pktpair_target *t;

	/* DSCP and probes take effect with the next packet / sample. */
	s->cfg = *cfg;
	if (!resched)
		return;

	event_cancel(&s->t_sample);
	if (!cfg->respond_only) {
		event_add_timer(s->loop, pp_sample_timer, s,
				MIN(cfg->interval, 1U), &s->t_sample);
		return;
	}

	/* Now a responder: stop probing and drop our own results. */
	event_cancel(&s->t_pair);
	event_cancel(&s->t_finish);
	XFREE(MTYPE_PKTPAIR_ACTIVE, s->active);
	s->nactive = 0;
	while ((t = pktpair_targets_pop(&s->targets))) {
		struct in_addr dst = t->dst;

		pp_target_free(t);
		pp_changed(s, dst);
	}
}

bool pktpair_session_bypass_ok(const struct pktpair_session *s,
			       const char **reason)
{
	if (reason)
		*reason = s->pfd_reason;
	return s->pfd >= 0;
}

int pktpair_session_fd(const struct pktpair_session *s)
{
	return s->fd;
}

const struct pktpair_cfg *pktpair_session_cfg(const struct pktpair_session *s)
{
	return &s->cfg;
}

struct interface *pktpair_session_ifp(const struct pktpair_session *s)
{
	return s->ifp;
}

struct pktpair_target *pktpair_target_lookup(struct pktpair_session *s,
					     struct in_addr dst)
{
	struct pktpair_target key = { .dst = dst };

	return pktpair_targets_find(&s->targets, &key);
}

const struct pktpair_oneway *pktpair_inbound_lookup(struct pktpair_session *s,
						    struct in_addr peer)
{
	struct pktpair_inbound key = { .src = peer }, *in;

	in = pktpair_inbound_find(&s->inbound, &key);
	return (in && in->stats.samples) ? &in->stats : NULL;
}

/* A direction's reported value: held, then loss-adjusted. */
static uint64_t pp_dir_bw(const struct pktpair_cfg *cfg, uint64_t smooth,
			  const struct pktpair_loss *l, uint32_t rtt_usec,
			  uint16_t pkt_size)
{
	if (!smooth || l->empty_run > cfg->loss.hold_samples)
		return 0;
	return pktpair_loss_adjust(smooth, l->rate, rtt_usec, pkt_size,
				   cfg->loss.adjust);
}

void pktpair_peer_bw(struct pktpair_session *s, struct in_addr peer,
		     uint64_t *rtt_kbps, uint64_t *out_kbps, uint64_t *in_kbps)
{
	struct pktpair_target *t = pktpair_target_lookup(s, peer);
	const struct pktpair_oneway *in = pktpair_inbound_lookup(s, peer);
	uint32_t rtt = (t && t->samples) ? t->stats.rtt_avg_usec : 0;

	*rtt_kbps = *out_kbps = *in_kbps = 0;
	if (t && t->samples)
		*rtt_kbps = pp_dir_bw(&s->cfg, t->stats.bw_smooth_kbps,
				      &t->stats.loss, rtt, t->stats.pkt_size);
	if (t && t->outbound.samples)
		*out_kbps = pp_dir_bw(&s->cfg, t->outbound.bw_smooth_kbps,
				      &t->outbound.loss, rtt,
				      t->outbound.pkt_size);
	if (in && in->samples)
		*in_kbps = pp_dir_bw(&s->cfg, in->bw_smooth_kbps, &in->loss, rtt,
				     in->pkt_size);
}

static uint32_t pp_loss_ppm(const struct pktpair_loss *l)
{
	return l->samples ? (uint32_t)(l->rate * 1000000.0 + 0.5) : 0;
}

void pktpair_peer_loss(struct pktpair_session *s, struct in_addr peer,
		       uint32_t *rtt_ppm, uint32_t *out_ppm, uint32_t *in_ppm)
{
	struct pktpair_target *t = pktpair_target_lookup(s, peer);
	const struct pktpair_oneway *in = pktpair_inbound_lookup(s, peer);

	*rtt_ppm = (t && t->samples) ? pp_loss_ppm(&t->stats.loss) : 0;
	*out_ppm = (t && t->outbound.samples) ? pp_loss_ppm(&t->outbound.loss)
					      : 0;
	*in_ppm = (in && in->samples) ? pp_loss_ppm(&in->loss) : 0;
}

void pktpair_session_foreach_peer(
	struct pktpair_session *s,
	void (*cb)(struct pktpair_session *s, struct in_addr peer, void *arg),
	void *arg)
{
	struct pktpair_target *t;
	struct pktpair_inbound *in;

	frr_each (pktpair_targets, &s->targets, t)
		cb(s, t->dst, arg);
	frr_each (pktpair_inbound, &s->inbound, in) {
		struct pktpair_target key = { .dst = in->src };

		/* Peers that are also targets were already visited. */
		if (!pktpair_targets_find(&s->targets, &key))
			cb(s, in->src, arg);
	}
}

/* ------------------------------------------------------------------ */
/* Display                                                            */
/* ------------------------------------------------------------------ */

const char *pktpair_speed_str(uint64_t kbps, char *buf, size_t len)
{
	if (kbps >= 1000000)
		snprintf(buf, len, "%.2f Gbps", kbps / 1000000.0);
	else if (kbps >= 1000)
		snprintf(buf, len, "%.2f Mbps", kbps / 1000.0);
	else
		snprintf(buf, len, "%" PRIu64 " kbps", kbps);
	return buf;
}

/* Round-trip results of probing a target. */
/* Loss for one direction, and the value reported for it (eff). */
static void pp_show_loss(struct vty *vty, struct json_object *json,
			 const struct pktpair_loss *l, uint64_t eff,
			 const char *indent)
{
	char b1[32];

	if (json) {
		json_object_double_add(json, "lossPct",
				       l->last_sent ? 100.0 * l->last_lost /
							      l->last_sent
						    : 0);
		json_object_double_add(json, "lossSmoothedPct",
				       100.0 * l->rate);
		json_object_int_add(json, "packetsSentTotal", l->pkts_sent);
		json_object_int_add(json, "packetsLostTotal", l->pkts_lost);
		json_object_int_add(json, "samplesWithoutValidPairs",
				    l->empty_run);
		json_object_int_add(json, "effectiveSpeedKbps", eff);
		return;
	}

	if (!l->samples)
		return;
	vty_out(vty,
		"%s    Loss %.2f%% last sample, %.2f%% smoothed (%" PRIu64
		"/%" PRIu64 " packets); reported speed %s%s\n",
		indent,
		l->last_sent ? 100.0 * l->last_lost / l->last_sent : 0.0,
		100.0 * l->rate, l->pkts_lost, l->pkts_sent,
		eff ? pktpair_speed_str(eff, b1, sizeof(b1)) : "none",
		l->empty_run && eff ? " (held)" : "");
}

static void pp_show_rtt(struct vty *vty, struct json_object *json, uint64_t eff,
			const struct pktpair_cfg *cfg,
			const struct pktpair_target *t, const char *indent)
{
	const struct pktpair_stats *st;
	int64_t age_ms = -1;
	char b1[32], b2[32];

	st = (t && t->samples) ? &t->stats : NULL;
	if (st)
		age_ms = monotime_since(&st->last_update, NULL) / 1000;

	if (json) {
		if (cfg) {
			json_object_int_add(json, "intervalSec", cfg->interval);
			json_object_int_add(json, "pairsPerSample",
					    cfg->probes);
			json_object_int_add(json, "dscp", cfg->dscp);
		}
		json_object_int_add(json, "samples", t ? t->samples : 0);
		if (!st)
			return;
		json_object_int_add(json, "probeSizeBytes", st->pkt_size);
		json_object_boolean_add(json, "txQdiscBypass",
					st->tx.mode == PKTPAIR_TX_BYPASS);
		json_object_string_add(json, "txPath", st->tx.path);
		if (st->tx.reason)
			json_object_string_add(json, "txQdiscBypassReason",
					       st->tx.reason);
		json_object_int_add(json, "lastSampleMsecAgo", age_ms);
		json_object_int_add(json, "pairsSent", st->pairs_sent);
		json_object_int_add(json, "pairsValid", st->pairs_valid);
		json_object_int_add(json, "packetsLost", st->pkts_lost);
		json_object_int_add(json, "rttMinUsec", st->rtt_min_usec);
		json_object_int_add(json, "rttAvgUsec", st->rtt_avg_usec);
		json_object_int_add(json, "rttMaxUsec", st->rtt_max_usec);
		json_object_int_add(json, "jitterUsec", st->jitter_usec);
		json_object_int_add(json, "interPacketDelayUsec",
				    st->ipd_avg_usec);
		json_object_int_add(json, "trainLength", st->train_len);
		if (st->train_len > 2)
			json_object_int_add(json, "trainSpanUsec",
					    st->span_usec);
		json_object_int_add(json, "estimatedSpeedKbps", st->bw_kbps);
		json_object_int_add(json, "estimatedSpeedSmoothedKbps",
				    st->bw_smooth_kbps);
		json_object_int_add(json, "smoothingResets",
				    st->smoother.resets);
		pp_show_loss(vty, json, &st->loss, eff, indent);
		return;
	}

	if (cfg)
		vty_out(vty,
			"%sPacket-pair probing: interval %us, %u pairs per sample, DSCP %u\n",
			indent, cfg->interval, cfg->probes, cfg->dscp);
	if (!st) {
		vty_out(vty, "%s  No samples completed yet\n", indent);
		return;
	}
	vty_out(vty,
		"%s  Last sample %" PRId64 ".%03" PRId64 "s ago (%" PRIu64
		" total): %u/%u pairs valid, %u packets lost, %u byte probes\n",
		indent, age_ms / 1000, age_ms % 1000, t->samples,
		st->pairs_valid, st->pairs_sent, st->pkts_lost, st->pkt_size);
	if (st->tx.reason)
		vty_out(vty, "%s  Transmit path: %s (%s)\n", indent,
			st->tx.desc, st->tx.reason);
	else
		vty_out(vty, "%s  Transmit path: %s\n", indent, st->tx.desc);
	if (st->train_len > 2)
		vty_out(vty,
			"%s  Trains of %u packets, fastest timed over %u.%03u ms\n",
			indent, st->train_len, st->span_usec / 1000,
			st->span_usec % 1000);
	if (st->pkts_lost < st->train_len * st->pairs_sent)
		vty_out(vty,
			"%s  RTT min/avg/max %u.%03u/%u.%03u/%u.%03u ms, jitter %u.%03u ms\n",
			indent, st->rtt_min_usec / 1000,
			st->rtt_min_usec % 1000, st->rtt_avg_usec / 1000,
			st->rtt_avg_usec % 1000, st->rtt_max_usec / 1000,
			st->rtt_max_usec % 1000, st->jitter_usec / 1000,
			st->jitter_usec % 1000);
	else
		vty_out(vty,
			"%s  RTT unavailable (no replies; does the target answer ICMP echo?)\n",
			indent);
	if (st->pairs_valid) {
		vty_out(vty, "%s  Inter-packet delay avg %u.%03u ms\n", indent,
			st->ipd_avg_usec / 1000, st->ipd_avg_usec % 1000);
		vty_out(vty, "%s  Estimated speed %s (smoothed %s)\n", indent,
			pktpair_speed_str(st->bw_kbps, b1, sizeof(b1)),
			pktpair_speed_str(st->bw_smooth_kbps, b2, sizeof(b2)));
	} else {
		vty_out(vty, "%s  Estimated speed unavailable\n", indent);
	}
	pp_show_loss(vty, NULL, &st->loss, eff, indent);
}

static void pp_show_oneway(struct vty *vty, struct json_object *json,
			   const char *key, const char *label,
			   const char *source, const struct pktpair_oneway *ow,
			   uint64_t eff, const char *indent)
{
	int64_t age_ms = monotime_since(&ow->last_update, NULL) / 1000;
	char b1[32], b2[32];

	if (json) {
		struct json_object *jo = json_object_new_object();

		json_object_int_add(jo, "samples", ow->samples);
		json_object_int_add(jo, "lastSampleMsecAgo", age_ms);
		json_object_int_add(jo, "probeSizeBytes", ow->pkt_size);
		json_object_int_add(jo, "pairsSent", ow->npairs);
		json_object_int_add(jo, "trainLength", ow->train_len);
		json_object_int_add(jo, "pairsReceived", ow->pairs_seen);
		json_object_int_add(jo, "pairsValid", ow->pairs_valid);
		json_object_int_add(jo, "packetsReceived", ow->pkts_rcvd);
		json_object_int_add(jo, "interPacketDelayUsec",
				    ow->ipd_avg_usec);
		json_object_int_add(jo, "jitterUsec", ow->jitter_usec);
		json_object_int_add(jo, "estimatedSpeedKbps", ow->bw_kbps);
		json_object_int_add(jo, "estimatedSpeedSmoothedKbps",
				    ow->bw_smooth_kbps);
		json_object_int_add(jo, "smoothingResets",
				    ow->smoother.resets);
		pp_show_loss(vty, jo, &ow->loss, eff, indent);
		json_object_object_add(json, key, jo);
		return;
	}

	if (ow->pairs_valid)
		vty_out(vty,
			"%s  %s speed %s (smoothed %s), one-way jitter %u.%03u ms\n",
			indent, label,
			pktpair_speed_str(ow->bw_kbps, b1, sizeof(b1)),
			pktpair_speed_str(ow->bw_smooth_kbps, b2, sizeof(b2)),
			ow->jitter_usec / 1000, ow->jitter_usec % 1000);
	else
		vty_out(vty, "%s  %s speed unavailable (no complete pairs)\n",
			indent, label);
	vty_out(vty,
		"%s    %s %" PRId64 ".%03" PRId64
		"s ago: %u/%u pairs valid, %u/%u packets received\n",
		indent, source, age_ms / 1000, age_ms % 1000, ow->pairs_valid,
		ow->npairs, ow->pkts_rcvd, ow->npairs * ow->train_len);
	pp_show_loss(vty, NULL, &ow->loss, eff, indent);
}

void pktpair_show_peer(struct vty *vty, struct json_object *json,
		       const struct pktpair_cfg *cfg,
		       struct pktpair_session *s, struct in_addr peer,
		       const char *indent)
{
	struct pktpair_target *t = s ? pktpair_target_lookup(s, peer) : NULL;
	const struct pktpair_oneway *in =
		s ? pktpair_inbound_lookup(s, peer) : NULL;
	bool responder = cfg ? cfg->respond_only
			     : (s && s->cfg.respond_only);
	uint64_t eff_rtt = 0, eff_out = 0, eff_in = 0;

	if (s)
		pktpair_peer_bw(s, peer, &eff_rtt, &eff_out, &eff_in);

	if (responder) {
		if (json)
			json_object_boolean_true_add(json, "responder");
		else if (cfg)
			vty_out(vty,
				"%sPacket-pair responder (measures the peer's probes, does not probe)\n",
				indent);
	} else {
		pp_show_rtt(vty, json, eff_rtt, cfg, t, indent);
		if (t && t->outbound.samples)
			pp_show_oneway(vty, json, "outbound", "Outbound",
				       "Reported by peer", &t->outbound,
				       eff_out, indent);
		else if (t && t->samples && !json)
			vty_out(vty,
				"%s  Outbound speed not reported (peer not running packet-pair?)\n",
				indent);
	}

	if (in)
		pp_show_oneway(vty, json, "inbound", "Inbound",
			       "Measured from peer's probes", in, eff_in,
			       indent);
	else if (responder && !json)
		vty_out(vty, "%s  No probes received from peer\n", indent);

	/* Recently ignored a message from this peer for its version. */
	if (s && s->ver_mismatch && IPV4_ADDR_SAME(&s->ver_last_src, &peer) &&
	    monotime_since(&s->ver_last_time, NULL) <
		    (int64_t)(3 * MAX(s->cfg.interval, 1) + 10) * 1000000) {
		if (json)
			json_object_int_add(json, "peerVersion", s->ver_last);
		else
			vty_out(vty,
				"%s  Peer uses packet-pair version %u, this router version %u: its probes and reports are ignored\n",
				indent, s->ver_last, PKTPAIR_VERSION);
	}
}

void pktpair_show_session(struct vty *vty, struct json_object *json,
			  struct pktpair_session *s, const char *indent)
{
	int64_t age_ms;

	if (json) {
		json_object_int_add(json, "version", PKTPAIR_VERSION);
		json_object_int_add(json, "versionMismatches",
				    s ? s->ver_mismatch : 0);
		if (s && s->ver_mismatch) {
			json_object_string_addf(json,
						"versionMismatchLastSource",
						"%pI4", &s->ver_last_src);
			json_object_int_add(json, "versionMismatchLastVersion",
					    s->ver_last);
		}
		json_object_int_add(json, "scheduleDeferrals",
				    s ? s->sched_waits : 0);
		return;
	}

	if (s && s->sched_waits)
		vty_out(vty, "%sSends deferred by the schedule: %" PRIu64 "\n",
			indent, s->sched_waits);
	if (!s || !s->ver_mismatch)
		return;
	age_ms = monotime_since(&s->ver_last_time, NULL) / 1000;
	vty_out(vty,
		"%sIgnored %" PRIu64
		" packet-pair messages from peers using another version than %u (last: %pI4, version %u, %" PRId64
		".%03" PRId64 "s ago)\n",
		indent, s->ver_mismatch, PKTPAIR_VERSION, &s->ver_last_src,
		s->ver_last, age_ms / 1000, age_ms % 1000);
}

void pktpair_show_train_cfg(struct vty *vty, struct json_object *json,
			    const struct pktpair_cfg *cfg, const char *indent)
{
	const struct pktpair_train_cfg *t = &cfg->train;
	const struct pktpair_sched_cfg *c = &cfg->sched;

	if (json) {
		json_object_string_add(json, "probeMode",
				       t->span_ms ? "train" : "pair");
		if (t->span_ms) {
			json_object_int_add(json, "trainSpanMsec", t->span_ms);
			json_object_int_add(json, "trainsPerSample", t->count);
			json_object_int_add(json, "trainMaxPackets",
					    t->max_len);
			json_object_int_add(json, "trainSkipPct", t->skip_pct);
		}
		if (c->period_ms) {
			json_object_int_add(json, "schedulePeriodMsec",
					    c->period_ms);
			json_object_int_add(json, "scheduleOffsetMsec",
					    c->offset_ms);
			json_object_int_add(json, "scheduleGuardMsec",
					    c->guard_ms);
		}
		return;
	}

	if (t->span_ms)
		vty_out(vty,
			"%sTrains: %u per sample, each sized to take %u ms (at most %u packets), first %u%% not timed\n",
			indent, t->count, t->span_ms, t->max_len, t->skip_pct);
	if (c->period_ms)
		vty_out(vty,
			"%sSchedule: avoiding %u ms around boundaries every %u ms at offset %u ms (UTC)\n",
			indent, c->guard_ms, c->period_ms, c->offset_ms);
}

void pktpair_show_loss_cfg(struct vty *vty, struct json_object *json,
			   const struct pktpair_loss_cfg *loss,
			   const char *indent)
{
	if (json) {
		json_object_string_add(json, "lossAdjust",
				       pktpair_loss_adjust_str(loss->adjust));
		json_object_int_add(json, "lossWeight", loss->weight);
		json_object_int_add(json, "holdSamples", loss->hold_samples);
		return;
	}

	vty_out(vty,
		"%sLoss: adjustment %s, weight %u%%, estimate held for %u sample%s without valid pairs\n",
		indent, pktpair_loss_adjust_str(loss->adjust), loss->weight,
		loss->hold_samples, loss->hold_samples == 1 ? "" : "s");
}

void pktpair_show_smoothing(struct vty *vty, struct json_object *json,
			    const struct pktpair_smooth_cfg *smooth,
			    const char *indent)
{
	if (json) {
		json_object_int_add(json, "smoothingWeight", smooth->weight);
		json_object_int_add(json, "stepThreshold",
				    smooth->step_threshold);
		json_object_int_add(json, "stepSamples", smooth->step_samples);
		if (smooth->window >= 2) {
			json_object_int_add(json, "smoothingWindow",
					    smooth->window);
			json_object_int_add(json, "smoothingPercentile",
					    smooth->percentile);
		}
		return;
	}

	if (smooth->window >= 2)
		vty_out(vty,
			"%sSmoothing: percentile %u of the last %u samples\n",
			indent, smooth->percentile, smooth->window);
	else if (smooth->step_threshold)
		vty_out(vty,
			"%sSmoothing: weight %u%%, reset after %u sample%s beyond %u%%\n",
			indent, smooth->weight, smooth->step_samples,
			smooth->step_samples == 1 ? "" : "s",
			smooth->step_threshold);
	else
		vty_out(vty,
			"%sSmoothing: weight %u%%, step detection off\n",
			indent, smooth->weight);
}
