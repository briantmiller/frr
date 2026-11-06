// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Packet-pair link speed estimation.
 *
 * A session runs on one interface and periodically sends back-to-back
 * pairs of MTU-sized ICMP echo requests to a set of IPv4 targets supplied
 * by the daemon (OSPF neighbors, NHRP peers, ...).  The targets' IP stacks
 * echo them back; from the replies the session derives, per target:
 *
 *   - round trip time (RTT) per probe pair,
 *   - jitter (mean absolute difference between consecutive RTTs),
 *   - inter-packet delay (dispersion) between the two replies of a pair,
 *   - estimated bottleneck bandwidth = packet_bits / dispersion
 *     (median over all pairs in a sample, to reject cross-traffic noise),
 *     plus an EWMA of that across samples.
 *
 * The daemon decides, per target and per sample, how probes are sent
 * (struct pktpair_tx):
 *
 *   PKTPAIR_TX_BYPASS: the probe is written to an AF_PACKET socket with
 *     PACKET_QDISC_BYPASS set, on tx.ifindex with link-layer destination
 *     tx.lladdr.  Optional pre-built headers (tx.encap, e.g. an outer IPv4
 *     and GRE header) are prepended to the inner probe.  The frame goes
 *     straight to the driver of tx.ifindex, skipping its egress qdisc.
 *
 *   PKTPAIR_TX_STACK: the probe goes through the IP stack (raw socket with
 *     IP_HDRINCL, bound to the session interface), and therefore through
 *     every qdisc on the way.
 *
 * Replies are always received on a raw ICMP socket bound to the session
 * interface, with kernel receive timestamps (SO_TIMESTAMPNS).
 *
 * One-way measurement
 * -------------------
 * The round-trip estimate is limited by the slower of the two directions.
 * To measure each direction separately, a session also recognizes probe
 * pairs arriving from peers (accepted by ops->accept), times their arrival
 * and computes the peer -> local ("inbound") bandwidth and one-way jitter.
 * When the peer's sample ends, the result is sent back to it in a report
 * (an ICMP echo reply carrying the prober's ICMP identifier), where it
 * becomes that target's local -> peer ("outbound") result.  Both sides
 * need a session for this; a session in respond_only mode measures and
 * reports without sending probes of its own.
 */

#ifndef _FRR_PKTPAIR_H
#define _FRR_PKTPAIR_H

#include <netinet/in.h>
#include <time.h>

#include "typesafe.h"
#include "vrf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct event_loop;
struct interface;
struct json_object;
struct vty;
struct zebra_privs_t;

/*
 * Version of the probe and report payload formats.  Both carry it right
 * after the magic number; a receiver ignores messages of any other
 * version (no measurement, no report) and counts them.  Increase only for
 * incompatible format changes.
 */
#define PKTPAIR_VERSION 2

/* Configuration defaults and limits. */
#define PKTPAIR_INTERVAL_DEFAULT 60 /* seconds between samples */
#define PKTPAIR_INTERVAL_MIN	 1
#define PKTPAIR_INTERVAL_MAX	 3600
#define PKTPAIR_PROBES_DEFAULT	 10 /* packet pairs per sample */
#define PKTPAIR_PROBES_MIN	 2
#define PKTPAIR_PROBES_MAX	 64
#define PKTPAIR_DSCP_DEFAULT	 0

/* Probe sizes (IP total length of the inner probe). */
#define PKTPAIR_PKT_MIN	    128
#define PKTPAIR_PKT_MAX	    9000
#define PKTPAIR_PKT_DEFAULT 1500

/* Room for headers a daemon prepends on the bypass path. */
#define PKTPAIR_ENCAP_MAX 64

/*
 * Smoothing of per-sample estimates across samples.
 *
 * Each sample's estimate (median over its pairs) is folded into an
 * exponentially weighted moving average of the inverse bandwidth, i.e. of
 * the time per bit, which is what packet pairs actually measure.  Averaging
 * times rather than rates keeps a single too-fast outlier from dragging
 * the average up: the result is a weighted harmonic mean.
 *
 * A sustained change in link speed would only fade in slowly, so when
 * step_samples consecutive samples all deviate from the smoothed value by
 * more than step_threshold percent in the same direction, the smoothed
 * value is reset to their (harmonic) mean.  A step_threshold of 0
 * disables this.
 */
#define PKTPAIR_SMOOTH_WEIGHT_DEFAULT  25 /* % weight of a new sample */
#define PKTPAIR_SMOOTH_WEIGHT_MIN      1
#define PKTPAIR_SMOOTH_WEIGHT_MAX      100
#define PKTPAIR_STEP_THRESHOLD_DEFAULT 30 /* %, 0 = no step detection */
#define PKTPAIR_STEP_THRESHOLD_MAX     1000
#define PKTPAIR_STEP_SAMPLES_DEFAULT   2
#define PKTPAIR_STEP_SAMPLES_MIN       1
#define PKTPAIR_STEP_SAMPLES_MAX       16

struct pktpair_smooth_cfg {
	uint8_t weight;		 /* 1-100 %; 100 = latest sample only */
	uint16_t step_threshold; /* 0-1000 %                          */
	uint8_t step_samples;	 /* 1-16                              */
	/*
	 * window > 0: instead of the moving average, the given percentile
	 * of the last "window" samples (nearest rank).  Suits links whose
	 * allocation changes every few seconds, where the average would
	 * keep resetting.
	 */
	uint8_t window;	    /* 0, 2-64 samples */
	uint8_t percentile; /* 1-100           */
};
#define PKTPAIR_SMOOTH_WINDOW_MAX	   64
#define PKTPAIR_SMOOTH_PERCENTILE_DEFAULT 50

#define PKTPAIR_SMOOTH_CFG_DEFAULT                                             \
	{                                                                      \
		.weight = PKTPAIR_SMOOTH_WEIGHT_DEFAULT,                       \
		.step_threshold = PKTPAIR_STEP_THRESHOLD_DEFAULT,              \
		.step_samples = PKTPAIR_STEP_SAMPLES_DEFAULT,                  \
	}

struct pktpair_smoother {
	double inv;	     /* EWMA of 1/kbps, 0 before the first sample */
	double step_inv_sum; /* 1/kbps summed over the pending step       */
	uint8_t step_count;  /* consecutive deviating samples            */
	int8_t step_dir;     /* +1 faster, -1 slower                     */
	uint32_t resets;     /* step resets so far                       */
	/* Window mode. */
	uint64_t hist[PKTPAIR_SMOOTH_WINDOW_MAX];
	uint8_t nhist;
	uint8_t pos;
};

/*
 * Fold a sample (kbit/s, > 0) into sm and return the smoothed value in
 * kbit/s.
 */
extern uint64_t pktpair_smooth_update(struct pktpair_smoother *sm,
				      const struct pktpair_smooth_cfg *cfg,
				      uint64_t sample_kbps);

/*
 * Loss accounting.
 *
 * Loss does not bias a packet-pair estimate: a pair either arrives whole
 * and is timed, or is discarded.  It only thins the sample, and with heavy
 * loss a sample can end without a single valid pair.  Two things follow:
 *
 * - The smoothed estimate is kept (held) through up to hold_samples
 *   consecutive samples without a valid pair before it is withdrawn, so
 *   loss does not make the reported speed flap to "unknown".
 *
 * - The packet loss rate is tracked per direction (EWMA over samples with
 *   the given weight) and can be applied to the speed that is reported,
 *   which is the link's capacity, to estimate what traffic can actually
 *   get through:
 *     none      capacity as measured
 *     delivery  capacity * (1 - loss): what survives the link
 *     tcp       the smaller of capacity and the steady-state throughput
 *               of a TCP flow at that loss and RTT (Mathis et al.:
 *               MSS / RTT * 1.22 / sqrt(loss)); without an RTT (inbound
 *               on a responder) it falls back to delivery
 */
enum pktpair_loss_adjust {
	PKTPAIR_LOSS_ADJUST_NONE = 0,
	PKTPAIR_LOSS_ADJUST_DELIVERY,
	PKTPAIR_LOSS_ADJUST_TCP,
};

#define PKTPAIR_LOSS_WEIGHT_DEFAULT  10 /* % weight of a new sample */
#define PKTPAIR_LOSS_WEIGHT_MIN	     1
#define PKTPAIR_LOSS_WEIGHT_MAX	     100
#define PKTPAIR_HOLD_SAMPLES_DEFAULT 3
#define PKTPAIR_HOLD_SAMPLES_MAX     16

struct pktpair_loss_cfg {
	uint8_t adjust;	      /* enum pktpair_loss_adjust */
	uint8_t weight;	      /* 1-100 %                  */
	uint8_t hold_samples; /* 0-16                     */
};

#define PKTPAIR_LOSS_CFG_DEFAULT                                               \
	{                                                                      \
		.adjust = PKTPAIR_LOSS_ADJUST_NONE,                            \
		.weight = PKTPAIR_LOSS_WEIGHT_DEFAULT,                         \
		.hold_samples = PKTPAIR_HOLD_SAMPLES_DEFAULT,                  \
	}

struct pktpair_loss {
	double rate;	   /* smoothed fraction of packets lost       */
	uint32_t samples;  /* samples folded into rate                */
	uint64_t pkts_sent; /* totals                                 */
	uint64_t pkts_lost;
	uint16_t last_sent; /* latest sample                          */
	uint16_t last_lost;
	uint8_t empty_run; /* consecutive samples without a valid pair */
};

/* Fold a sample of sent/lost packets into l; valid: it had a valid pair. */
extern void pktpair_loss_update(struct pktpair_loss *l,
				const struct pktpair_loss_cfg *cfg,
				unsigned int sent, unsigned int lost,
				bool valid);

/*
 * Apply a loss adjustment to a capacity in kbit/s.  rtt_usec and pkt_size
 * (IP length, for the MSS) are used by PKTPAIR_LOSS_ADJUST_TCP only.
 */
extern uint64_t pktpair_loss_adjust(uint64_t kbps, double loss,
				    uint32_t rtt_usec, uint16_t pkt_size,
				    enum pktpair_loss_adjust mode);

extern const char *pktpair_loss_adjust_str(enum pktpair_loss_adjust mode);

/*
 * Packet trains.  On links that deliver traffic in scheduled frames rather
 * than serializing it at a bit rate (satellite, cellular, DOCSIS), two
 * packets often ride in the same frame and arrive together, or are split
 * across frames and arrive a frame time apart, and a packet pair measures
 * neither the link nor the allocation.  A train long enough to span many
 * frames averages that out: its rate is the packets received after the
 * head divided by the time from the first to the last of them.
 *
 * span_ms 0 means packet pairs.  Otherwise each sample sends "count"
 * trains whose length is chosen so that, at the current estimate, a train
 * takes span_ms at the bottleneck (at least PKTPAIR_TRAIN_LEN_MIN and at
 * most max_len packets).  The first skip_pct percent of each train is not
 * timed, as schedulers can be slow to grant a new burst its full rate.
 * The sample value is the highest train rate: cross traffic can only
 * slow a train down.
 */
#define PKTPAIR_TRAIN_LEN_MIN	      8
#define PKTPAIR_TRAIN_LEN_MAX	      1024
#define PKTPAIR_TRAIN_SPAN_MIN	      2 /* ms */
#define PKTPAIR_TRAIN_SPAN_MAX	      500
#define PKTPAIR_TRAIN_COUNT_DEFAULT   3
#define PKTPAIR_TRAIN_COUNT_MAX	      16
#define PKTPAIR_TRAIN_MAXLEN_DEFAULT  512
#define PKTPAIR_TRAIN_SKIP_MAX	      50

struct pktpair_train_cfg {
	uint16_t span_ms; /* 0 = packet pairs   */
	uint8_t count;	  /* trains per sample  */
	uint16_t max_len; /* packets            */
	uint8_t skip_pct; /* head not timed, %  */
};

/*
 * Avoid periodic disruptions, such as a satellite network's path
 * reallocation every 15 s at fixed wall-clock offsets: no train or pair is
 * sent within guard_ms of a boundary, nor so late that it would still be
 * in flight then.  Boundaries are at offset_ms + k * period_ms of the
 * system clock (UTC), so the clock must be synchronized.  period_ms 0
 * disables it.
 */
struct pktpair_sched_cfg {
	uint32_t period_ms;
	uint32_t offset_ms;
	uint16_t guard_ms;
};

/*
 * Milliseconds to wait before starting something that lasts dur_ms at
 * now_ms (UTC epoch ms), 0 if it can start now.
 */
extern uint32_t pktpair_sched_delay(uint64_t now_ms,
				    const struct pktpair_sched_cfg *c,
				    uint32_t dur_ms);

struct pktpair_cfg {
	uint16_t interval; /* seconds */
	uint8_t probes;	   /* pairs per sample */
	uint8_t dscp;	   /* 0-63, inner IP header */
	bool respond_only; /* measure and report peers' probes only */
	struct pktpair_smooth_cfg smooth;
	struct pktpair_loss_cfg loss;
	struct pktpair_train_cfg train;
	struct pktpair_sched_cfg sched;
};

enum pktpair_tx_mode {
	PKTPAIR_TX_STACK = 0,
	PKTPAIR_TX_BYPASS,
};

/* How probes towards one target are sent during one sample. */
struct pktpair_tx {
	enum pktpair_tx_mode mode;
	const char *path;   /* short machine-readable id, for JSON  */
	const char *reason; /* why bypass is partial/absent, or NULL */
	char desc[96];	    /* human-readable description           */

	struct in_addr src; /* inner IPv4 source address           */

	/* PKTPAIR_TX_BYPASS only. */
	ifindex_t ifindex;
	uint16_t protocol; /* ethertype, host order (ETH_P_IP)    */
	uint8_t halen;
	uint8_t lladdr[16];
	uint16_t encap_len;
	uint8_t encap[PKTPAIR_ENCAP_MAX];
};

/* Results of the most recent completed sample for one target. */
struct pktpair_stats {
	uint32_t rtt_min_usec; /* over the first packet of each pair */
	uint32_t rtt_avg_usec;
	uint32_t rtt_max_usec;
	uint32_t jitter_usec;	 /* mean |RTT(i) - RTT(i-1)|          */
	uint32_t ipd_avg_usec;	 /* mean reply dispersion             */
	uint64_t bw_kbps;	 /* median packet-pair estimate       */
	uint64_t bw_smooth_kbps; /* smoothed over samples             */
	struct pktpair_smoother smoother;
	uint16_t pkt_size;	 /* IP length of each inner probe     */
	uint16_t pairs_sent;
	uint16_t pairs_valid; /* both replies, positive gap        */
	uint16_t pkts_lost;
	uint16_t train_len;	  /* packets per pair/train         */
	uint32_t span_usec;	  /* timed span of the best train   */
	struct pktpair_loss loss; /* both directions together     */
	struct pktpair_tx tx; /* how this sample was sent          */
	struct timeval last_update; /* monotonic */
};

/* One-way results for one direction, measured at the receiving end. */
struct pktpair_oneway {
	uint64_t bw_kbps;	 /* median over the sample's pairs   */
	uint64_t bw_smooth_kbps; /* smoothed over samples            */
	struct pktpair_smoother smoother;
	uint32_t ipd_avg_usec;	 /* mean arrival gap within pairs    */
	uint32_t jitter_usec;	 /* mean |OWD(i) - OWD(i-1)|         */
	uint16_t pkt_size;
	uint16_t interval;	 /* sender's probing interval, s     */
	uint8_t npairs;	     /* pairs the sender sent            */
	uint8_t pairs_seen;  /* pairs with at least one arrival  */
	uint8_t pairs_valid; /* both arrived, positive gap       */
	uint16_t pkts_rcvd;
	uint16_t train_len;  /* packets per pair/train          */
	struct pktpair_loss loss;
	uint64_t samples;
	struct timeval last_update; /* monotonic */
};

/*
 * A pair (len 2) or train, on the probing side (replies) or the measured
 * side (probes).  Packet 0 gives RTT / one-way delay; packets from index
 * skip on are timed from the first to the last arrival.
 */
struct pktpair_pair {
	struct timespec tx0;  /* packet 0 sent (sender's clock) */
	struct timespec rx0;  /* packet 0 (or its reply) arrived */
	struct timespec rx_a; /* first timed arrival            */
	struct timespec rx_b; /* last timed arrival             */
	uint16_t len;
	uint16_t skip;
	uint16_t sent;	 /* packets sent (prober)          */
	uint16_t rcvd;	 /* arrivals                       */
	uint16_t steady; /* arrivals with index >= skip    */
	uint8_t seen01;	 /* packets 0 and 1 arrived (bits) */
};

PREDECL_HASH(pktpair_targets);

struct pktpair_target {
	struct pktpair_targets_item item;
	struct in_addr dst;

	/* Current sample. */
	uint32_t sample_id;
	uint8_t npairs;
	uint16_t pkt_size;
	uint16_t train_len; /* packets per pair/train this sample */
	bool seen; /* re-added by the daemon this round */
	struct pktpair_tx tx;
	struct pktpair_pair pairs[PKTPAIR_PROBES_MAX];

	/* Results. */
	uint64_t samples;
	struct pktpair_stats stats;

	/* Local -> target, as reported back by the target. */
	uint32_t prev_sample_id; /* a late report for it is still taken */
	uint32_t outbound_sample_id;
	struct pktpair_oneway outbound;
};

struct pktpair_session;

struct pktpair_ops {
	/*
	 * Called at the start of every sample.  The daemon calls
	 * pktpair_target_add() once for every target to probe now; targets
	 * not added are dropped together with their statistics.
	 */
	void (*collect)(struct pktpair_session *s, void *arg);

	/*
	 * Choose how to reach target t during this sample.  tx is zeroed
	 * and must at least get mode and src; ip_len is the total length of
	 * the inner probe (for building encap headers).  Return false to
	 * skip the target this round.
	 */
	bool (*prepare)(struct pktpair_session *s, struct pktpair_target *t,
			struct pktpair_tx *tx, uint16_t ip_len, void *arg);

	/*
	 * Optional: whether probes arriving from src should be measured and
	 * reported (e.g. src is a neighbor on this interface).  Without it,
	 * any sender is accepted, up to a fixed number of senders.
	 */
	bool (*accept)(struct pktpair_session *s, struct in_addr src,
		       void *arg);

	/*
	 * Optional: results for peer changed (new sample, report, inbound
	 * measurement) or went away.  Use pktpair_peer_bw() for the values.
	 */
	void (*changed)(struct pktpair_session *s, struct in_addr peer,
			void *arg);

	/* Optional: return true to log debug messages. */
	bool (*debug)(void *arg);
};

/*
 * Start a session on ifp.  Returns NULL if the receive socket can't be
 * opened.  The caller must free the session before ifp goes away.
 */
extern struct pktpair_session *
pktpair_session_new(struct event_loop *loop, struct zebra_privs_t *privs,
		    struct interface *ifp, vrf_id_t vrf_id,
		    const struct pktpair_cfg *cfg,
		    const struct pktpair_ops *ops, void *arg);
extern void pktpair_session_free(struct pktpair_session **s);

/* Apply changed configuration to a running session. */
extern void pktpair_session_set_cfg(struct pktpair_session *s,
				    const struct pktpair_cfg *cfg);

/* Whether the AF_PACKET bypass socket could be opened, and if not why. */
extern bool pktpair_session_bypass_ok(const struct pktpair_session *s,
				      const char **reason);

/* A socket usable for ioctls (SIOCGARP) in the session's VRF. */
extern int pktpair_session_fd(const struct pktpair_session *s);

extern struct interface *pktpair_session_ifp(const struct pktpair_session *s);

/* The configuration the session runs with. */
extern const struct pktpair_cfg *
pktpair_session_cfg(const struct pktpair_session *s);

/* For use from ops->collect only. */
extern void pktpair_target_add(struct pktpair_session *s, struct in_addr dst);

extern struct pktpair_target *
pktpair_target_lookup(struct pktpair_session *s, struct in_addr dst);

/*
 * Current bandwidths for a peer, in kbit/s, 0 when unknown: the
 * round-trip estimate from probing it, the outbound one-way result it
 * reported, and the inbound one-way result measured from its probes.
 * These are the smoothed estimates, held through up to hold_samples
 * samples without a valid pair, with the configured loss adjustment
 * applied.
 */
extern void pktpair_peer_bw(struct pktpair_session *s, struct in_addr peer,
			    uint64_t *rtt_kbps, uint64_t *out_kbps,
			    uint64_t *in_kbps);

/*
 * Smoothed packet loss for a peer, in parts per million, per direction as
 * above (the round-trip figure covers both directions).  0 when unknown.
 */
extern void pktpair_peer_loss(struct pktpair_session *s, struct in_addr peer,
			      uint32_t *rtt_ppm, uint32_t *out_ppm,
			      uint32_t *in_ppm);

/* Call cb for every peer the session has results or state for. */
extern void pktpair_session_foreach_peer(
	struct pktpair_session *s,
	void (*cb)(struct pktpair_session *s, struct in_addr peer, void *arg),
	void *arg);

/* Peer -> local results measured from peer's probes, or NULL. */
extern const struct pktpair_oneway *
pktpair_inbound_lookup(struct pktpair_session *s, struct in_addr peer);

/*
 * Display everything known about one peer: the configuration line
 * (unless cfg is NULL), the round-trip results of probing it, the
 * outbound result it reported, and the inbound result measured from its
 * probes.  s may be NULL (session not running).  Text output starts at
 * the given indent, details are indented two more columns.  With json
 * non-NULL, keys are added to json instead ("outbound" and "inbound" as
 * nested objects).
 */
extern void pktpair_show_peer(struct vty *vty, struct json_object *json,
			      const struct pktpair_cfg *cfg,
			      struct pktpair_session *s, struct in_addr peer,
			      const char *indent);

/* The smoothing configuration, as a text line or JSON keys. */
extern void pktpair_show_smoothing(struct vty *vty, struct json_object *json,
				   const struct pktpair_smooth_cfg *smooth,
				   const char *indent);

/* Probe mode (pairs/trains) and schedule, as text lines or JSON keys. */
extern void pktpair_show_train_cfg(struct vty *vty, struct json_object *json,
				   const struct pktpair_cfg *cfg,
				   const char *indent);

/* The loss accounting configuration, as a text line or JSON keys. */
extern void pktpair_show_loss_cfg(struct vty *vty, struct json_object *json,
				  const struct pktpair_loss_cfg *loss,
				  const char *indent);

/*
 * Session-wide information: the payload version in use and messages
 * ignored because peers use another version.  Text output is printed
 * only when there were such messages.
 */

extern void pktpair_show_session(struct vty *vty, struct json_object *json,
				 struct pktpair_session *s,
				 const char *indent);

extern const char *pktpair_speed_str(uint64_t kbps, char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_PKTPAIR_H */
