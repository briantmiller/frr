// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Unit test for packet-pair smoothing (pktpair_smooth_update), loss
 * accounting (pktpair_loss_update, pktpair_loss_adjust) and the send
 * schedule (pktpair_sched_delay).
 *
 * Expected values are derived by hand from the definition: an EWMA of
 * 1/bandwidth with the configured weight, plus a reset to the harmonic
 * mean of step_samples consecutive samples that all deviate by more than
 * step_threshold percent in the same direction.
 */

#include <zebra.h>

#include <assert.h>

#include "pktpair.h"

static int failures;

#define EXPECT(got, want)                                                      \
	do {                                                                   \
		uint64_t _g = (got), _w = (want);                              \
		if ((_g > _w ? _g - _w : _w - _g) > 1) {                       \
			printf("FAIL %s:%d: got %" PRIu64 ", want %" PRIu64    \
			       "\n",                                           \
			       __func__, __LINE__, _g, _w);                    \
			failures++;                                            \
		}                                                              \
	} while (0)

static const struct pktpair_smooth_cfg cfg_default = PKTPAIR_SMOOTH_CFG_DEFAULT;
static const struct pktpair_smooth_cfg cfg_nostep = {
	.weight = 25, .step_threshold = 0, .step_samples = 2
};

/* Averaging times, not rates: a fast outlier moves the value little. */
static void test_harmonic(void)
{
	struct pktpair_smoother sm = {};

	EXPECT(pktpair_smooth_update(&sm, &cfg_nostep, 100000), 100000);
	/* 1/(0.75/100000 + 0.25/1000000) = 129032; averaging rates: 325000 */
	EXPECT(pktpair_smooth_update(&sm, &cfg_nostep, 1000000), 129032);

	memset(&sm, 0, sizeof(sm));
	pktpair_smooth_update(&sm, &cfg_nostep, 100000);
	/* 1/(0.75/100000 + 0.25/10000) = 30769 */
	EXPECT(pktpair_smooth_update(&sm, &cfg_nostep, 10000), 30769);

	/* A zero sample (no valid pairs) leaves the value alone. */
	EXPECT(pktpair_smooth_update(&sm, &cfg_nostep, 0), 30769);
	assert(sm.resets == 0);
}

/* A drop from 1 Gbit/s to 5 Mbit/s is followed after two samples. */
static void test_step_down(void)
{
	struct pktpair_smoother sm = {};

	pktpair_smooth_update(&sm, &cfg_default, 1000000);
	/* First deviating sample: EWMA only, 1/(0.75e-6 + 0.25/5000) */
	EXPECT(pktpair_smooth_update(&sm, &cfg_default, 5000), 19704);
	assert(sm.step_count == 1 && sm.step_dir == -1 && sm.resets == 0);
	/* Second one: reset to their harmonic mean. */
	EXPECT(pktpair_smooth_update(&sm, &cfg_default, 5000), 5000);
	assert(sm.resets == 1 && sm.step_count == 0);

	/* Without step detection it is still 11356 after two samples. */
	memset(&sm, 0, sizeof(sm));
	pktpair_smooth_update(&sm, &cfg_nostep, 1000000);
	pktpair_smooth_update(&sm, &cfg_nostep, 5000);
	EXPECT(pktpair_smooth_update(&sm, &cfg_nostep, 5000), 11356);
}

/*
 * A rise from 5 to 20 Mbit/s: time averaging alone is slow in this
 * direction (10260 after four samples), the step reset is not.
 */
static void test_step_up(void)
{
	struct pktpair_smoother sm = {};
	uint64_t v = 0;
	int i;

	pktpair_smooth_update(&sm, &cfg_nostep, 5000);
	for (i = 0; i < 4; i++)
		v = pktpair_smooth_update(&sm, &cfg_nostep, 20000);
	EXPECT(v, 10260);

	memset(&sm, 0, sizeof(sm));
	pktpair_smooth_update(&sm, &cfg_default, 5000);
	pktpair_smooth_update(&sm, &cfg_default, 20000);
	EXPECT(pktpair_smooth_update(&sm, &cfg_default, 20000), 20000);
	assert(sm.resets == 1);

	/* The reset uses the harmonic mean of the deviating samples. */
	memset(&sm, 0, sizeof(sm));
	pktpair_smooth_update(&sm, &cfg_default, 5000);
	pktpair_smooth_update(&sm, &cfg_default, 20000);
	/* 2 / (1/20000 + 1/40000) = 26667 */
	EXPECT(pktpair_smooth_update(&sm, &cfg_default, 40000), 26667);
}

/* Deviations in alternating directions are noise, not a step. */
static void test_direction_flip(void)
{
	struct pktpair_smoother sm = {};

	pktpair_smooth_update(&sm, &cfg_default, 1000);
	pktpair_smooth_update(&sm, &cfg_default, 2000);
	assert(sm.step_count == 1 && sm.step_dir == 1);
	pktpair_smooth_update(&sm, &cfg_default, 500);
	assert(sm.step_count == 1 && sm.step_dir == -1 && sm.resets == 0);
	/* 1/(0.75 * (0.75/1000 + 0.25/2000) + 0.25/500) = 865 */
	EXPECT((uint64_t)(1.0 / sm.inv + 0.5), 865);
}

/* Variation inside the threshold never resets. */
static void test_noise(void)
{
	struct pktpair_smoother sm = {};
	uint64_t v = 0;
	int i;

	for (i = 0; i < 40; i++)
		v = pktpair_smooth_update(&sm, &cfg_default, i & 1 ? 1100 : 1000);
	assert(sm.resets == 0);
	assert(v > 1000 && v < 1100);
}

/* Configuration extremes. */
static void test_config(void)
{
	struct pktpair_smoother sm = {};
	struct pktpair_smooth_cfg latest = {
		.weight = 100, .step_threshold = 0, .step_samples = 2
	};
	struct pktpair_smooth_cfg eager = {
		.weight = 25, .step_threshold = 10, .step_samples = 1
	};

	/* Weight 100: the latest sample only. */
	pktpair_smooth_update(&sm, &latest, 1000);
	EXPECT(pktpair_smooth_update(&sm, &latest, 7000), 7000);
	EXPECT(pktpair_smooth_update(&sm, &latest, 300), 300);

	/* One sample beyond 10% is enough. */
	memset(&sm, 0, sizeof(sm));
	pktpair_smooth_update(&sm, &eager, 1000);
	EXPECT(pktpair_smooth_update(&sm, &eager, 1050), 1012);
	EXPECT(pktpair_smooth_update(&sm, &eager, 1200), 1200);
	assert(sm.resets == 1);

	/* An unset weight behaves as the default. */
	memset(&sm, 0, sizeof(sm));
	latest.weight = 0;
	pktpair_smooth_update(&sm, &latest, 100000);
	EXPECT(pktpair_smooth_update(&sm, &latest, 1000000), 129032);
}

/* Loss rate: EWMA over samples, totals, and the run of empty samples. */
static void test_loss_update(void)
{
	struct pktpair_loss l = {};
	const struct pktpair_loss_cfg cfg = PKTPAIR_LOSS_CFG_DEFAULT;

	/* The first sample sets the rate. */
	pktpair_loss_update(&l, &cfg, 20, 2, true);
	EXPECT((uint64_t)(l.rate * 1e6 + 0.5), 100000);
	/* 0.1 + 0.1 * (0 - 0.1) = 0.09 */
	pktpair_loss_update(&l, &cfg, 20, 0, true);
	EXPECT((uint64_t)(l.rate * 1e6 + 0.5), 90000);
	assert(l.pkts_sent == 40 && l.pkts_lost == 2 && l.samples == 2);
	assert(l.last_sent == 20 && l.last_lost == 0 && l.empty_run == 0);

	/* Samples without a valid pair are counted until one has one. */
	pktpair_loss_update(&l, &cfg, 20, 20, false);
	pktpair_loss_update(&l, &cfg, 20, 19, false);
	assert(l.empty_run == 2);
	pktpair_loss_update(&l, &cfg, 20, 1, true);
	assert(l.empty_run == 0);

	/* Nothing sent: only the empty run moves. */
	pktpair_loss_update(&l, &cfg, 0, 0, false);
	assert(l.samples == 5 && l.empty_run == 1);
}

static void test_loss_adjust(void)
{
	/* none, and no loss: unchanged. */
	EXPECT(pktpair_loss_adjust(100000, 0.03, 50000, 1500,
				   PKTPAIR_LOSS_ADJUST_NONE),
	       100000);
	EXPECT(pktpair_loss_adjust(100000, 0, 50000, 1500,
				   PKTPAIR_LOSS_ADJUST_TCP),
	       100000);
	/* delivery: capacity * (1 - p) */
	EXPECT(pktpair_loss_adjust(100000, 0.03, 50000, 1500,
				   PKTPAIR_LOSS_ADJUST_DELIVERY),
	       97000);
	/* tcp: 1460 * 8 bit / 50 ms * 1.22 / sqrt(0.01) = 2849.9 kbit/s */
	EXPECT(pktpair_loss_adjust(100000, 0.01, 50000, 1500,
				   PKTPAIR_LOSS_ADJUST_TCP),
	       2849);
	/* ... but never above the capacity (100 us RTT: 1.42 Gbit/s). */
	EXPECT(pktpair_loss_adjust(100000, 0.01, 100, 1500,
				   PKTPAIR_LOSS_ADJUST_TCP),
	       100000);
	/* tcp without an RTT falls back to delivery. */
	EXPECT(pktpair_loss_adjust(100000, 0.01, 0, 1500,
				   PKTPAIR_LOSS_ADJUST_TCP),
	       99000);
	/* Everything lost. */
	EXPECT(pktpair_loss_adjust(100000, 1.0, 50000, 1500,
				   PKTPAIR_LOSS_ADJUST_DELIVERY),
	       0);
}

/* Window mode: a percentile of the last N samples. */
static void test_window(void)
{
	struct pktpair_smoother sm = {};
	struct pktpair_smooth_cfg med = { .window = 5, .percentile = 50 };
	struct pktpair_smooth_cfg max = { .window = 5, .percentile = 100 };
	struct pktpair_smooth_cfg min = { .window = 5, .percentile = 1 };
	uint64_t v = 0;
	int i;

	for (i = 1; i <= 5; i++)
		v = pktpair_smooth_update(&sm, &med, 10 * i);
	EXPECT(v, 30);
	/* The oldest (10) leaves the window; one outlier moves it one step. */
	EXPECT(pktpair_smooth_update(&sm, &med, 1000), 40);
	EXPECT(pktpair_smooth_update(&sm, &max, 0), 1000);
	EXPECT(pktpair_smooth_update(&sm, &min, 0), 20);
	/* A sample without valid pairs does not enter the window. */
	EXPECT(pktpair_smooth_update(&sm, &med, 0), 40);
	assert(sm.nhist == 6);

	/* Fewer samples than the window. */
	memset(&sm, 0, sizeof(sm));
	EXPECT(pktpair_smooth_update(&sm, &med, 0), 0);
	EXPECT(pktpair_smooth_update(&sm, &med, 700), 700);
	EXPECT(pktpair_smooth_update(&sm, &med, 100), 100);
}

/* Starlink: every 15 s at :12, :27, :42, :57, keeping 1 s away. */
static void test_sched(void)
{
	struct pktpair_sched_cfg c = {
		.period_ms = 15000, .offset_ms = 12000, .guard_ms = 1000
	};
	struct pktpair_sched_cfg off = {};

	/* At a boundary: wait out the guard. */
	EXPECT(pktpair_sched_delay(12000, &c, 20), 1000);
	EXPECT(pktpair_sched_delay(12000 + 15000 * 1000ULL, &c, 20), 1000);
	EXPECT(pktpair_sched_delay(12400, &c, 20), 600);
	/* Clear of both boundaries. */
	EXPECT(pktpair_sched_delay(13000, &c, 20), 0);
	EXPECT(pktpair_sched_delay(25980, &c, 20), 0);
	/* Would still be in flight within the guard of the next one. */
	EXPECT(pktpair_sched_delay(25981, &c, 20), 2019);
	/* Before the offset in the first period. */
	EXPECT(pktpair_sched_delay(11500, &c, 20), 1500);
	/* Disabled, or nothing could ever fit. */
	EXPECT(pktpair_sched_delay(12000, &off, 20), 0);
	EXPECT(pktpair_sched_delay(12000, &c, 13000), 0);
}

int main(int argc, char **argv)
{
	test_harmonic();
	test_step_down();
	test_step_up();
	test_direction_flip();
	test_noise();
	test_config();
	test_loss_update();
	test_loss_adjust();
	test_window();
	test_sched();

	if (failures) {
		printf("%d failure(s)\n", failures);
		return 1;
	}
	return 0;
}
