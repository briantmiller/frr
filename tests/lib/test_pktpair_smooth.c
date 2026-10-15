// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Unit test for packet-pair smoothing (pktpair_smooth_update).
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

int main(int argc, char **argv)
{
	test_harmonic();
	test_step_down();
	test_step_up();
	test_direction_flip();
	test_noise();
	test_config();

	if (failures) {
		printf("%d failure(s)\n", failures);
		return 1;
	}
	return 0;
}
