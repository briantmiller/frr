// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SAND v2 - daemon entry point
 */

#include <zebra.h>

#include "getopt.h"
#include "if.h"
#include "log.h"
#include "frrevent.h"
#include "privs.h"
#include "sigevent.h"
#include "lib/version.h"
#include "command.h"
#include "vty.h"
#include "memory.h"
#include "libfrr.h"
#include "vrf.h"

#include "sandd/sandd.h"

struct event_loop *master;

static zebra_capabilities_t _caps_p[] = {
	ZCAP_NET_RAW,
	ZCAP_BIND,
	ZCAP_NET_ADMIN,
};

struct zebra_privs_t sandd_privs = {
#if defined(FRR_USER)
	.user = FRR_USER,
#endif
#if defined FRR_GROUP
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0,
};

static struct option longopts[] = { { 0 } };

static FRR_NORETURN void sand_sigexit(void)
{
	zlog_notice("Terminating on signal");
	/* graceful leave: purge our records so others drop us at once */
	sand_stop(true);
	sand_zebra_stop();
	vrf_terminate();
	sand_terminate();
	frr_fini();
	exit(0);
}

static void sand_sigusr1(void)
{
	zlog_rotate();
}

static struct frr_signal_t sand_signals[] = {
	{ .signal = SIGUSR1, .handler = &sand_sigusr1 },
	{ .signal = SIGINT, .handler = &sand_sigexit },
	{ .signal = SIGTERM, .handler = &sand_sigexit },
};

static const struct frr_yang_module_info *const sandd_yang_modules[] = {
	&frr_interface_info,
	&frr_vrf_info,
};

FRR_DAEMON_INFO(sandd, SANDD,
	.vty_port = SAND_VTY_PORT,
	.proghelp = "Implementation of the SAND v2 routing protocol for unidirectional links.",

	.signals = sand_signals,
	.n_signals = array_size(sand_signals),

	.privs = &sandd_privs,

	.yang_modules = sandd_yang_modules,
	.n_yang_modules = array_size(sandd_yang_modules),
);

int main(int argc, char **argv)
{
	frr_preinit(&sandd_di, argc, argv);
	frr_opt_add("", longopts, "");

	while (1) {
		int opt = frr_getopt(argc, argv, NULL);

		if (opt == EOF)
			break;
		switch (opt) {
		case 0:
			break;
		default:
			frr_help_exit(1);
		}
	}

	master = frr_init();

	sand_init();
	sand_if_init();
	sand_vty_init();
	sand_zebra_init();

	frr_config_fork();
	frr_run(master);

	return 0;
}
