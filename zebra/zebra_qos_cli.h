// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QoS (class-map / policy-map / service-policy) CLI, runs in mgmtd.
 *
 * Copyright (C) 2026 FRRouting
 */

#ifndef _ZEBRA_QOS_CLI_H
#define _ZEBRA_QOS_CLI_H

#include "northbound.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_qos_cli_info;

extern void zebra_qos_cli_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_QOS_CLI_H */
