// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Traffic Control (TC) interaction with the kernel using socket.
 *
 * Copyright (C) 2022 Shichu Yang
 */

#include <zebra.h>

#ifndef HAVE_NETLINK

#include "lib_errors.h"

#include "zebra/rt.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_tc.h"

enum zebra_dplane_result kernel_tc_update(struct zebra_dplane_ctx *ctx)
{
	flog_err(EC_LIB_UNAVAILABLE, "%s not Implemented for this platform",
		 __func__);
	return ZEBRA_DPLANE_REQUEST_FAILURE;
}

int kernel_tc_class_stats(ifindex_t ifindex,
			  void (*cb)(const struct zebra_tc_class_stats *stats, void *arg),
			  void *arg)
{
	return -1;
}

#endif /* !HAVE_NETLINK */
