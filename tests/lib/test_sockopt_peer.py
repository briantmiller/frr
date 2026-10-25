# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestSockoptPeer(frrtest.TestMultiOut):
    program = "./test_sockopt_peer"


TestSockoptPeer.exit_cleanly()
