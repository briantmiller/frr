# SPDX-License-Identifier: ISC
import frrtest


class TestPktpairSmooth(frrtest.TestMultiOut):
    program = "./test_pktpair_smooth"


TestPktpairSmooth.exit_cleanly()
