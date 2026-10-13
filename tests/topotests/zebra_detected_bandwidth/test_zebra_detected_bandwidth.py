#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_zebra_detected_bandwidth.py
#
# Copyright (c) 2026
#

"""
Test zebra's detected bandwidth: per next hop and per interface values
reported by daemons over ZAPI (ZEBRA_DETECTED_BW_UPDATE).

Topology (OSPF broadcast network, all three routers probing):

        +----+  r1-eth0 .1
        | r1 +------------+
        +----+            |
        +----+  r2-eth0 .2+----+
        | r2 +------------+ s1 |   10.0.123.0/24
        +----+            +----+
        +----+  r3-eth0 .3|
        | r3 +------------+
        +----+

Switch ports are shaped, so the link speeds differ per direction and per
neighbor:
  towards r2: 5 Mbit/s    (r1 -> r2)
  towards r3: 10 Mbit/s   (r1 -> r3)
  towards r1: 20 Mbit/s   (r2 -> r1, r3 -> r1)

sharpd on r1 reports values of its own for the same interface.

Verified on r1:
  - ospfd reports each neighbor as a next hop, with one-way outbound and
    inbound values that follow the shapers
  - the interface bandwidth for ospf is the fastest next hop by default
    ("detected-bandwidth aggregate max") and the sum with
    "detected-bandwidth aggregate sum"
  - sharpd's values for the same interface and next hop are kept apart
    from ospfd's: neither overwrites the other
  - when sharpd exits, its values are removed and ospfd's stay
  - when packet-pair is disabled in ospfd, its values are withdrawn
"""

import json
import os
import re
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd, pytest.mark.sharpd]

R2 = "10.0.123.2"
R3 = "10.0.123.3"
TO_R2, TO_R3, TO_R1 = 5000, 10000, 20000  # kbit/s
TOLERANCE = 0.25


def build_topo(tgen):
    "Build function"
    switch = tgen.add_switch("s1")
    for rname in ["r1", "r2", "r3"]:
        tgen.add_router(rname)
        switch.add_link(tgen.gears[rname])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        extra = ["sharpd"] if rname == "r1" else None
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)), extra_daemons=extra
        )

    tgen.start_router()

    _shape_towards(tgen, "r2", TO_R2)
    _shape_towards(tgen, "r3", TO_R3)
    _shape_towards(tgen, "r1", TO_R1)


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


#
# Helpers
#


def _switch_port(tgen, rname):
    "The s1 port facing rname's eth0."
    peer_index = tgen.net[rname].cmd("cat /sys/class/net/{}-eth0/iflink".format(rname))
    _, out, _ = tgen.net["s1"].cmd_status("ip -o link show master s1")
    for line in out.splitlines():
        m = re.match(r"(\d+): ([^:@]+)", line)
        if m and m.group(1) == peer_index.strip():
            return m.group(2)
    pytest.fail("no s1 port for {}: {}".format(rname, out))


def _shape_towards(tgen, rname, kbps):
    rc, out, err = tgen.net["s1"].cmd_status(
        "tc qdisc replace dev {} root tbf rate {}kbit burst 1600 "
        "latency 400ms".format(_switch_port(tgen, rname), kbps)
    )
    if rc:
        pytest.skip("tc tbf not available: {} {}".format(out, err))


def _dbw(router):
    "show zebra detected-bandwidth json, for r1-eth0"
    try:
        data = json.loads(
            router.vtysh_cmd("show zebra detected-bandwidth interface r1-eth0 json")
        )
    except ValueError:
        return {}
    return data.get("r1-eth0", {})


def _near(value, kbps):
    return abs(value - kbps) <= kbps * TOLERANCE


def _check_ospf_nexthops(router):
    src = _dbw(router).get("sources", {}).get("ospf")
    if not src:
        return "no ospf source"
    nhs = src.get("nexthops", {})
    for nh, out, inb in ((R2, TO_R2, TO_R1), (R3, TO_R3, TO_R1)):
        v = nhs.get(nh)
        if v is None:
            return "next hop {} missing: {}".format(nh, nhs)
        if v["outSource"] != "one-way" or v["inSource"] != "one-way":
            return "{} not one-way yet: {}".format(nh, v)
        if not _near(v["outKbps"], out) or not _near(v["inKbps"], inb):
            return "{} out/in {}/{} not near {}/{}".format(
                nh, v["outKbps"], v["inKbps"], out, inb
            )
    return None


def _check_interface(router, source, out, inb, nexthops):
    src = _dbw(router).get("sources", {}).get(source)
    if not src:
        return "no {} source".format(source)
    if src["nexthopCount"] != nexthops:
        return "{} next hops: {}".format(source, src)
    if not _near(src["outKbps"], out) or not _near(src["inKbps"], inb):
        return "{} interface out/in {}/{} not near {}/{}".format(
            source, src["outKbps"], src["inKbps"], out, inb
        )
    return None


def _expect(func, count=30, wait=1, msg=""):
    _, result = topotest.run_and_expect(func, None, count=count, wait=wait)
    assert result is None, "{}: {}".format(msg, result)


def _skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


#
# Tests
#


def test_ospf_nexthops():
    "ospfd reports both neighbors with per-direction values."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    _expect(
        partial(_check_ospf_nexthops, r1),
        count=60,
        wait=2,
        msg="ospf next hops in zebra",
    )
    logger.info("r1 zebra detected bandwidth: %s", _dbw(r1))

    output = r1.vtysh_cmd("show zebra detected-bandwidth")
    logger.info(output)
    assert "Interface r1-eth0 (vrf default), aggregate max" in output, output
    assert re.search(
        r"10\.0\.123\.2: out [\d.]+ Mbps \(one-way\), in [\d.]+ Mbps \(one-way\), "
        r"round trip [\d.]+ Mbps",
        output,
    ), output


def test_aggregate_max():
    "By default the interface bandwidth is that of the fastest next hop."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    _expect(
        partial(_check_interface, r1, "ospf", TO_R3, TO_R1, 2),
        msg="ospf interface bandwidth with aggregate max",
    )
    assert _dbw(r1)["aggregate"] == "max"

    data = json.loads(r1.vtysh_cmd("show interface r1-eth0 json"))
    dbw = data["r1-eth0"]["detectedBandwidth"]
    assert dbw["aggregate"] == "max", dbw
    assert dbw["sources"]["ospf"]["nexthopCount"] == 2, dbw
    output = r1.vtysh_cmd("show interface r1-eth0")
    assert "Detected bandwidth (aggregate max):" in output, output
    assert re.search(r"ospf: out [\d.]+ Mbps, in [\d.]+ Mbps, 2 next hops", output)


def test_aggregate_sum():
    "With aggregate sum the next hops add up."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("""
        configure terminal
         interface r1-eth0
          detected-bandwidth aggregate sum
        """)
    assert re.search(
        r"^ detected-bandwidth aggregate sum$",
        r1.vtysh_cmd("show running-config"),
        re.M,
    )
    _expect(
        partial(_check_interface, r1, "ospf", TO_R2 + TO_R3, 2 * TO_R1, 2),
        msg="ospf interface bandwidth with aggregate sum",
    )
    assert _dbw(r1)["aggregate"] == "sum"

    r1.vtysh_cmd("""
        configure terminal
         interface r1-eth0
          no detected-bandwidth aggregate
        """)
    assert "detected-bandwidth" not in r1.vtysh_cmd("show running-config")
    _expect(
        partial(_check_interface, r1, "ospf", TO_R3, TO_R1, 2),
        count=5,
        msg="back to aggregate max",
    )


def test_sources_kept_apart():
    "sharpd's values don't overwrite ospfd's, even for the same next hop."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("sharp detected-bandwidth r1-eth0 {} out 1000 in 2000".format(R2))
    r1.vtysh_cmd("sharp detected-bandwidth r1-eth0 10.0.123.99 rtt 3000")

    def _check():
        sharp = _dbw(r1).get("sources", {}).get("sharp", {}).get("nexthops", {})
        if set(sharp) != {R2, "10.0.123.99"}:
            return "sharp next hops: {}".format(sharp)
        if sharp[R2]["outKbps"] != 1000 or sharp[R2]["inKbps"] != 2000:
            return "sharp {}: {}".format(R2, sharp[R2])
        v = sharp["10.0.123.99"]
        if v["outKbps"] != 3000 or v["outSource"] != "round-trip":
            return "sharp 10.0.123.99: {}".format(v)
        return _check_ospf_nexthops(r1)

    _expect(_check, count=10, msg="sharp and ospf side by side")

    # Each source is aggregated on its own.
    _expect(partial(_check_interface, r1, "sharp", 3000, 3000, 2), count=5)
    _expect(partial(_check_interface, r1, "ospf", TO_R3, TO_R1, 2), count=5)

    r1.vtysh_cmd("no sharp detected-bandwidth r1-eth0 10.0.123.99")
    _expect(partial(_check_interface, r1, "sharp", 1000, 2000, 1), count=5)


def test_daemon_exit_removes_its_values():
    "When sharpd exits zebra drops its values; ospfd's remain."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    kill_router_daemons(tgen, "r1", ["sharpd"], save_config=False)

    def _check():
        sources = _dbw(r1).get("sources", {})
        if "sharp" in sources:
            return "sharp still present: {}".format(sources["sharp"])
        return _check_ospf_nexthops(r1)

    _expect(_check, count=10, msg="sharp values not removed")

    # A restarted sharpd starts from a clean slate and can report again.
    start_router_daemons(tgen, "r1", ["sharpd"])
    assert "sharp" not in _dbw(r1).get("sources", {})
    _expect(
        lambda: (
            r1.vtysh_cmd("sharp detected-bandwidth r1-eth0 {} out 500".format(R2))
            and None
        )
        or _check_interface(r1, "sharp", 500, 0, 1),
        count=10,
        msg="restarted sharpd cannot report",
    )


def test_packet_pair_disabled():
    "Disabling packet-pair in ospfd withdraws its values."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("""
        configure terminal
         interface r1-eth0
          no ip ospf packet-pair
        """)

    def _ospf_gone():
        sources = _dbw(r1).get("sources", {})
        return "still present: {}".format(sources) if "ospf" in sources else None

    _expect(_ospf_gone, count=10, msg="ospf values not withdrawn")
    # The restarted sharpd's value is unaffected; withdraw it too.
    assert "sharp" in _dbw(r1).get("sources", {})
    r1.vtysh_cmd("no sharp detected-bandwidth r1-eth0")
    _expect(
        lambda: None if not _dbw(r1) else "still present: {}".format(_dbw(r1)),
        count=5,
        msg="sharp clear",
    )
    assert "Detected bandwidth" not in r1.vtysh_cmd("show interface r1-eth0")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
