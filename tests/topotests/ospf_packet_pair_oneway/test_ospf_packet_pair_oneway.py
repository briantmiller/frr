#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_ospf_packet_pair_oneway.py
#
# Copyright (c) 2026
#

"""
Test one-way (per direction) packet-pair measurement between OSPF
neighbors.

Topology:

     +----+ r1-eth0   +----+   r2-eth0 +----+
     | r1 +-----------+ s1 +-----------+ r2 |   OSPF point-to-point
     +----+  .1       +-+--+        .2 +----+   10.0.12.0/24
                        |
                        | r3-eth0 .3  (no OSPF: not a neighbor)
                      +-+--+
                      | r3 |
                      +----+

Both r1 and r2 run "ip ospf packet-pair interval 2 probes 8".  Each
measures how the other's probes arrive and reports the result back, so
each side learns its outbound speed (reported by the peer) as well as its
inbound speed (measured locally).

The asymmetric link is emulated with shapers on the switch ports, which
neither router's qdisc bypass can skip:
  s1 port towards r2: 5 Mbit/s   (r1 -> r2)
  s1 port towards r1: 20 Mbit/s  (r2 -> r1)

Verified:
  - without shaping both sides have outbound and inbound results, and one
    side's outbound is the other side's inbound
  - with asymmetric shaping, the round-trip estimate follows the slower
    direction while outbound/inbound follow each direction
  - "ip ospf packet-pair responder": r2 stops probing but keeps measuring
    and reporting; r1's inbound result from r2 expires
  - with packet-pair removed from r2, r1's outbound result expires
  - probes from a host that is not an OSPF neighbor are not measured or
    answered with a report
  - payload version checking: probes and reports of another version from
    a neighbor are ignored and counted, the neighbor detail says why, and
    the neighbor's real version-1 traffic keeps working; another
    version from a non-neighbor is not even counted
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
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd]

UP_KBPS = 5000  # r1 -> r2
DOWN_KBPS = 20000  # r2 -> r1
TOLERANCE = 0.25


def build_topo(tgen):
    "Build function"
    for rname in ["r1", "r2", "r3"]:
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    for rname in ["r1", "r2", "r3"]:
        switch.add_link(tgen.gears[rname])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


#
# Helpers
#


def _pp(router, nbr_rid):
    try:
        data = json.loads(router.vtysh_cmd("show ip ospf neighbor detail json"))
    except ValueError:
        return None
    for entry in data.get("neighbors", {}).get(nbr_rid, []):
        return entry.get("packetPair")
    return None


def _switch_port(tgen, rname):
    "The s1 port facing rname's eth0 (shaping it shapes traffic to rname)."
    peer_index = tgen.net[rname].cmd("cat /sys/class/net/{}-eth0/iflink".format(rname))
    rc, out, _ = tgen.net["s1"].cmd_status("ip -o link show master s1")
    for line in out.splitlines():
        m = re.match(r"(\d+): ([^:@]+)", line)
        if m and m.group(1) == peer_index.strip():
            return m.group(2)
    pytest.fail("no s1 port for {}: {}".format(rname, out))


def _shape_towards(tgen, rname, kbps):
    port = _switch_port(tgen, rname)
    rc, out, err = tgen.net["s1"].cmd_status(
        "tc qdisc replace dev {} root tbf rate {}kbit burst 1600 "
        "latency 400ms".format(port, kbps)
    )
    if rc:
        pytest.skip("tc tbf not available: {} {}".format(out, err))


def _unshape_towards(tgen, rname):
    tgen.net["s1"].cmd_status(
        "tc qdisc del dev {} root".format(_switch_port(tgen, rname))
    )


def _near(value, kbps, tolerance=TOLERANCE):
    return abs(value - kbps) <= kbps * tolerance


def _check_dir(router, nbr_rid, key, kbps=None, min_samples=1):
    "Check the outbound or inbound result towards/from a neighbor."
    pp = _pp(router, nbr_rid)
    if pp is None:
        return "no packetPair data"
    ow = pp.get(key)
    if ow is None:
        return "no {} result: {}".format(key, pp)
    if ow.get("samples", 0) < min_samples:
        return "{} has {} samples".format(key, ow.get("samples"))
    if ow.get("pairsValid", 0) == 0 or ow.get("estimatedSpeedKbps", 0) <= 0:
        return "{} has no valid pairs: {}".format(key, ow)
    if kbps is not None and not _near(ow["estimatedSpeedKbps"], kbps):
        return "{} {} kbps not within {:.0%} of {}".format(
            key, ow["estimatedSpeedKbps"], TOLERANCE, kbps
        )
    return None


def _pp_intf(router, ifname):
    try:
        data = json.loads(router.vtysh_cmd("show ip ospf interface json"))
    except ValueError:
        return {}
    return data.get("interfaces", {}).get(ifname, {}).get("packetPair", {})


def _forge(tgen, host, *args):
    "Run forge_probes.py in host's namespace; skip if scapy is missing."
    rc, _, _ = tgen.net[host].cmd_status("python3 -c 'import scapy.all'", warn=False)
    if rc:
        pytest.skip("scapy not installed")
    script = os.path.join(CWD, "forge_probes.py")
    out = tgen.net[host].cmd("python3 {} {}".format(script, " ".join(args)))
    logger.info("forge_probes.py %s on %s: %s", " ".join(args), host, out)
    return out


def _expect(func, count=30, wait=1, msg=""):
    _, result = topotest.run_and_expect(func, None, count=count, wait=wait)
    assert result is None, "{}: {}".format(msg, result)


def _skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


#
# Tests
#


def test_adjacency():
    "r1 and r2 become Full neighbors."
    tgen = get_topogen()
    _skip_on_failure(tgen)

    for router, nbr in (("r1", "2.2.2.2"), ("r2", "1.1.1.1")):
        expected = {"neighbors": {nbr: [{"nbrState": "Full/-"}]}}
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ip ospf neighbor json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "{} not Full with {}".format(router, nbr)


def test_both_directions_reported():
    "Each side gets outbound (reported) and inbound (measured) results."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    for router, nbr in ((r1, "2.2.2.2"), (r2, "1.1.1.1")):
        for key in ("outbound", "inbound"):
            _expect(
                partial(_check_dir, router, nbr, key),
                msg="{} {} result".format(router.name, key),
            )

    pp1, pp2 = _pp(r1, "2.2.2.2"), _pp(r2, "1.1.1.1")
    logger.info("r1: %s", pp1)
    logger.info("r2: %s", pp2)
    for ow in (pp1["outbound"], pp1["inbound"]):
        assert ow["pairsSent"] == 8 and ow["probeSizeBytes"] == 1500, ow
        assert ow["jitterUsec"] >= 0 and ow["interPacketDelayUsec"] > 0, ow

    output = r1.vtysh_cmd("show ip ospf neighbor detail")
    for pattern in (
        r"Outbound speed [\d.]+ [kMG]bps \(smoothed [\d.]+ [kMG]bps\), "
        r"one-way jitter [\d.]+ ms",
        r"Reported by peer [\d.]+s ago: \d+/8 pairs valid, \d+/16 packets received",
        r"Inbound speed [\d.]+ [kMG]bps \(smoothed [\d.]+ [kMG]bps\), "
        r"one-way jitter [\d.]+ ms",
        r"Measured from peer's probes [\d.]+s ago",
    ):
        assert re.search(pattern, output), "missing '{}' in:\n{}".format(
            pattern, output
        )


def test_asymmetric_link():
    "Each direction is measured separately on an asymmetric link."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    s1 = _pp(r1, "2.2.2.2")
    s2 = _pp(r2, "1.1.1.1")
    _shape_towards(tgen, "r2", UP_KBPS)
    _shape_towards(tgen, "r1", DOWN_KBPS)
    try:
        # Wait for samples taken entirely after the change.
        checks = (
            (r1, "2.2.2.2", "outbound", UP_KBPS, s1["outbound"]["samples"]),
            (r1, "2.2.2.2", "inbound", DOWN_KBPS, s1["inbound"]["samples"]),
            (r2, "1.1.1.1", "outbound", DOWN_KBPS, s2["outbound"]["samples"]),
            (r2, "1.1.1.1", "inbound", UP_KBPS, s2["inbound"]["samples"]),
        )
        for router, nbr, key, kbps, before in checks:
            _expect(
                partial(_check_dir, router, nbr, key, kbps, before + 2),
                count=20,
                wait=2,
                msg="{} {} not near {} kbps".format(router.name, key, kbps),
            )

        # The round trip is limited by the slower direction.
        for router, nbr in ((r1, "2.2.2.2"), (r2, "1.1.1.1")):
            pp = _pp(router, nbr)
            logger.info("%s with asymmetric shaping: %s", router.name, pp)
            assert _near(pp["estimatedSpeedKbps"], UP_KBPS), pp

        output = r1.vtysh_cmd("show ip ospf neighbor detail")
        logger.info("r1 neighbor detail:\n%s", output)
    finally:
        _unshape_towards(tgen, "r2")
        _unshape_towards(tgen, "r1")


def test_non_neighbor_ignored():
    "Probes from a host that isn't an OSPF neighbor get no report."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    out = _forge(tgen, "r3", "probe", "r3-eth0", "10.0.12.3", "10.0.12.1")
    replies = re.search(r"REPLIES (\d+)", out)
    assert replies and int(replies.group(1)) > 0, "probes did not reach r1: " + out
    assert "REPORTS 0" in out, out


def test_version_mismatch():
    "Probes and reports of another payload version are ignored and counted."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    intf = _pp_intf(r1, "r1-eth0")
    assert intf["version"] == 1 and intf["versionMismatches"] == 0, intf
    inbound_before = _pp(r1, "2.2.2.2")["inbound"]["samples"]

    # Another version from a non-neighbor: dropped without a trace.
    out = _forge(tgen, "r3", "probe", "r3-eth0", "10.0.12.3", "10.0.12.1", "2")
    assert "REPORTS 0" in out, out
    assert _pp_intf(r1, "r1-eth0")["versionMismatches"] == 0

    # Version 2 probes claiming to come from neighbor r2: they reach r1
    # (its kernel echoes them) but are not measured.
    out = _forge(tgen, "r3", "probe", "r3-eth0", "10.0.12.2", "10.0.12.1", "2")
    intf = _pp_intf(r1, "r1-eth0")
    logger.info("r1 after version 2 probes: %s", intf)
    assert intf["versionMismatches"] >= 4, intf
    assert intf["versionMismatchLastSource"] == "10.0.12.2", intf
    assert intf["versionMismatchLastVersion"] == 2, intf

    # A version 2 report from r2 for one of r1's real samples.
    count = intf["versionMismatches"]
    out = _forge(tgen, "r2", "report", "r2-eth0", "10.0.12.2", "10.0.12.1", "2")
    assert "REPORTED" in out, out
    _expect(
        lambda: (
            None
            if _pp_intf(r1, "r1-eth0")["versionMismatches"] > count
            else "report not counted"
        ),
        count=5,
        msg="version 2 report",
    )

    output = r1.vtysh_cmd("show ip ospf interface r1-eth0")
    assert re.search(
        r"Ignored \d+ packet-pair messages from peers using another version "
        r"than 1 \(last: 10\.0\.12\.2, version 2",
        output,
    ), output
    output = r1.vtysh_cmd("show ip ospf neighbor detail")
    assert (
        "Peer uses packet-pair version 2, this router version 1: "
        "its probes and reports are ignored" in output
    ), output
    assert _pp(r1, "2.2.2.2").get("peerVersion") == 2

    # r2's real version 1 probes are still measured.
    _expect(
        partial(_check_dir, r1, "2.2.2.2", "inbound", None, inbound_before + 2),
        count=15,
        msg="r2's version 1 probes no longer measured",
    )


def test_responder():
    "A responder measures and reports without probing."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    r2.vtysh_cmd("""
        configure terminal
         interface r2-eth0
          ip ospf packet-pair responder
        """)
    assert re.search(
        r"^ ip ospf packet-pair responder$",
        r2.vtysh_cmd("show running-config"),
        re.M,
    )
    out = r2.vtysh_cmd("show ip ospf interface r2-eth0")
    assert "Packet-pair responder active" in out, out

    before = _pp(r1, "2.2.2.2")["outbound"]["samples"]
    _expect(
        partial(_check_dir, r1, "2.2.2.2", "outbound", None, before + 2),
        count=15,
        msg="r1 gets no reports from responder r2",
    )

    def _r2_responder_only():
        pp = _pp(r2, "1.1.1.1")
        if not pp or not pp.get("responder"):
            return "r2 not shown as responder: {}".format(pp)
        if "samples" in pp or "outbound" in pp:
            return "r2 still shows its own probing results: {}".format(pp)
        return _check_dir(r2, "1.1.1.1", "inbound")

    _expect(_r2_responder_only, count=10, msg="r2 responder display")

    # r2 no longer probes, so r1's inbound result from it expires.
    def _r1_inbound_gone():
        pp = _pp(r1, "2.2.2.2")
        return None if "inbound" not in pp else "still there: {}".format(pp)

    _expect(_r1_inbound_gone, count=40, msg="r1 inbound did not expire")


def test_peer_without_packet_pair():
    "With packet-pair removed on r2, r1's outbound result expires."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    r2.vtysh_cmd("""
        configure terminal
         interface r2-eth0
          no ip ospf packet-pair responder
        """)
    assert "packet-pair" not in r2.vtysh_cmd("show running-config")

    def _r1_outbound_gone():
        pp = _pp(r1, "2.2.2.2")
        return None if "outbound" not in pp else "still there: {}".format(pp)

    _expect(_r1_outbound_gone, count=20, msg="r1 outbound did not expire")
    assert "Outbound speed not reported" in r1.vtysh_cmd("show ip ospf neighbor detail")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
