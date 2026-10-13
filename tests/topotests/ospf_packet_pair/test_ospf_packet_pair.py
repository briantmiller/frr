#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_ospf_packet_pair.py
#
# Copyright (c) 2026
#

"""
Test OSPF packet-pair link speed estimation ("ip ospf packet-pair").

Topology:

            10.0.12.0/24 (point-to-point)
     +----+ r1-eth0          r2-eth0 +----+
     | r1 +--------------------------+ r2 |
     +-+--+                          +-+--+
       | r1-eth1                       | r2-eth1
       |        10.0.123.0/24          |
     --+--------------+----------------+--  (broadcast, switch s2)
                      | r3-eth0
                    +-+--+
                    | r3 |
                    +----+

Only r1 is configured for packet-pair probing:
  r1-eth0: interval 2, probes 8, dscp 46
  r1-eth1: interval 2, probes 6 (dscp default 0)
r2 and r3 have no packet-pair configuration; they only answer ICMP echo.

Verified:
  - configuration display (running-config, show ip ospf interface [json])
  - RTT, jitter, inter-packet delay and speed in neighbor detail [json]
  - probes bypass the local egress qdisc (PACKET_QDISC_BYPASS): a shaper
    on r1-eth0 does not change the estimate
  - a shaper outside r1's egress qdisc (r2-eth0, reply path) is measured
  - the IP-stack fallback is used and reported while the neighbor's MAC
    is unresolved, and bypass resumes once ARP completes
  - probes carry the configured DSCP on the wire
  - several neighbors on one broadcast segment are each measured
  - a neighbor that ignores ICMP echo is reported as all-lost, no speed
  - reconfiguration to defaults and removal with "no ip ospf packet-pair"
"""

import json
import os
import re
import shutil
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd]

# Shaped bottleneck used by the rate test, and the accepted error.
SHAPED_RATE_KBPS = 5000
RATE_TOLERANCE = 0.30


def build_topo(tgen):
    "Build function"
    for rname in ["r1", "r2", "r3"]:
        tgen.add_router(rname)

    # r1-eth0 <-> r2-eth0, point-to-point
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r1-eth1, r2-eth1, r3-eth0, broadcast
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


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


def _json(router, cmd):
    output = router.vtysh_cmd(cmd)
    try:
        return json.loads(output)
    except ValueError:
        return {}


def _nbr_entry(router, nbr_rid, ifname):
    """
    Return the "show ip ospf neighbor detail json" entry for neighbor
    nbr_rid reached via ifname (a router-id can appear once per interface).
    """
    data = _json(router, "show ip ospf neighbor detail json")
    for entry in data.get("neighbors", {}).get(nbr_rid, []):
        if entry.get("ifaceName") == ifname:
            return entry
    return None


def _check_full(router, expected):
    "expected: list of (nbr_rid, ifname) that must be Full"
    for nbr_rid, ifname in expected:
        entry = _nbr_entry(router, nbr_rid, ifname)
        if entry is None:
            return "{} not seen on {}".format(nbr_rid, ifname)
        if not entry.get("nbrState", "").startswith("Full"):
            return "{} on {} is {}".format(nbr_rid, ifname, entry.get("nbrState"))
    return None


def _pp(router, nbr_rid, ifname):
    entry = _nbr_entry(router, nbr_rid, ifname)
    if entry is None:
        return None
    return entry.get("packetPair")


def _check_pp_valid(router, nbr_rid, ifname, min_samples=1, pairs=None, bypass=True):
    "Return None once a sample with valid RTT and speed is available."
    pp = _pp(router, nbr_rid, ifname)
    if pp is None:
        return "no packetPair data for {} on {}".format(nbr_rid, ifname)
    if bypass is not None and pp.get("txQdiscBypass") != bypass:
        return "txQdiscBypass is {}: {}".format(pp.get("txQdiscBypass"), pp)
    if pp.get("samples", 0) < min_samples:
        return "only {} samples".format(pp.get("samples", 0))
    if pairs is not None and pp.get("pairsSent") != pairs:
        return "pairsSent {} != {}".format(pp.get("pairsSent"), pairs)
    if pp.get("pairsValid", 0) == 0:
        return "no valid pairs: {}".format(pp)
    for key in ("rttMinUsec", "rttAvgUsec", "rttMaxUsec", "estimatedSpeedKbps"):
        if pp.get(key, 0) <= 0:
            return "{} not positive: {}".format(key, pp)
    if not pp["rttMinUsec"] <= pp["rttAvgUsec"] <= pp["rttMaxUsec"]:
        return "RTT min/avg/max not ordered: {}".format(pp)
    if pp.get("interPacketDelayUsec", -1) < 0 or pp.get("jitterUsec", -1) < 0:
        return "missing interPacketDelayUsec/jitterUsec: {}".format(pp)
    return None


def _check_speed_near(router, nbr_rid, ifname, kbps, tolerance, min_samples=0):
    pp = _pp(router, nbr_rid, ifname)
    if pp is None or pp.get("pairsValid", 0) == 0:
        return "no valid sample yet: {}".format(pp)
    if pp.get("samples", 0) < min_samples:
        return "waiting for a sample taken entirely after the change"
    if not pp.get("txQdiscBypass"):
        return "sample not sent with qdisc bypass: {}".format(pp)
    est = pp["estimatedSpeedKbps"]
    if abs(est - kbps) > kbps * tolerance:
        return "estimate {} kbps not within {:.0%} of {} kbps".format(
            est, tolerance, kbps
        )
    return None


def _shape(router, ifname, kbps):
    """
    Put a tbf shaper on ifname's egress. A one-packet burst makes tbf
    serialize a pair like a real link of that rate would.
    """
    out = router.cmd(
        "tc qdisc replace dev {} root tbf rate {}kbit burst 1600 "
        "latency 400ms 2>&1 || echo TC_FAILED".format(ifname, kbps)
    )
    if "TC_FAILED" in out:
        pytest.skip("tc tbf not available: {}".format(out))


def _unshape(router, ifname):
    router.cmd("tc qdisc del dev {} root 2>/dev/null".format(ifname))


def _expect(func, count=30, wait=1, msg=""):
    _, result = topotest.run_and_expect(func, None, count=count, wait=wait)
    assert result is None, "{}: {}".format(msg, result)


def _skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


#
# Tests
#


def test_ospf_convergence():
    "Wait for all adjacencies to reach Full."
    tgen = get_topogen()
    _skip_on_failure(tgen)

    r1 = tgen.gears["r1"]
    _expect(
        partial(
            _check_full,
            r1,
            [("2.2.2.2", "r1-eth0"), ("2.2.2.2", "r1-eth1"), ("3.3.3.3", "r1-eth1")],
        ),
        count=60,
        msg="r1 adjacencies did not come up",
    )


def test_packet_pair_config_display():
    "Configuration shows up in running-config and show ip ospf interface."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    running = r1.vtysh_cmd("show running-config")
    assert "ip ospf packet-pair interval 2 probes 8 dscp 46" in running
    assert "ip ospf packet-pair interval 2 probes 6\n" in running

    expected = {
        "interfaces": {
            "r1-eth0": {
                "packetPair": {
                    "enabled": True,
                    "running": True,
                    "intervalSec": 2,
                    "pairsPerSample": 8,
                    "dscp": 46,
                    "qdiscBypass": True,
                    "version": 1,
                    "versionMismatches": 0,
                }
            },
            "r1-eth1": {
                "packetPair": {
                    "enabled": True,
                    "running": True,
                    "intervalSec": 2,
                    "pairsPerSample": 6,
                    "dscp": 0,
                    "qdiscBypass": True,
                }
            },
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip ospf interface json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "packet-pair interface JSON mismatch"

    output = r1.vtysh_cmd("show ip ospf interface r1-eth0")
    assert re.search(
        r"Packet-pair probing active: interval 2s, 8 pairs per sample, DSCP 46", output
    ), output
    assert "Probes bypass the egress qdisc (PACKET_QDISC_BYPASS)" in output

    # Not configured on r2: no packet-pair section at all.
    data = _json(tgen.gears["r2"], "show ip ospf interface r2-eth0 json")
    assert "packetPair" not in data.get("interfaces", {}).get("r2-eth0", {})


def test_packet_pair_neighbor_stats():
    "RTT, jitter, inter-packet delay and speed appear in neighbor detail."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    _expect(
        partial(_check_pp_valid, r1, "2.2.2.2", "r1-eth0", pairs=8),
        msg="no packet-pair results towards r2 on r1-eth0",
    )

    pp = _pp(r1, "2.2.2.2", "r1-eth0")
    logger.info("r1 -> r2 (r1-eth0) packet-pair: %s", pp)
    assert pp["intervalSec"] == 2
    assert pp["pairsPerSample"] == 8
    assert pp["dscp"] == 46
    assert pp["probeSizeBytes"] == 1500
    assert pp["estimatedSpeedSmoothedKbps"] > 0
    assert pp["txQdiscBypass"] is True
    assert "txQdiscBypassReason" not in pp

    output = r1.vtysh_cmd("show ip ospf neighbor detail")
    for pattern in (
        r"Packet-pair probing: interval 2s, 8 pairs per sample, DSCP 46",
        r"RTT min/avg/max [\d.]+/[\d.]+/[\d.]+ ms, jitter [\d.]+ ms",
        r"Inter-packet delay avg [\d.]+ ms",
        r"Estimated speed [\d.]+ [kMG]bps \(smoothed [\d.]+ [kMG]bps\)",
        r"Transmit path: qdisc bypass \(local egress QoS excluded\)",
    ):
        assert re.search(pattern, output), "missing '{}' in:\n{}".format(
            pattern, output
        )

    # Routers without packet-pair configured show nothing.
    output = tgen.gears["r2"].vtysh_cmd("show ip ospf neighbor detail")
    assert "Packet-pair" not in output


def test_packet_pair_local_qdisc_bypassed():
    "A shaper on r1's own egress does not affect the estimate."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    # Unshaped veth estimate, for reference (typically Gbit/s).
    _expect(partial(_check_pp_valid, r1, "2.2.2.2", "r1-eth0"))
    before = _pp(r1, "2.2.2.2", "r1-eth0")["samples"]

    _shape(r1, "r1-eth0", SHAPED_RATE_KBPS)
    try:
        # Require two more samples so neither straddles the change.
        _expect(
            partial(_check_pp_valid, r1, "2.2.2.2", "r1-eth0", min_samples=before + 2),
            count=20,
            wait=1,
            msg="no samples while r1-eth0 is shaped",
        )
        pp = _pp(r1, "2.2.2.2", "r1-eth0")
        logger.info("r1-eth0 shaped to %d kbps, estimate: %s", SHAPED_RATE_KBPS, pp)
        assert pp["txQdiscBypass"] is True, pp
        # Through the qdisc this would read ~5 Mbit/s; the link is far faster.
        assert pp["estimatedSpeedKbps"] > 10 * SHAPED_RATE_KBPS, pp

        # The shaper is really in effect for normal traffic: OSPF packets
        # went through it and tbf accounted for them.
        stats = r1.cmd("tc -s qdisc show dev r1-eth0")
        logger.info("r1-eth0 qdisc:\n%s", stats)
        assert re.search(r"qdisc tbf .*rate 5Mbit", stats), stats
        sent = re.search(r"Sent (\d+) bytes (\d+) pkt", stats)
        assert sent and int(sent.group(2)) > 0, stats
    finally:
        _unshape(r1, "r1-eth0")


def test_packet_pair_remote_shaping_measured():
    "A bottleneck beyond r1's egress qdisc (r2's reply path) is measured."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    before = _pp(r1, "2.2.2.2", "r1-eth0")["samples"]
    _shape(r2, "r2-eth0", SHAPED_RATE_KBPS)
    try:
        _expect(
            partial(
                _check_speed_near,
                r1,
                "2.2.2.2",
                "r1-eth0",
                SHAPED_RATE_KBPS,
                RATE_TOLERANCE,
                before + 2,
            ),
            count=20,
            wait=2,
            msg="speed estimate did not converge on the shaped rate",
        )
        pp = _pp(r1, "2.2.2.2", "r1-eth0")
        logger.info("r2-eth0 shaped to %d kbps, estimate: %s", SHAPED_RATE_KBPS, pp)
        # 1500 byte probes at 5 Mbit/s are 2.4 ms apart.
        expected_ipd = 1500 * 8 * 1000 // SHAPED_RATE_KBPS
        assert (
            abs(pp["interPacketDelayUsec"] - expected_ipd)
            <= expected_ipd * RATE_TOLERANCE
        ), pp
    finally:
        _unshape(r2, "r2-eth0")


def test_packet_pair_fallback_without_arp():
    "With the neighbor MAC unresolved, the IP path is used, then bypass resumes."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    def _check_fallback():
        # Flush r1's ARP cache right before a sample starts. On this
        # point-to-point link OSPF only sends multicast, so nothing but
        # the probes themselves re-resolves r2's MAC.
        r1.cmd("ip neigh flush dev r1-eth0")
        before = _pp(r1, "2.2.2.2", "r1-eth0")["samples"]
        for _ in range(6):
            topotest.sleep(0.5)
            pp = _pp(r1, "2.2.2.2", "r1-eth0")
            if pp["samples"] > before:
                if pp["txQdiscBypass"] is False:
                    return None
                before = pp["samples"]
                r1.cmd("ip neigh flush dev r1-eth0")
        return "no sample sent via the IP path: {}".format(pp)

    _expect(_check_fallback, count=5, wait=0, msg="fallback not observed")
    pp = _pp(r1, "2.2.2.2", "r1-eth0")
    logger.info("fallback sample: %s", pp)
    assert pp["txQdiscBypassReason"] == "neighbor MAC not resolved", pp
    output = r1.vtysh_cmd("show ip ospf neighbor detail")
    assert (
        "Transmit path: IP stack, local egress QoS applies "
        "(neighbor MAC not resolved)" in output
    ), output

    # The fallback sample triggered ARP; bypass is used again afterwards.
    _expect(
        partial(
            _check_pp_valid, r1, "2.2.2.2", "r1-eth0", min_samples=pp["samples"] + 1
        ),
        count=10,
        msg="bypass did not resume after ARP resolution",
    )


def test_packet_pair_dscp_on_wire():
    "Probes and their replies carry the configured DSCP (46 -> TOS 0xb8)."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    if not shutil.which("tcpdump"):
        pytest.skip("tcpdump not installed")

    r2 = tgen.gears["r2"]
    # Interval is 2s, so 6s always covers at least one sample.
    out = r2.cmd(
        "timeout 6 tcpdump -l -c 4 -nv -i r2-eth0 "
        "'icmp[icmptype] == icmp-echo and src host 10.0.12.1' 2>/dev/null"
    )
    logger.info("tcpdump on r2-eth0:\n%s", out)
    tos = re.findall(r"tos (0x[0-9a-f]+)", out)
    assert tos, "no probe packets captured:\n{}".format(out)
    assert all(t == "0xb8" for t in tos), "unexpected TOS: {}".format(tos)
    # ospfd builds the IP header itself for the bypass path.
    assert "flags [DF], proto ICMP (1), length 1500" in out, out
    assert "10.0.12.1 > 10.0.12.2: ICMP echo request" in out, out


def test_packet_pair_broadcast_neighbors():
    "Each neighbor on a broadcast segment is measured independently."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    for rid in ("2.2.2.2", "3.3.3.3"):
        _expect(
            partial(_check_pp_valid, r1, rid, "r1-eth1", pairs=6),
            msg="no packet-pair results towards {} on r1-eth1".format(rid),
        )
        pp = _pp(r1, rid, "r1-eth1")
        logger.info("r1 -> %s (r1-eth1) packet-pair: %s", rid, pp)
        assert pp["dscp"] == 0
        assert pp["pairsPerSample"] == 6


def test_packet_pair_no_icmp_reply():
    "A neighbor that ignores ICMP echo is reported as lost, no speed."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    def _check_all_lost():
        pp = _pp(r1, "3.3.3.3", "r1-eth1")
        if pp is None or pp.get("pairsSent", 0) == 0:
            return "no sample: {}".format(pp)
        if pp["pairsValid"] != 0 or pp["packetsLost"] != 2 * pp["pairsSent"]:
            return "sample not fully lost yet: {}".format(pp)
        if pp["estimatedSpeedKbps"] != 0 or pp["rttAvgUsec"] != 0:
            return "stale results reported: {}".format(pp)
        return None

    r3.cmd_raises("sysctl -qw net.ipv4.icmp_echo_ignore_all=1")
    try:
        _expect(_check_all_lost, count=15, msg="loss not reported")
        output = r1.vtysh_cmd("show ip ospf neighbor detail")
        assert "RTT unavailable" in output
        assert "Estimated speed unavailable" in output
        # The adjacency itself is unaffected.
        assert _check_full(r1, [("3.3.3.3", "r1-eth1")]) is None
    finally:
        r3.cmd("sysctl -qw net.ipv4.icmp_echo_ignore_all=0")

    _expect(
        partial(_check_pp_valid, r1, "3.3.3.3", "r1-eth1"),
        count=15,
        msg="no recovery after ICMP echo re-enabled",
    )


def test_packet_pair_reconfigure_defaults():
    "Re-entering the command without options reverts to defaults."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("""
        configure terminal
         interface r1-eth1
          ip ospf packet-pair
        """)
    running = r1.vtysh_cmd("show running-config")
    assert re.search(r"^ ip ospf packet-pair$", running, re.M), running

    expected = {
        "interfaces": {
            "r1-eth1": {
                "packetPair": {
                    "running": True,
                    "intervalSec": 60,
                    "pairsPerSample": 10,
                    "dscp": 0,
                }
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip ospf interface r1-eth1 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert result is None, "defaults not applied"

    # Out-of-range values are rejected by the CLI.
    for bad in ("interval 0", "probes 1", "probes 65", "dscp 64"):
        out = r1.vtysh_cmd(
            "configure terminal\ninterface r1-eth1\nip ospf packet-pair {}".format(bad)
        )
        assert "Unknown command" in out or "%" in out, "accepted '{}'".format(bad)


def test_packet_pair_disable():
    '"no ip ospf packet-pair" stops probing and removes the statistics.'
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("""
        configure terminal
         interface r1-eth0
          no ip ospf packet-pair
         interface r1-eth1
          no ip ospf packet-pair
        """)

    running = r1.vtysh_cmd("show running-config")
    assert "packet-pair" not in running

    def _check_gone():
        for rid, ifname in (
            ("2.2.2.2", "r1-eth0"),
            ("2.2.2.2", "r1-eth1"),
            ("3.3.3.3", "r1-eth1"),
        ):
            entry = _nbr_entry(r1, rid, ifname)
            if entry is None:
                return "{} on {} missing".format(rid, ifname)
            if "packetPair" in entry:
                return "packetPair still present for {} on {}".format(rid, ifname)
        return None

    _expect(_check_gone, count=5, msg="statistics not removed")

    intf = _json(r1, "show ip ospf interface json").get("interfaces", {})
    assert "packetPair" not in intf.get("r1-eth0", {})
    assert "packetPair" not in intf.get("r1-eth1", {})

    # No more probes leave r1 (r2 is not probing, so any echo is from r1).
    if shutil.which("tcpdump"):
        out = tgen.gears["r2"].cmd(
            "timeout 5 tcpdump -l -c 1 -n -i r2-eth0 "
            "'icmp[icmptype] == icmp-echo' 2>/dev/null"
        )
        assert "ICMP echo request" not in out, out

    # Adjacencies are untouched.
    assert _check_full(r1, [("2.2.2.2", "r1-eth0"), ("3.3.3.3", "r1-eth1")]) is None


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
