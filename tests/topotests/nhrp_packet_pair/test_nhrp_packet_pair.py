#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_nhrp_packet_pair.py
#
# Copyright (c) 2026
#

"""
Test NHRP packet-pair link speed estimation ("ip nhrp packet-pair").

Topology (same underlay as nhrp_topo):

                                        +------+
                                        |  r2  |  NHS (hub)
                                        +--+---+
                                   r2-eth0 | .2     10.2.1.0/24
                                        +--+---+
                                        |  r3  |  underlay router
                                        +--+---+
                                           | .3     10.1.1.0/24
                 +------+ .1               |                .4 +------+
                 |  r1  +------------------+-------------------+  r4  |
                 +------+ r1-eth0                      r4-eth0 +------+
                 NHC (spoke)                                NHC (spoke)

    mGRE tunnels rX-gre0, key 42, 10.255.255.X/32

Packet-pair configuration:
  r1-gre0: interval 2, probes 6, dscp 46  -> probes its NHS, r2
  r2-gre0: interval 2, probes 4           -> probes its clients, r1 and r4
  r4-gre0: none                           -> only answers probes

Verified:
  - configuration display (running-config, show ip nhrp packet-pair [json])
  - a client probes its active NHS; an NHS probes each registered client
  - probes bypass both the tunnel and the underlay egress qdisc: shapers
    on r1-gre0 and r1-eth0 don't change r1's estimate
  - a shaper beyond the local egress qdiscs (r2-eth0, the reply path) is
    measured
  - when the frame can't be built (GRE checksums enabled) probes fall back
    to tunnel-only bypass, and the reason is reported
  - probes carry the configured DSCP inside the tunnel, the outer header
    follows the tunnel's tos setting, and the GRE key is set
  - spoke-to-spoke shortcut peers are not probed
  - one-way results: r1 and r2 each measure the other's probes and report
    back, giving outbound and inbound speeds per peer; with shapers on the
    underlay router r3 (r1 -> r2: 5 Mbit/s, r2 -> r1: 20 Mbit/s) each
    direction is measured separately
  - "ip nhrp packet-pair responder" on r4 lets the hub learn its outbound
    speed to r4 without r4 probing
  - results reach zebra ("show zebra detected-bandwidth") as nhrp next
    hops per tunnel, combined per interface by "detected-bandwidth
    aggregate max|sum"
  - "no ip nhrp packet-pair" stops probing
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
from lib.common_config import required_linux_kernel_version
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.nhrpd]

SHAPED_RATE_KBPS = 5000
RATE_TOLERANCE = 0.30

R1_GRE = "10.255.255.1"
R2_GRE = "10.255.255.2"
R4_GRE = "10.255.255.4"


def build_topo(tgen):
    "Build function"
    for rname in ["r1", "r2", "r3", "r4"]:
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r4"])


def _populate_iface():
    tgen = get_topogen()
    gre = (
        "ip tunnel add {0}-gre0 mode gre ttl 64 key 42 dev {0}-eth0 "
        "local {1} remote 0.0.0.0"
    )
    common = [
        "ip link set dev {0}-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-eth0/disable_ipv6",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-gre0/disable_ipv6",
    ]
    hub_redirect = (
        "iptables -A FORWARD -i {0}-gre0 -o {0}-gre0 -m hashlimit "
        "--hashlimit-upto 4/minute --hashlimit-burst 1 "
        "--hashlimit-mode srcip,dstip --hashlimit-srcmask 24 "
        "--hashlimit-dstmask 24 --hashlimit-name loglimit-0 "
        "-j NFLOG --nflog-group 1 --nflog-range 128"
    )

    for rname, local in (("r1", "10.1.1.1"), ("r2", "10.2.1.2"), ("r4", "10.1.1.4")):
        cmds = [gre.format(rname, local)] + [c.format(rname) for c in common]
        if rname == "r2":
            cmds.append(hub_redirect.format(rname))
        for cmd in cmds:
            output = tgen.net[rname].cmd(cmd)
            logger.info("%s: %s -> %s", rname, cmd, output)


def setup_module(mod):
    "Sets up the pytest environment"
    result = required_linux_kernel_version("4.18")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    _populate_iface()

    gre_ok = tgen.net["r1"].cmd("ip link show r1-gre0 >/dev/null 2>&1 && echo GRE_OK")
    if "GRE_OK" not in gre_ok:
        tgen.stop_topology()
        pytest.skip("kernel lacks GRE tunnel support")

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
    try:
        return json.loads(router.vtysh_cmd(cmd))
    except ValueError:
        return {}


def _pp_if(router, ifname):
    return _json(router, "show ip nhrp packet-pair json").get(ifname)


def _pp_peer(router, ifname, peer):
    intf = _pp_if(router, ifname)
    if not intf:
        return None
    return intf.get("peers", {}).get(peer)


def _check_peer_valid(router, ifname, peer, role, path=None, min_samples=1):
    p = _pp_peer(router, ifname, peer)
    if p is None:
        return "{} not listed on {} {}".format(peer, router.name, ifname)
    if p.get("role") != role:
        return "{} role is {}, expected {}".format(peer, p.get("role"), role)
    if p.get("samples", 0) < min_samples:
        return "only {} samples: {}".format(p.get("samples", 0), p)
    if path is not None and p.get("txPath") != path:
        return "txPath {} != {}: {}".format(p.get("txPath"), path, p)
    if p.get("pairsValid", 0) == 0:
        return "no valid pairs: {}".format(p)
    for key in ("rttMinUsec", "rttAvgUsec", "rttMaxUsec", "estimatedSpeedKbps"):
        if p.get(key, 0) <= 0:
            return "{} not positive: {}".format(key, p)
    if not p["rttMinUsec"] <= p["rttAvgUsec"] <= p["rttMaxUsec"]:
        return "RTT min/avg/max not ordered: {}".format(p)
    return None


def _check_speed_near(router, ifname, peer, kbps, tolerance, min_samples):
    p = _pp_peer(router, ifname, peer)
    if p is None or p.get("pairsValid", 0) == 0:
        return "no valid sample yet: {}".format(p)
    if p.get("samples", 0) < min_samples:
        return "waiting for a sample taken entirely after the change"
    est = p["estimatedSpeedKbps"]
    if abs(est - kbps) > kbps * tolerance:
        return "estimate {} kbps not within {:.0%} of {} kbps".format(
            est, tolerance, kbps
        )
    return None


def _check_oneway(router, ifname, peer, key, kbps=None, min_samples=1):
    "Check a peer's outbound or inbound one-way result."
    p = _pp_peer(router, ifname, peer)
    if p is None:
        return "{} not listed on {}".format(peer, router.name)
    ow = p.get(key)
    if ow is None:
        return "no {} result: {}".format(key, p)
    if ow.get("samples", 0) < min_samples:
        return "{} has {} samples".format(key, ow.get("samples"))
    if ow.get("pairsValid", 0) == 0:
        return "{} has no valid pairs: {}".format(key, ow)
    est = ow.get("estimatedSpeedKbps", 0)
    if kbps is not None and abs(est - kbps) > kbps * RATE_TOLERANCE:
        return "{} {} kbps not within {:.0%} of {}".format(
            key, est, RATE_TOLERANCE, kbps
        )
    return None


def _shape(router, ifname, kbps):
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


def test_registrations():
    "Both spokes register with the hub."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r2 = tgen.gears["r2"]

    def _check():
        cache = _json(r2, "show ip nhrp cache json")
        dyn = {
            e.get("protocol")
            for e in cache.get("table", [])
            if e.get("type") == "dynamic"
        }
        missing = {R1_GRE, R4_GRE} - dyn
        return "missing registrations: {}".format(missing) if missing else None

    _expect(_check, count=60, msg="spokes did not register")


def test_packet_pair_config_display():
    "Configuration shows in running-config and the show command."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    assert "ip nhrp packet-pair interval 2 probes 6 dscp 46" in r1.vtysh_cmd(
        "show running-config"
    )
    assert re.search(
        r"^ ip nhrp packet-pair interval 2 probes 4$",
        r2.vtysh_cmd("show running-config"),
        re.M,
    )

    expected = {
        "r1-gre0": {
            "enabled": True,
            "running": True,
            "qdiscBypass": True,
            "intervalSec": 2,
            "pairsPerSample": 6,
            "dscp": 46,
            "version": 1,
            "versionMismatches": 0,
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip nhrp packet-pair json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "r1 packet-pair JSON mismatch"

    # r4 has no packet-pair configuration.
    assert _json(tgen.gears["r4"], "show ip nhrp packet-pair json") == {}


def test_client_probes_nhs():
    "A spoke probes its NHS, with both egress qdiscs bypassed."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    _expect(
        partial(_check_peer_valid, r1, "r1-gre0", R2_GRE, "nhs", "underlay-bypass"),
        msg="r1 has no packet-pair results for its NHS",
    )
    p = _pp_peer(r1, "r1-gre0", R2_GRE)
    logger.info("r1 -> NHS r2: %s", p)
    assert p["nbma"] == "10.2.1.2"
    assert p["txQdiscBypass"] is True
    assert "txQdiscBypassReason" not in p
    assert p["probeSizeBytes"] == 1472  # tunnel MTU: 1500 - IP - GRE w/ key

    # Only the NHS is probed by a spoke.
    assert set(_pp_if(r1, "r1-gre0")["peers"]) == {R2_GRE}

    output = r1.vtysh_cmd("show ip nhrp packet-pair")
    for pattern in (
        r"Interface r1-gre0: packet-pair probing active, interval 2s, "
        r"6 pairs per sample, DSCP 46",
        r"Peer 10\.255\.255\.2 \(NHS\), NBMA 10\.2\.1\.2",
        r"Transmit path: tunnel and underlay qdisc bypass via r1-eth0",
        r"RTT min/avg/max [\d.]+/[\d.]+/[\d.]+ ms, jitter [\d.]+ ms",
        r"Inter-packet delay avg [\d.]+ ms",
        r"Estimated speed [\d.]+ [kMG]bps \(smoothed [\d.]+ [kMG]bps\)",
    ):
        assert re.search(pattern, output), "missing '{}' in:\n{}".format(
            pattern, output
        )


def test_nhs_probes_clients():
    "The hub probes every registered client."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r2 = tgen.gears["r2"]

    for peer, nbma in ((R1_GRE, "10.1.1.1"), (R4_GRE, "10.1.1.4")):
        _expect(
            partial(
                _check_peer_valid, r2, "r2-gre0", peer, "client", "underlay-bypass"
            ),
            msg="r2 has no packet-pair results for client {}".format(peer),
        )
        p = _pp_peer(r2, "r2-gre0", peer)
        logger.info("r2 -> client %s: %s", peer, p)
        assert p["nbma"] == nbma

    output = r2.vtysh_cmd("show ip nhrp packet-pair")
    assert "Peer 10.255.255.1 (client), NBMA 10.1.1.1" in output, output
    assert "Peer 10.255.255.4 (client), NBMA 10.1.1.4" in output, output
    assert "Transmit path: tunnel and underlay qdisc bypass via r2-eth0" in output


def test_local_qdiscs_bypassed():
    "Shapers on r1's tunnel and underlay interfaces don't affect its estimate."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    before = _pp_peer(r1, "r1-gre0", R2_GRE)["samples"]
    _shape(r1, "r1-gre0", SHAPED_RATE_KBPS)
    _shape(r1, "r1-eth0", SHAPED_RATE_KBPS)
    try:
        _expect(
            partial(
                _check_peer_valid,
                r1,
                "r1-gre0",
                R2_GRE,
                "nhs",
                "underlay-bypass",
                before + 2,
            ),
            count=20,
            msg="no samples while r1 is shaped",
        )
        p = _pp_peer(r1, "r1-gre0", R2_GRE)
        logger.info("r1 shaped to %d kbps, estimate: %s", SHAPED_RATE_KBPS, p)
        assert p["estimatedSpeedKbps"] > 10 * SHAPED_RATE_KBPS, p

        # The shapers are in effect for other traffic (NHRP registrations
        # go through both).
        for ifname in ("r1-gre0", "r1-eth0"):
            stats = r1.cmd("tc -s qdisc show dev {}".format(ifname))
            logger.info("%s qdisc:\n%s", ifname, stats)
            sent = re.search(r"Sent (\d+) bytes (\d+) pkt", stats)
            assert sent and int(sent.group(2)) > 0, stats
    finally:
        _unshape(r1, "r1-gre0")
        _unshape(r1, "r1-eth0")


def test_remote_shaping_measured():
    "A bottleneck on the reply path (r2-eth0) is measured by r1."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    before = _pp_peer(r1, "r1-gre0", R2_GRE)["samples"]
    before_hub = _pp_peer(r2, "r2-gre0", R1_GRE)["samples"]
    _shape(r2, "r2-eth0", SHAPED_RATE_KBPS)
    try:
        _expect(
            partial(
                _check_speed_near,
                r1,
                "r1-gre0",
                R2_GRE,
                SHAPED_RATE_KBPS,
                RATE_TOLERANCE,
                before + 2,
            ),
            count=20,
            wait=2,
            msg="r1's estimate did not converge on the shaped rate",
        )
        logger.info(
            "r2-eth0 shaped to %d kbps, r1 estimate: %s",
            SHAPED_RATE_KBPS,
            _pp_peer(r1, "r1-gre0", R2_GRE),
        )

        # r2's own probes to r1 bypass r2-eth0's qdisc, and r1's replies
        # don't cross it, so r2 still sees the unshaped path.
        _expect(
            partial(
                _check_peer_valid,
                r2,
                "r2-gre0",
                R1_GRE,
                "client",
                "underlay-bypass",
                before_hub + 2,
            ),
            count=20,
        )
        p = _pp_peer(r2, "r2-gre0", R1_GRE)
        logger.info("r2 -> r1 while r2-eth0 shaped: %s", p)
        assert p["estimatedSpeedKbps"] > 10 * SHAPED_RATE_KBPS, p
    finally:
        _unshape(r2, "r2-eth0")


def test_probes_on_wire():
    "Inner DSCP 46, outer TOS per tunnel config (0), GRE key 42."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    if not shutil.which("tcpdump"):
        pytest.skip("tcpdump not installed")

    r3 = tgen.gears["r3"]
    # Probes are 1472 bytes inside, 1500 outside; byte 48 of the outer
    # packet is the inner ICMP type (20 IP + 8 GRE with key + 20 IP).
    out = r3.cmd(
        "timeout 6 tcpdump -l -c 2 -nvv -i r3-eth0 "
        "'src host 10.1.1.1 and ip proto 47 and ip[2:2] == 1500 "
        "and ip[48] == 8' 2>/dev/null"
    )
    logger.info("tcpdump on r3-eth0:\n%s", out)
    assert "key=0x2a" in out, out
    assert re.search(r"IP \(tos 0x0, ttl 64, .*flags \[DF\], proto GRE", out), out
    assert re.search(r"IP \(tos 0xb8, ttl 64, .*proto ICMP \(1\), length 1472", out)
    assert "10.255.255.1 > 10.255.255.2: ICMP echo request" in out, out
    assert "bad cksum" not in out and "wrong" not in out, out


def test_fallback_tunnel_bypass():
    "With GRE checksums on, probes fall back to tunnel-only bypass."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]

    out = r1.cmd("ip link set dev r1-gre0 type gre ocsum 2>&1 || echo FAILED")
    details = r1.cmd("ip -d link show r1-gre0")
    if "FAILED" in out or "ocsum" not in details:
        pytest.skip("can't enable GRE checksums: {} {}".format(out, details))

    try:
        before = _pp_peer(r1, "r1-gre0", R2_GRE)["samples"]
        _expect(
            partial(
                _check_peer_valid,
                r1,
                "r1-gre0",
                R2_GRE,
                "nhs",
                "tunnel-bypass",
                before + 1,
            ),
            count=15,
            msg="no tunnel-bypass sample with GRE checksums enabled",
        )
        p = _pp_peer(r1, "r1-gre0", R2_GRE)
        logger.info("r1 with ocsum: %s", p)
        assert p["txQdiscBypass"] is True
        assert p["txQdiscBypassReason"] == "GRE checksum or sequence numbers enabled"
        output = r1.vtysh_cmd("show ip nhrp packet-pair")
        assert (
            "Transmit path: tunnel qdisc bypass, underlay qdisc applies "
            "(GRE checksum or sequence numbers enabled)" in output
        ), output
    finally:
        r1.cmd("ip link set dev r1-gre0 type gre noocsum")
        if "ocsum" in r1.cmd("ip -d link show r1-gre0"):
            r1.cmd(
                "ip tunnel change r1-gre0 mode gre ttl 64 key 42 "
                "local 10.1.1.1 remote 0.0.0.0"
            )

    _expect(
        partial(_check_peer_valid, r1, "r1-gre0", R2_GRE, "nhs", "underlay-bypass"),
        count=15,
        msg="underlay bypass did not resume",
    )


def test_oneway_results():
    "r1 and r2 report each other's probes: outbound and inbound per peer."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    for router, ifname, peer in (
        (r1, "r1-gre0", R2_GRE),
        (r2, "r2-gre0", R1_GRE),
    ):
        for key in ("outbound", "inbound"):
            _expect(
                partial(_check_oneway, router, ifname, peer, key),
                msg="{} has no {} result for {}".format(router.name, key, peer),
            )
    logger.info("r1 -> NHS r2: %s", _pp_peer(r1, "r1-gre0", R2_GRE))

    # r4 runs no packet-pair: the hub gets no reports from it, and r4
    # sends it no probes.
    p = _pp_peer(r2, "r2-gre0", R4_GRE)
    assert "outbound" not in p and "inbound" not in p, p
    assert "Outbound speed not reported" in r2.vtysh_cmd("show ip nhrp packet-pair")


def test_oneway_asymmetric():
    "Shapers on the underlay router are measured per direction."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    up, down = 5000, 20000  # r1 -> r2, r2 -> r1

    p1 = _pp_peer(r1, "r1-gre0", R2_GRE)
    p2 = _pp_peer(r2, "r2-gre0", R1_GRE)
    _shape(r3, "r3-eth1", up)  # towards r2
    _shape(r3, "r3-eth0", down)  # towards r1 and r4
    try:
        checks = (
            (r1, "r1-gre0", R2_GRE, "outbound", up, p1),
            (r1, "r1-gre0", R2_GRE, "inbound", down, p1),
            (r2, "r2-gre0", R1_GRE, "outbound", down, p2),
            (r2, "r2-gre0", R1_GRE, "inbound", up, p2),
        )
        for router, ifname, peer, key, kbps, before in checks:
            _expect(
                partial(
                    _check_oneway,
                    router,
                    ifname,
                    peer,
                    key,
                    kbps,
                    before[key]["samples"] + 2,
                ),
                count=20,
                wait=2,
                msg="{} {} not near {} kbps".format(router.name, key, kbps),
            )
        for router, ifname, peer in (
            (r1, "r1-gre0", R2_GRE),
            (r2, "r2-gre0", R1_GRE),
        ):
            p = _pp_peer(router, ifname, peer)
            logger.info("%s asymmetric: %s", router.name, p)
            # The round trip is limited by the slower direction.
            assert abs(p["estimatedSpeedKbps"] - up) <= up * RATE_TOLERANCE, p
        output = r1.vtysh_cmd("show ip nhrp packet-pair")
        logger.info("r1:\n%s", output)
        assert re.search(r"Outbound speed [\d.]+ Mbps", output), output
        assert re.search(r"Inbound speed [\d.]+ Mbps", output), output
    finally:
        _unshape(r3, "r3-eth1")
        _unshape(r3, "r3-eth0")


def test_responder():
    "A responder spoke lets the hub learn its outbound speed to it."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]

    r4.vtysh_cmd("""
        configure terminal
         interface r4-gre0
          ip nhrp packet-pair responder
        """)
    try:
        assert re.search(
            r"^ ip nhrp packet-pair responder$",
            r4.vtysh_cmd("show running-config"),
            re.M,
        )
        _expect(
            partial(_check_oneway, r2, "r2-gre0", R4_GRE, "outbound"),
            msg="hub gets no reports from responder r4",
        )
        intf = _pp_if(r4, "r4-gre0")
        assert intf["responder"] is True and intf["running"] is True, intf
        _expect(
            partial(_check_oneway, r4, "r4-gre0", R2_GRE, "inbound"),
            msg="r4 does not measure the hub's probes",
        )
        p = _pp_peer(r4, "r4-gre0", R2_GRE)
        logger.info("r4 responder: %s", p)
        assert p.get("responder") is True and "samples" not in p, p
    finally:
        r4.vtysh_cmd("""
            configure terminal
             interface r4-gre0
              no ip nhrp packet-pair
            """)


def _zebra_nhrp(router, ifname):
    try:
        data = json.loads(
            router.vtysh_cmd(
                "show zebra detected-bandwidth interface {} json".format(ifname)
            )
        )
    except ValueError:
        return None
    return data.get(ifname, {}).get("sources", {}).get("nhrp")


def test_zebra_detected_bandwidth():
    "nhrpd reports per-peer bandwidth to zebra, aggregated per tunnel."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _check_r1():
        src = _zebra_nhrp(r1, "r1-gre0")
        nh = (src or {}).get("nexthops", {}).get(R2_GRE)
        if not nh:
            return "no nhrp next hop {} in r1's zebra: {}".format(R2_GRE, src)
        if nh["outSource"] != "one-way" or nh["inSource"] != "one-way":
            return "not one-way yet: {}".format(nh)
        return None if nh["rttKbps"] > 0 else "no round trip: {}".format(nh)

    _expect(_check_r1, msg="spoke's zebra")

    def _check_r2():
        src = _zebra_nhrp(r2, "r2-gre0")
        nhs = (src or {}).get("nexthops", {})
        if set(nhs) != {R1_GRE, R4_GRE}:
            return "hub's zebra next hops: {}".format(nhs)
        if nhs[R1_GRE]["outSource"] != "one-way":
            return "r1 not one-way: {}".format(nhs[R1_GRE])
        # r4 runs no packet-pair: only the round trip is known.
        if nhs[R4_GRE]["outSource"] != "round-trip":
            return "r4: {}".format(nhs[R4_GRE])
        return None

    _expect(_check_r2, msg="hub's zebra")

    src = _zebra_nhrp(r2, "r2-gre0")
    nhs = src["nexthops"].values()
    assert src["outKbps"] == max(n["outKbps"] for n in nhs), src

    r2.vtysh_cmd("""
        configure terminal
         interface r2-gre0
          detected-bandwidth aggregate sum
        """)
    try:
        _expect(
            lambda: (
                None
                if _zebra_nhrp(r2, "r2-gre0")["outKbps"]
                == sum(
                    n["outKbps"]
                    for n in _zebra_nhrp(r2, "r2-gre0")["nexthops"].values()
                )
                else "not summed"
            ),
            count=5,
            msg="aggregate sum",
        )
        src = _zebra_nhrp(r2, "r2-gre0")
        logger.info("hub zebra, aggregate sum: %s", src)
        assert src["outKbps"] == sum(n["outKbps"] for n in src["nexthops"].values())
        assert src["inKbps"] == sum(n["inKbps"] for n in src["nexthops"].values())
    finally:
        r2.vtysh_cmd("""
            configure terminal
             interface r2-gre0
              no detected-bandwidth aggregate
            """)


def test_shortcut_peers_not_probed():
    "A spoke-to-spoke shortcut does not make r1 probe r4."
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]
    rc, _, _ = r1.cmd_status("iptables --version")
    if rc == 127:
        pytest.skip("iptables is not installed (needed for shortcuts)")

    def _shortcut_up():
        r1.cmd("ping -c 3 -i 0.3 192.168.4.4")
        cache = _json(r1, "show ip nhrp cache json")
        for e in cache.get("table", []):
            if e.get("protocol") == R4_GRE and e.get("type") == "dynamic":
                return None
        return "no dynamic cache entry for r4 on r1"

    _expect(_shortcut_up, count=20, wait=1, msg="shortcut r1 -> r4 not created")

    # Give the next samples a chance to (wrongly) include r4.
    before = _pp_peer(r1, "r1-gre0", R2_GRE)["samples"]
    _expect(
        partial(_check_peer_valid, r1, "r1-gre0", R2_GRE, "nhs", None, before + 2),
        count=15,
    )
    peers = _pp_if(r1, "r1-gre0")["peers"]
    assert set(peers) == {R2_GRE}, peers


def test_packet_pair_disable():
    '"no ip nhrp packet-pair" stops probing.'
    tgen = get_topogen()
    _skip_on_failure(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    for router, ifname in ((r1, "r1-gre0"), (r2, "r2-gre0")):
        router.vtysh_cmd("""
            configure terminal
             interface {}
              no ip nhrp packet-pair
            """.format(ifname))
        assert "packet-pair" not in router.vtysh_cmd("show running-config")
        assert _json(router, "show ip nhrp packet-pair json") == {}
        _expect(
            lambda: (
                None
                if _zebra_nhrp(router, ifname) is None
                else "nhrp values still in zebra"
            ),
            count=5,
            msg="{} zebra".format(router.name),
        )

    if shutil.which("tcpdump"):
        out = tgen.gears["r3"].cmd(
            "timeout 5 tcpdump -l -c 1 -n -i r3-eth0 "
            "'ip proto 47 and ip[2:2] == 1500' 2>/dev/null"
        )
        assert "GRE" not in out, out


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
