#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_qos.py
#
# Copyright (c) 2026 FRRouting
#
"""
test_zebra_qos.py: class based QoS (class-map / policy-map / service-policy)

Topology:

    +----+ r1-eth0          r2-eth0 +----+
    | r1 |--------- s1 -------------| r2 |
    +----+ 192.0.2.1    192.0.2.2   +----+

r1 applies the PARENT policy-map (with the CHILD policy nested below the WEB
class) to traffic leaving r1-eth0.  The tests check:

- the HTB qdisc / class hierarchy, rates, ceilings, priorities and pfifo
  queue limits zebra programs,
- show commands and running configuration,
- that traffic lands in the expected HTB class (needs cls_flower and
  act_gact in the kernel, skipped otherwise),
- that a "qos bandwidth" change only updates the HTB classes in place,
- that policy-map and access-list changes re-install the hierarchy,
- removing and re-applying the service-policy.

Traffic is generated with a small python UDP sender (setting IP_TOS /
IPV6_TCLASS and the source address), so the test does not depend on ping.
"""

import functools
import json
import os
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.mgmtd]

INTF = "r1-eth0"

# TOS byte values (DSCP << 2)
TOS = {
    "default": 0x00,
    "cs1": 0x20,
    "af11": 0x28,
    "cs6": 0xC0,
    "ef": 0xB8,
}

# Expected kernel state for the configuration in r1/frr.conf, interface QoS
# bandwidth 20mbps.  Inner classes have no priority printed by tc.
EXPECTED_CLASSES_20M = {
    "beef:1": dict(parent=None, rate=20000000, ceil=20000000),
    # VOICE: bandwidth 5mbps, max-bandwidth 50%, priority 0, queue-limit 64
    "beef:2": dict(parent="beef:1", rate=5000000, ceil=10000000, prio=0, leaf=True),
    # MGMT: bandwidth 5%, priority 1, ceil = interface bandwidth
    "beef:3": dict(parent="beef:1", rate=1000000, ceil=20000000, prio=1, leaf=True),
    # WEB: bandwidth 20%, child policy -> inner class
    "beef:4": dict(parent="beef:1", rate=4000000, ceil=20000000, leaf=False),
    # CHILD/BULK: 30% of WEB, queue-limit 200, default priority 7
    "beef:5": dict(parent="beef:4", rate=1200000, ceil=20000000, prio=7, leaf=True),
    # CHILD/class-default: 70% of WEB
    "beef:6": dict(parent="beef:4", rate=2800000, ceil=20000000, prio=7, leaf=True),
    # PARENT/class-default: 10%, max-bandwidth 15mbps
    "beef:7": dict(parent="beef:1", rate=2000000, ceil=15000000, prio=7, leaf=True),
}

EXPECTED_FIFOS = {"beef:2": 64, "beef:5": 200}


def build_topo(tgen):
    "Build function"
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        # Avoid waiting for IPv6 DAD before sending test traffic.
        router.cmd("sysctl -qw net.ipv6.conf.all.accept_dad=0")
        router.cmd("sysctl -qw net.ipv6.conf.default.accept_dad=0")
        router.cmd("sysctl -qw net.ipv6.conf.{}-eth0.accept_dad=0".format(rname))
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    # 192.0.2.80 (the WEB access-list destination) is not a real host;
    # resolve it to r2 so packets towards it leave r1-eth0.
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r2_mac = r2.cmd("cat /sys/class/net/r2-eth0/address").strip()
    r1.cmd_raises(
        "ip neigh replace 192.0.2.80 lladdr {} dev {} nud permanent".format(
            r2_mac, INTF
        )
    )

    yield tgen

    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


#
# Helpers
#

_UNITS = {"bit": 1, "kbit": 1000, "mbit": 1000000, "gbit": 1000000000}


def _rate2bps(text):
    m = re.match(r"([\d.]+)([KMG]?bit)$", text, re.IGNORECASE)
    assert m, "cannot parse tc rate {!r}".format(text)
    return int(round(float(m.group(1)) * _UNITS[m.group(2).lower()]))


def tc_classes(router, intf=INTF):
    """
    Parse "tc -s class show" into {classid: {...}}.  Text output is used
    because iproute2 does not render HTB classes in JSON on all versions.
    """
    out = router.cmd("tc -s class show dev {}".format(intf))
    classes = {}
    current = None
    for line in out.splitlines():
        m = re.match(
            r"class htb (\S+) (?:root|parent (\S+))(?: leaf (\S+))?"
            r"(?: prio (\d+))? (?:quantum \d+ )?rate (\S+) ceil (\S+)",
            line,
        )
        if m:
            current = m.group(1)
            classes[current] = dict(
                parent=m.group(2),
                leaf_qdisc=m.group(3),
                prio=int(m.group(4)) if m.group(4) is not None else None,
                rate=_rate2bps(m.group(5)),
                ceil=_rate2bps(m.group(6)),
                bytes=0,
                packets=0,
            )
            continue
        m = re.match(r"\s*Sent (\d+) bytes (\d+) pkt", line)
        if m and current:
            classes[current]["bytes"] = int(m.group(1))
            classes[current]["packets"] = int(m.group(2))
    return classes


def tc_qdiscs(router, intf=INTF):
    out = router.cmd("tc -j qdisc show dev {}".format(intf))
    try:
        return json.loads(out)
    except ValueError:
        return []


def root_qdisc(router, intf=INTF):
    for q in tc_qdiscs(router, intf):
        if q.get("root"):
            return q
    return None


def check_classes(router, expected, fifos):
    "Compare kernel classes with the expected layout, return None when equal"
    root = root_qdisc(router)
    if not root or root.get("kind") != "htb" or root.get("handle") != "beef:":
        return "no zebra HTB root qdisc: {}".format(root)

    classes = tc_classes(router)
    if set(classes) != set(expected):
        return "classes {} != expected {}".format(sorted(classes), sorted(expected))

    for cid, want in expected.items():
        have = classes[cid]
        for key in ("parent", "rate", "ceil", "prio"):
            if key in want and have[key] != want[key]:
                return "{} {}: have {} want {}".format(cid, key, have[key], want[key])
        if "leaf" in want and want["leaf"] is False and have["prio"] is not None:
            return "{} should be an inner class: {}".format(cid, have)

    qdiscs = tc_qdiscs(router)
    for cid, limit in fifos.items():
        found = [
            q
            for q in qdiscs
            if q.get("parent") == cid
            and q.get("kind") == "pfifo"
            and q.get("options", {}).get("limit") == limit
        ]
        if not found:
            return "no pfifo limit {} below {}: {}".format(limit, cid, qdiscs)
        if classes[cid]["leaf_qdisc"] != found[0]["handle"]:
            return "{} leaf qdisc {} != {}".format(
                cid, classes[cid]["leaf_qdisc"], found[0]["handle"]
            )

    return None


def kernel_supports_flower(tgen):
    """
    Classification needs cls_flower, act_gact and filter chains.  Probe on
    r2, which has no QoS configuration.
    """
    r2 = tgen.gears["r2"]
    r2.cmd("tc qdisc del dev r2-eth0 root 2>/dev/null")
    r2.cmd("tc qdisc add dev r2-eth0 root handle 1: htb")
    out = r2.cmd(
        "tc filter add dev r2-eth0 parent 1: chain 0 prio 1 protocol all "
        "flower action gact goto chain 1 2>&1 && echo FLOWER-OK"
    )
    r2.cmd("tc qdisc del dev r2-eth0 root 2>/dev/null")
    return "FLOWER-OK" in out


SENDER = """
import socket, sys
fam = socket.AF_INET6 if ":" in sys.argv[2] else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
if fam == socket.AF_INET:
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, int(sys.argv[3], 0))
else:
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, int(sys.argv[3], 0))
s.bind((sys.argv[1], 0))
for _ in range(int(sys.argv[4])):
    try:
        s.sendto(b"x" * 200, (sys.argv[2], 9))
    except OSError:
        pass
"""


def send_udp(router, src, dst, tos, count):
    "Send @count UDP packets from @src to @dst with the given TOS/TCLASS"
    router.cmd("python3 -c '{}' {} {} {} {}".format(SENDER, src, dst, hex(tos), count))


# Sends as fast as the qdisc lets it for a number of seconds.
TIMED_SENDER = """
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, int(sys.argv[3], 0))
s.bind((sys.argv[1], 0))
end = time.time() + float(sys.argv[4])
while time.time() < end:
    try:
        s.sendto(b"x" * 1400, (sys.argv[2], 9))
    except OSError:
        time.sleep(0.001)
"""


def start_udp_stream(router, src, dst, tos, seconds):
    "Start a background UDP stream (see TIMED_SENDER), return its pid"
    out = router.cmd(
        "python3 -c '{}' {} {} {} {} >/dev/null 2>&1 & echo $!".format(
            TIMED_SENDER, src, dst, hex(tos), seconds
        )
    )
    return out.strip().splitlines()[-1]


def stop_udp_stream(router, pid):
    router.cmd("kill {} 2>/dev/null".format(pid))


def show_qos_json(router, intf=INTF):
    out = router.vtysh_cmd("show qos interface {} json".format(intf), isjson=True)
    return out.get(intf, {})


def wait_for(func, what, count=30, wait=1):
    result, out = topotest.run_and_expect(func, None, count=count, wait=wait)
    assert result, "{}: {}".format(what, out)


#
# Tests
#


def test_qos_htb_hierarchy(tgen):
    "zebra installs the HTB hierarchy described by PARENT/CHILD"

    r1 = tgen.gears["r1"]
    wait_for(
        functools.partial(check_classes, r1, EXPECTED_CLASSES_20M, EXPECTED_FIFOS),
        "HTB hierarchy not installed as expected",
    )

    root = root_qdisc(r1)
    assert (
        root["options"]["default"] == "0x7"
    ), "unclassified traffic must go to PARENT/class-default: {}".format(root)
    logger.info("tc class:\n%s", r1.cmd("tc class show dev " + INTF))


def test_qos_show_commands(tgen):
    "show qos interface and the running configuration"

    r1 = tgen.gears["r1"]

    def _show():
        out = r1.vtysh_cmd("show qos interface " + INTF)
        for needle in (
            "QoS bandwidth: 20.00Mbps",
            "Service policy (output): PARENT",
            "State: installed, 7 classes",
            "PARENT/VOICE",
            "CHILD/BULK",
        ):
            if needle not in out:
                return "missing {!r} in:\n{}".format(needle, out)
        return None

    wait_for(_show, "show qos interface")

    running = r1.vtysh_cmd("show running-config")
    for block in (
        "class-map match-any VOICE\n match access-group name VOICE\n match ip dscp ef\nexit",
        "class-map match-all MGMT\n match access-group name MGMT\n match ip dscp cs6\nexit",
        "policy-map CHILD\n class BULK\n  bandwidth percent 30\n  queue-limit 200 packets\n exit",
        " class VOICE\n  bandwidth 5mbps\n  max-bandwidth percent 50\n  priority 0\n"
        "  queue-limit 64 packets\n exit",
        " class WEB\n  bandwidth percent 20\n  priority 2\n  service-policy CHILD\n exit",
        "interface r1-eth0\n ip address 192.0.2.1/24\n ipv6 address 2001:db8:1::1/64\n"
        " qos bandwidth 20mbps\n service-policy output PARENT\nexit",
    ):
        assert block in running, "missing in running-config:\n{}\n---\n{}".format(
            block, running
        )

    # classes keep their configured order
    pmap = running[running.index("policy-map PARENT") :]
    order = [pmap.index(" class " + c + "\n") for c in ("VOICE", "MGMT", "WEB")]
    assert order == sorted(order), "class order changed:\n{}".format(pmap)


def test_qos_show_statistics(tgen):
    "show qos interface reports per class statistics and utilization"

    r1 = tgen.gears["r1"]

    # Unclassified traffic goes to PARENT/class-default (beef:7: rate 2mbps,
    # ceiling 15mbps) through the HTB default class, so this works without
    # flower support.  Offer more than the ceiling for a while.
    pid = start_udp_stream(r1, "192.0.2.1", "192.0.2.2", TOS["default"], 12)

    def _utilization():
        data = show_qos_json(r1)
        if not data.get("installed") or not data.get("statistics"):
            return "no statistics: {}".format(data)
        classes = {c["classId"]: c for c in data["classes"]}
        default = classes["beef:7"].get("stats", {})
        voice = classes["beef:2"].get("stats", {})
        root = classes["beef:1"].get("stats", {})
        if not default.get("rateValid") or not root.get("rateValid"):
            return "no rate estimate: {}".format(classes)
        # the estimator averages over a few seconds: wait until it shows
        # the class running close to its ceiling
        if not 70 <= default.get("ceilUtilization", 0) <= 110:
            return "class-default ceiling utilization {}%: {}".format(
                default.get("ceilUtilization"), default
            )
        # 15mbps is far above the 2mbps guaranteed rate: borrowing
        if default.get("rateUtilization", 0) < 300:
            return "class-default rate utilization {}%".format(
                default.get("rateUtilization")
            )
        if default.get("packets", 0) == 0 or default.get("bytes", 0) == 0:
            return "no packets counted: {}".format(default)
        if voice.get("currentRate", 0) > 100000:
            return "unexpected VOICE traffic: {}".format(voice)
        if root.get("currentRate", 0) < default["currentRate"] * 0.9:
            return "root rate {} below class-default {}".format(
                root.get("currentRate"), default["currentRate"]
            )
        return None

    try:
        wait_for(_utilization, "class statistics/utilization", count=15)

        out = r1.vtysh_cmd("show qos interface " + INTF)
        for needle in ("Current", "%Rate", "%Ceil", "Drops", "Backlog"):
            assert needle in out, "missing {!r} in:\n{}".format(needle, out)
        line = [
            l
            for l in out.splitlines()
            if l.strip().startswith("beef:7 ") and "Mbps" in l and "%" in l
        ]
        assert line, "no statistics line for beef:7:\n{}".format(out)
        logger.info("show qos interface:\n%s", out)
    finally:
        stop_udp_stream(r1, pid)

    # once the stream stops the estimate decays again
    def _idle():
        default = {c["classId"]: c for c in show_qos_json(r1)["classes"]}["beef:7"]
        rate = default.get("stats", {}).get("currentRate", 0)
        if rate > 7500000:
            return "class-default still at {} bps".format(rate)
        return None

    wait_for(_idle, "rate estimate did not decay", count=20)


# (class-map, policy-map, HTB class, filters attached to, number of filters)
# for r1/frr.conf, in the order "show class-map interface" lists them.
EXPECTED_CLASS_MAPS = [
    # ACL VOICE: 2 IPv4 + 1 IPv6 entries + end, dscp ef: IPv4 + IPv6 + end
    ("VOICE", "PARENT", "beef:2", "beef:", 7),
    # match-all: 1 ACL entry combined with cs6 + end
    ("MGMT", "PARENT", "beef:3", "beef:", 2),
    ("WEB", "PARENT", "beef:4", "beef:", 2),
    ("BULK", "CHILD", "beef:5", "beef:4", 3),
    ("class-default", "CHILD", "beef:6", "beef:4", 1),
    ("class-default", "PARENT", "beef:7", "beef:", 1),
]


def show_class_map_json(router, intf=INTF):
    out = router.vtysh_cmd("show class-map interface {} json".format(intf), isjson=True)
    return out.get(intf, {})


def test_qos_show_class_map(tgen):
    "show class-map interface lists the filters of every class-map"

    r1 = tgen.gears["r1"]
    flower = kernel_supports_flower(tgen)

    def _structure():
        data = show_class_map_json(r1)
        if not data.get("installed"):
            return "not installed: {}".format(data)
        cmaps = data.get("classMaps", [])
        have = [
            (
                c["classMap"],
                c["policyMap"],
                c["classId"],
                c["filtersAttachedTo"],
                len(c["filters"]),
            )
            for c in cmaps
        ]
        if have != EXPECTED_CLASS_MAPS:
            return "class-maps {} != {}".format(have, EXPECTED_CLASS_MAPS)
        if not data.get("filterStatistics"):
            return "filter statistics could not be read"
        for c in cmaps:
            if "classStats" not in c:
                return "no class statistics for {}".format(c["classId"])
            for f in c["filters"]:
                if f.get("inKernel") is not flower:
                    return "{} filter {} inKernel={}, expected {}".format(
                        c["classMap"], f, f.get("inKernel"), flower
                    )
        return None

    wait_for(_structure, "show class-map interface structure")

    data = show_class_map_json(r1)
    voice = data["classMaps"][0]
    assert voice["matchType"] == "match-any", voice
    origins = [f["origin"] for f in voice["filters"]]
    assert origins == [
        "access-list VOICE seq 5 deny",
        "access-list VOICE seq 10 permit",
        "ipv6 access-list VOICE seq 5 permit",
        "no match: next statement",
        "match ip dscp ef",
        "match ip dscp ef",
        "no match: next statement",
    ], origins
    matches = [(f["protocol"], f["match"], f["action"]) for f in voice["filters"]]
    assert matches == [
        ("ipv4", "src 10.1.1.0/24", "goto chain 1"),
        ("ipv4", "src 10.0.0.0/8", "classify"),
        ("ipv6", "src 2001:db8:99::/48", "classify"),
        ("all", "any", "goto chain 1"),
        ("ipv4", "dscp ef", "classify"),
        ("ipv6", "dscp ef", "classify"),
        ("all", "any", "goto chain 2"),
    ], matches
    mgmt = data["classMaps"][1]
    assert mgmt["filters"][0]["match"] == "src 172.16.0.0/24 dscp cs6", mgmt

    out_if = r1.vtysh_cmd("show class-map interface " + INTF)
    for needle in (
        "Interface r1-eth0, service-policy output PARENT",
        "Class-map VOICE (match-any)",
        "Policy-map CHILD, HTB class beef:5, parent beef:4",
        "Filters attached to beef:4, in evaluation order:",
        "access-list WEB seq 5 permit",
        "class-default: everything else",
    ):
        assert needle in out_if, "missing {!r} in:\n{}".format(needle, out_if)
    logger.info("show class-map interface:\n%s", out_if)

    # filters zebra could not install are flagged
    warned = "filters are missing from the kernel" in out_if
    assert warned is not flower, "missing-filter warning={} with flower={}:\n{}".format(
        warned, flower, out_if
    )

    out = r1.vtysh_cmd("show class-map interface does-not-exist")
    assert "Interface does-not-exist not found" in out, out

    if not flower:
        return

    # per filter hit counters follow the traffic
    def _filter_packets(origin):
        voice = show_class_map_json(r1)["classMaps"][0]
        return {f["origin"]: f.get("packets", 0) for f in voice["filters"]}[origin]

    permit = "access-list VOICE seq 10 permit"
    deny = "access-list VOICE seq 5 deny"
    send_udp(r1, "10.3.3.3", "192.0.2.2", TOS["default"], 1)
    send_udp(r1, "10.1.1.1", "192.0.2.2", TOS["default"], 1)
    permit_before = _filter_packets(permit)
    deny_before = _filter_packets(deny)
    send_udp(r1, "10.3.3.3", "192.0.2.2", TOS["default"], 25)
    send_udp(r1, "10.1.1.1", "192.0.2.2", TOS["default"], 15)

    def _counted():
        p = _filter_packets(permit) - permit_before
        d = _filter_packets(deny) - deny_before
        if p < 25 or d < 15:
            return "permit filter +{} (want 25), deny filter +{} (want 15)".format(p, d)
        return None

    wait_for(_counted, "filter counters", count=10)


def test_qos_filters_installed(tgen):
    "flower filters and filter chains are installed"

    if not kernel_supports_flower(tgen):
        pytest.skip("kernel lacks cls_flower/act_gact")

    r1 = tgen.gears["r1"]

    def _filters():
        root = r1.cmd("tc filter show dev {} parent beef:".format(INTF))
        child = r1.cmd("tc filter show dev {} parent beef:4".format(INTF))
        for needle in (
            "flower",
            "goto chain",
            "classid beef:2",
            "classid beef:3",
            "classid beef:4",
            "classid beef:7",
        ):
            if needle not in root:
                return "missing {!r} in root filters:\n{}".format(needle, root)
        for needle in ("classid beef:5", "classid beef:6"):
            if needle not in child:
                return "missing {!r} in WEB child filters:\n{}".format(needle, child)
        return None

    wait_for(_filters, "filters not installed")


# (description, source, destination, TOS, expected class)
CLASSIFICATION_CASES = [
    ("acl permit 10/8", "10.3.3.3", "192.0.2.2", "default", "beef:2"),
    ("acl deny 10.1.1/24", "10.1.1.1", "192.0.2.2", "default", "beef:7"),
    ("acl deny, match-any dscp ef", "10.1.1.1", "192.0.2.2", "ef", "beef:2"),
    ("match-all acl + cs6", "172.16.0.1", "192.0.2.2", "cs6", "beef:3"),
    ("match-all acl without cs6", "172.16.0.1", "192.0.2.2", "default", "beef:7"),
    ("WEB dst, child BULK cs1", "192.0.2.1", "192.0.2.80", "cs1", "beef:5"),
    ("WEB dst, child default", "192.0.2.1", "192.0.2.80", "af11", "beef:6"),
    ("ipv6 acl permit", "2001:db8:99::1", "2001:db8:1::2", "default", "beef:2"),
    ("ipv6 dscp ef", "2001:db8:1::1", "2001:db8:1::2", "ef", "beef:2"),
    ("ipv6 unmatched", "2001:db8:1::1", "2001:db8:1::2", "default", "beef:7"),
]


@pytest.mark.parametrize(
    "desc,src,dst,tos,expected",
    CLASSIFICATION_CASES,
    ids=[c[0] for c in CLASSIFICATION_CASES],
)
def test_qos_classification(tgen, desc, src, dst, tos, expected):
    "traffic is put into the class selected by the class-maps"

    if not kernel_supports_flower(tgen):
        pytest.skip("kernel lacks cls_flower/act_gact")

    r1 = tgen.gears["r1"]
    count = 40

    # prime neighbor resolution so it does not disturb the counters
    send_udp(r1, src, dst, TOS[tos], 1)

    before = tc_classes(r1)
    send_udp(r1, src, dst, TOS[tos], count)

    def _counted():
        after = tc_classes(r1)
        delta = {
            cid: after[cid]["packets"] - before.get(cid, {}).get("packets", 0)
            for cid in after
            if EXPECTED_CLASSES_20M.get(cid, {}).get("leaf")
        }
        if delta.get(expected, 0) < count:
            return "{}: expected {} packets in {}, deltas {}".format(
                desc, count, expected, delta
            )
        stray = {c: d for c, d in delta.items() if c != expected and d >= count // 2}
        if stray:
            return "{}: traffic leaked into {}".format(desc, stray)
        return None

    wait_for(_counted, "classification", count=10)


def test_qos_bandwidth_change_in_place(tgen):
    "changing only 'qos bandwidth' updates rates/ceilings without reinstalling"

    r1 = tgen.gears["r1"]

    # unclassified traffic (default class via the HTB default) works even
    # without flower support
    send_udp(r1, "192.0.2.1", "192.0.2.2", TOS["default"], 50)
    before = tc_classes(r1)
    assert before["beef:7"]["packets"] >= 50, before
    leafs_before = {q["parent"]: q["handle"] for q in tc_qdiscs(r1) if "parent" in q}

    r1.vtysh_cmd("""
        configure terminal
         interface r1-eth0
          qos bandwidth 40mbps
        """)

    expected = {}
    for cid, want in EXPECTED_CLASSES_20M.items():
        want = dict(want)
        if cid != "beef:7":
            # rates expressed in percent and default ceilings follow the
            # interface bandwidth; VOICE has a fixed 5mbps rate
            if cid != "beef:2":
                want["rate"] *= 2
            want["ceil"] *= 2
        else:
            # class-default: 10% rate, fixed 15mbps ceiling
            want["rate"] *= 2
        expected[cid] = want

    wait_for(
        functools.partial(check_classes, r1, expected, EXPECTED_FIFOS),
        "rates/ceilings not updated for 40mbps",
    )

    after = tc_classes(r1)
    # Counters survive an in-place change, a re-installed qdisc starts at 0.
    for cid in ("beef:1", "beef:7"):
        assert (
            after[cid]["packets"] >= before[cid]["packets"]
        ), "{} counters were reset, qdisc re-installed: before {} after {}".format(
            cid, before[cid], after[cid]
        )
    leafs_after = {q["parent"]: q["handle"] for q in tc_qdiscs(r1) if "parent" in q}
    assert leafs_after == leafs_before, "leaf qdiscs changed: {} -> {}".format(
        leafs_before, leafs_after
    )

    r1.vtysh_cmd("""
        configure terminal
         interface r1-eth0
          qos bandwidth 20mbps
        """)
    wait_for(
        functools.partial(check_classes, r1, EXPECTED_CLASSES_20M, EXPECTED_FIFOS),
        "rates/ceilings not restored for 20mbps",
    )


def test_qos_policy_change_reinstalls(tgen):
    "modifying the policy-map re-installs the hierarchy"

    r1 = tgen.gears["r1"]

    send_udp(r1, "192.0.2.1", "192.0.2.2", TOS["default"], 50)
    before = tc_classes(r1)
    assert before["beef:1"]["packets"] >= 50, before

    r1.vtysh_cmd("""
        configure terminal
         class-map match-all SCAVENGER
          match ip dscp cs1
         exit
         policy-map PARENT
          class SCAVENGER
           bandwidth 500k
           max-bandwidth 1m
         exit
        """)

    # SCAVENGER is added after WEB/CHILD, class-default moves to beef:8
    expected = dict(EXPECTED_CLASSES_20M)
    expected["beef:7"] = dict(
        parent="beef:1", rate=500000, ceil=1000000, prio=7, leaf=True
    )
    expected["beef:8"] = dict(EXPECTED_CLASSES_20M["beef:7"])

    wait_for(
        functools.partial(check_classes, r1, expected, EXPECTED_FIFOS),
        "hierarchy not re-installed with SCAVENGER",
    )
    root = root_qdisc(r1)
    assert root["options"]["default"] == "0x8", root

    after = tc_classes(r1)
    assert (
        after["beef:1"]["packets"] < before["beef:1"]["packets"]
    ), "root class counters not reset, qdisc was not re-installed"

    r1.vtysh_cmd("""
        configure terminal
         policy-map PARENT
          no class SCAVENGER
         exit
         no class-map SCAVENGER
        """)
    wait_for(
        functools.partial(check_classes, r1, EXPECTED_CLASSES_20M, EXPECTED_FIFOS),
        "hierarchy not restored after removing SCAVENGER",
    )


def test_qos_acl_change(tgen):
    "access-list changes are picked up by the class-maps using them"

    if not kernel_supports_flower(tgen):
        pytest.skip("kernel lacks cls_flower/act_gact")

    r1 = tgen.gears["r1"]
    r2_mac = tgen.gears["r2"].cmd("cat /sys/class/net/r2-eth0/address").strip()
    r1.cmd_raises(
        "ip neigh replace 192.0.2.81 lladdr {} dev {} nud permanent".format(
            r2_mac, INTF
        )
    )

    def _goes_to(dst, cid):
        before = tc_classes(r1)
        send_udp(r1, "192.0.2.1", dst, TOS["af11"], 30)
        after = tc_classes(r1)
        delta = after[cid]["packets"] - before.get(cid, {}).get("packets", 0)
        if delta < 30:
            return "{} -> {}: delta {}".format(dst, cid, delta)
        return None

    # 192.0.2.81 is not in WEB yet: class-default
    wait_for(functools.partial(_goes_to, "192.0.2.81", "beef:7"), "before acl change")

    r1.vtysh_cmd("""
        configure terminal
         access-list WEB seq 10 permit ip any host 192.0.2.81
        """)
    # now WEB -> CHILD class-default
    wait_for(functools.partial(_goes_to, "192.0.2.81", "beef:6"), "after acl change")

    r1.vtysh_cmd("""
        configure terminal
         no access-list WEB seq 10 permit ip any host 192.0.2.81
        """)
    wait_for(functools.partial(_goes_to, "192.0.2.81", "beef:7"), "after acl removal")


def test_qos_remove_and_reapply(tgen):
    "removing the service-policy removes the qdisc, re-applying restores it"

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("""
        configure terminal
         interface r1-eth0
          no service-policy output
        """)

    def _removed():
        root = root_qdisc(r1)
        if root and root.get("handle") == "beef:":
            return "zebra qdisc still installed: {}".format(root)
        out = r1.vtysh_cmd("show qos interface " + INTF)
        if "Service policy (output): none" not in out:
            return out
        return None

    wait_for(_removed, "service-policy not removed")

    r1.vtysh_cmd("""
        configure terminal
         interface r1-eth0
          service-policy output PARENT
        """)
    wait_for(
        functools.partial(check_classes, r1, EXPECTED_CLASSES_20M, EXPECTED_FIFOS),
        "service-policy not re-applied",
    )


def test_qos_undefined_policy(tgen):
    "referencing a policy-map that does not exist installs nothing"

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("""
        configure terminal
         interface r1-eth0
          service-policy output DOES-NOT-EXIST
        """)

    def _not_installed():
        root = root_qdisc(r1)
        if root and root.get("handle") == "beef:":
            return "zebra qdisc still installed: {}".format(root)
        out = r1.vtysh_cmd("show qos interface " + INTF)
        if "not installed (policy-map is not configured)" not in out:
            return out
        return None

    wait_for(_not_installed, "undefined policy-map")

    r1.vtysh_cmd("""
        configure terminal
         interface r1-eth0
          service-policy output PARENT
        """)
    wait_for(
        functools.partial(check_classes, r1, EXPECTED_CLASSES_20M, EXPECTED_FIFOS),
        "service-policy not re-applied",
    )


# Extended access-list: source and/or destination, IPv4 and IPv6 entries in
# lists of the same name.
EXT_ACL_CONFIG = """
configure terminal
 access-list EXT seq 5 deny ip host 172.16.0.1 host 192.0.2.86
 access-list EXT seq 10 permit ip 172.16.0.0 0.0.0.255 192.0.2.84 0.0.0.3
 access-list EXT seq 15 permit ip any host 192.0.2.90
 access-list EXT seq 20 permit ip 172.16.0.1 0.0.255.0 host 192.0.2.91
 ipv6 access-list EXT seq 5 permit ipv6 host 2001:db8:1::1 2001:db8:2:: ::ffff:ffff:ffff:ffff
 ipv6 access-list EXT seq 10 deny ipv6 any host 2001:db8:3::1
 class-map match-any EXT
  match access-group name EXT
 exit
 policy-map PARENT
  class EXT
   bandwidth percent 10
  exit
"""

EXT_ACL_LINES = [
    "access-list EXT seq 5 deny ip host 172.16.0.1 host 192.0.2.86",
    "access-list EXT seq 10 permit ip 172.16.0.0 0.0.0.255 192.0.2.84 0.0.0.3",
    "access-list EXT seq 15 permit ip any host 192.0.2.90",
    "access-list EXT seq 20 permit ip 172.16.0.1 0.0.255.0 host 192.0.2.91",
    "ipv6 access-list EXT seq 5 permit ipv6 host 2001:db8:1::1 2001:db8:2:: "
    "::ffff:ffff:ffff:ffff",
    "ipv6 access-list EXT seq 10 deny ipv6 any host 2001:db8:3::1",
]

# EXT is appended to PARENT after WEB: it becomes beef:7, class-default beef:8
EXT_CASES = [
    ("v4 src net + dst net", "172.16.0.7", "192.0.2.85", "beef:7"),
    ("v4 deny host/host", "172.16.0.1", "192.0.2.86", "beef:8"),
    ("v4 same dst, other src", "172.16.0.7", "192.0.2.86", "beef:7"),
    ("v4 src outside wildcard", "172.16.1.7", "192.0.2.85", "beef:8"),
    ("v4 dst only (any src)", "192.0.2.1", "192.0.2.90", "beef:7"),
    ("v4 non-contiguous wildcard", "172.16.1.1", "192.0.2.91", "beef:7"),
    ("v4 non-contiguous wildcard miss", "172.16.1.7", "192.0.2.91", "beef:8"),
    ("v6 src host + dst /64", "2001:db8:1::1", "2001:db8:2::5", "beef:7"),
    ("v6 other src", "2001:db8:5::1", "2001:db8:2::5", "beef:8"),
    ("v6 dst outside /64", "2001:db8:1::1", "2001:db8:2:1::5", "beef:8"),
    ("v6 deny dst host", "2001:db8:1::1", "2001:db8:3::1", "beef:8"),
]


def test_qos_extended_acl(tgen):
    "class-maps using extended (source/destination) IPv4 and IPv6 access-lists"

    r1 = tgen.gears["r1"]
    r2_mac = tgen.gears["r2"].cmd("cat /sys/class/net/r2-eth0/address").strip()

    # extra sources, and make the test destinations reachable through r2
    for addr in ("172.16.0.7/32", "172.16.1.1/32", "172.16.1.7/32"):
        r1.cmd("ip addr add {} dev lo".format(addr))
    r1.cmd("ip -6 addr add 2001:db8:5::1/128 dev lo nodad")
    for dst in ("192.0.2.84", "192.0.2.85", "192.0.2.86", "192.0.2.90", "192.0.2.91"):
        r1.cmd_raises(
            "ip neigh replace {} lladdr {} dev {} nud permanent".format(
                dst, r2_mac, INTF
            )
        )
    r1.cmd("ip -6 route replace 2001:db8:2::/47 via 2001:db8:1::2 dev " + INTF)

    filters_before = show_qos_json(r1)["filters"]

    out = r1.vtysh_cmd(EXT_ACL_CONFIG)
    assert "duplicated" not in out and "failed" not in out, out

    # Both families with the same name are accepted (used to be rejected
    # as "duplicated access list value").
    running = r1.vtysh_cmd("show running-config")
    for line in EXT_ACL_LINES:
        assert line in running, "missing {!r} in running-config:\n{}".format(
            line, running
        )

    expected = dict(EXPECTED_CLASSES_20M)
    expected["beef:7"] = dict(
        parent="beef:1", rate=2000000, ceil=20000000, prio=7, leaf=True
    )
    expected["beef:8"] = dict(EXPECTED_CLASSES_20M["beef:7"])

    def _installed():
        error = check_classes(r1, expected, EXPECTED_FIFOS)
        if error:
            return error
        # one flower filter per access-list entry (4 IPv4 + 2 IPv6) plus the
        # catch-all closing the EXT segment
        filters = show_qos_json(r1)["filters"]
        if filters != filters_before + 7:
            return "{} filters, expected {}".format(filters, filters_before + 7)
        return None

    try:
        wait_for(_installed, "EXT class not installed")

        if kernel_supports_flower(tgen):
            failures = []
            for desc, src, dst, want in EXT_CASES:
                send_udp(r1, src, dst, TOS["default"], 1)
                before = tc_classes(r1)
                send_udp(r1, src, dst, TOS["default"], 30)
                after = tc_classes(r1)
                delta = {
                    cid: after[cid]["packets"] - before.get(cid, {}).get("packets", 0)
                    for cid in after
                }
                if delta.get(want, 0) < 30:
                    failures.append(
                        "{}: expected {}, deltas {}".format(desc, want, delta)
                    )
            assert not failures, "\n".join(failures)
        else:
            logger.info("kernel lacks cls_flower/act_gact: classification not checked")
    finally:
        r1.vtysh_cmd("""
            configure terminal
             policy-map PARENT
              no class EXT
             exit
             no class-map EXT
             no access-list EXT
             no ipv6 access-list EXT
            """)

    wait_for(
        functools.partial(check_classes, r1, EXPECTED_CLASSES_20M, EXPECTED_FIFOS),
        "hierarchy not restored after removing EXT",
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
