#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_qos_detected_bw.py
#
# Copyright (c) 2026 FRRouting
#
"""
test_zebra_qos_detected_bw.py: QoS interface bandwidth from the bandwidth
detected by OSPF and/or NHRP ("qos bandwidth detected ...").

Topology:

    +----+ r1-eth0          r2-eth0 +----+
    | r1 |--------- s1 -------------| r2 |
    +----+ 192.0.2.1    192.0.2.2   +----+

ospfd and nhrpd are emulated by zapi_detected_bw.py, which connects to
zebra as the given protocol and sends ZEBRA_DETECTED_BW_UPDATE messages,
so the reported values are deterministic.  The tests check the source
priority, the fallback to the next source, to the default and to the
interface bandwidth, aggregation of several next hops, that a static
"qos bandwidth" replaces the detected sources, and that the HTB root class
follows the selected bandwidth.
"""

import functools
import json
import os
import re
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.mgmtd]

INTF = "r1-eth0"
SRCDIR = os.path.realpath(os.path.join(CWD, "../../.."))
INJECTOR = os.path.join(CWD, "zapi_detected_bw.py")
ZSERV = "/var/run/frr/zserv.api"

injectors = {}


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
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    yield tgen

    for proto in list(injectors):
        stop_injector(proto)
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


#
# Helpers
#


def fifo_path(proto):
    return os.path.join(get_topogen().logdir, "r1", "{}-dbw.fifo".format(proto))


def start_injector(proto):
    "Connect to r1's zebra as PROTO"
    r1 = get_topogen().gears["r1"]
    fifo = fifo_path(proto)
    if os.path.exists(fifo):
        os.unlink(fifo)
    os.mkfifo(fifo)
    injectors[proto] = r1.popen(
        [
            sys.executable,
            INJECTOR,
            "--zserv",
            ZSERV,
            "--srcdir",
            SRCDIR,
            "--proto",
            proto,
            "--fifo",
            fifo,
        ]
    )


def inject(proto, line):
    with open(fifo_path(proto), "w", encoding="utf-8") as f:
        f.write(line + "\n")


def stop_injector(proto):
    "Close PROTO's zebra connection, zebra drops its values"
    proc = injectors.pop(proto)
    if proc.poll() is None:
        inject(proto, "quit")
        try:
            proc.wait(timeout=10)
        except Exception:  # pylint: disable=broad-except
            proc.kill()


def ifindex():
    r1 = get_topogen().gears["r1"]
    return int(r1.cmd("cat /sys/class/net/{}/ifindex".format(INTF)).strip())


def set_bw(proto, nexthop, kbps):
    inject(proto, "set {} {} {}".format(ifindex(), nexthop, kbps))


def del_bw(proto, nexthop):
    inject(proto, "del {} {}".format(ifindex(), nexthop))


def vtysh_conf(*lines):
    r1 = get_topogen().gears["r1"]
    cmd = 'vtysh -c "configure terminal"'
    for line in lines:
        cmd += ' -c "{}"'.format(line)
    return r1.cmd(cmd)


def qos_show():
    r1 = get_topogen().gears["r1"]
    out = r1.vtysh_cmd("show qos interface {} json".format(INTF))
    try:
        return json.loads(out).get(INTF, {})
    except ValueError:
        return {}


def root_rate():
    "Rate of the HTB root class zebra installed on r1-eth0, in bps"
    r1 = get_topogen().gears["r1"]
    out = r1.cmd("tc class show dev {}".format(INTF))
    m = re.search(r"class htb beef:1 root .*?rate (\d+(?:\.\d+)?)([KMG]?)bit", out)
    if not m:
        return None
    mult = {"": 1, "K": 1000, "M": 1000000, "G": 1000000000}[m.group(2)]
    return int(round(float(m.group(1)) * mult))


def _check_bw(source, bps):
    show = qos_show()
    have = (show.get("qosBandwidthSource"), show.get("qosBandwidth"), root_rate())
    want = (source, bps, bps)
    if have != want:
        return "(source, qosBandwidth, tc root rate) {} != {}".format(have, want)
    return None


def expect_bw(source, bps, msg):
    _, result = topotest.run_and_expect(
        functools.partial(_check_bw, source, bps), None, count=30, wait=1
    )
    assert result is None, "{}: {}".format(msg, result)


#
# Tests
#


def test_running_config(tgen):
    "The detected bandwidth configuration is shown in the running config"
    r1 = tgen.gears["r1"]
    out = r1.vtysh_cmd("show running-config")
    assert " qos bandwidth detected ospf nhrp default 3mbps" in out, out


def test_default(tgen):
    "Nothing detected yet: the configured default is used"
    expect_bw("default", 3000000, "default bandwidth not used")

    show = qos_show()
    srcs = show["detectedBandwidth"]["sources"]
    assert [(s["priority"], s["protocol"], s["available"]) for s in srcs] == [
        (1, "ospf", False),
        (2, "nhrp", False),
    ], srcs
    assert show["detectedBandwidth"]["default"] == 3000000, show


def test_second_source(tgen):
    "Only the second priority source has a value: it is used"
    start_injector("ospf")
    start_injector("nhrp")
    # give zebra time to accept both clients
    time.sleep(1)

    set_bw("nhrp", "192.0.2.2", 8000)
    expect_bw("nhrp", 8000000, "nhrp bandwidth not used")


def test_first_source(tgen):
    "The first priority source takes over once it has a value"
    set_bw("ospf", "192.0.2.2", 5000)
    expect_bw("ospf", 5000000, "ospf bandwidth not preferred")

    srcs = qos_show()["detectedBandwidth"]["sources"]
    assert srcs[0]["available"] and srcs[0]["bandwidth"] == 5000000, srcs
    assert srcs[1]["available"] and srcs[1]["bandwidth"] == 8000000, srcs


def test_nexthop_aggregation(tgen):
    "Several next hops are combined per 'detected-bandwidth aggregate'"
    set_bw("ospf", "192.0.2.3", 6000)
    expect_bw("ospf", 6000000, "ospf next hops not aggregated by max")

    vtysh_conf("interface {}".format(INTF), "detected-bandwidth aggregate sum")
    expect_bw("ospf", 11000000, "ospf next hops not aggregated by sum")

    vtysh_conf("interface {}".format(INTF), "no detected-bandwidth aggregate sum")
    expect_bw("ospf", 6000000, "aggregation not restored to max")

    del_bw("ospf", "192.0.2.3")
    expect_bw("ospf", 5000000, "ospf next hop not withdrawn")


def test_reorder(tgen):
    "The order on the command line is the priority"
    vtysh_conf(
        "interface {}".format(INTF), "qos bandwidth detected nhrp ospf default 3mbps"
    )
    expect_bw("nhrp", 8000000, "nhrp not preferred after reorder")

    vtysh_conf(
        "interface {}".format(INTF), "qos bandwidth detected ospf nhrp default 3mbps"
    )
    expect_bw("ospf", 5000000, "ospf not preferred after reorder")


def test_single_source(tgen):
    "With a single source the other daemon is ignored"
    vtysh_conf("interface {}".format(INTF), "qos bandwidth detected nhrp")
    expect_bw("nhrp", 8000000, "nhrp only source not used")

    out = tgen.gears["r1"].vtysh_cmd("show running-config")
    assert re.search(r"^ qos bandwidth detected nhrp$", out, re.M), out

    vtysh_conf(
        "interface {}".format(INTF), "qos bandwidth detected ospf nhrp default 3mbps"
    )
    expect_bw("ospf", 5000000, "ospf not used after restore")


def test_daemon_gone(tgen):
    "A daemon going away falls back to the next source, then to the default"
    stop_injector("ospf")
    expect_bw("nhrp", 8000000, "no fallback to nhrp when ospf went away")

    del_bw("nhrp", "192.0.2.2")
    expect_bw("default", 3000000, "no fallback to the default")

    set_bw("nhrp", "192.0.2.2", 7000)
    expect_bw("nhrp", 7000000, "nhrp value not used again")

    stop_injector("nhrp")
    expect_bw("default", 3000000, "no fallback to the default when nhrp went away")


def test_no_default(tgen):
    "Without a default the interface bandwidth is used"
    vtysh_conf("interface {}".format(INTF), "qos bandwidth detected ospf nhrp")
    expect_bw("interface", 2000000, "interface bandwidth not used")


def test_static_replaces_detected(tgen):
    "A static qos bandwidth replaces the detected configuration and back"
    vtysh_conf("interface {}".format(INTF), "qos bandwidth 20mbps")
    expect_bw("static", 20000000, "static bandwidth not used")

    out = tgen.gears["r1"].vtysh_cmd("show running-config")
    assert "qos bandwidth detected" not in out, out
    assert " qos bandwidth 20mbps" in out, out

    vtysh_conf("interface {}".format(INTF), "qos bandwidth detected ospf default 4mbps")
    expect_bw("default", 4000000, "detected configuration not restored")
    out = tgen.gears["r1"].vtysh_cmd("show running-config")
    assert " qos bandwidth 20mbps" not in out, out


def test_no_detected(tgen):
    "Removing the detected configuration falls back to the interface bandwidth"
    vtysh_conf("interface {}".format(INTF), "no qos bandwidth detected")
    expect_bw("interface", 2000000, "detected configuration not removed")
    assert "detectedBandwidth" not in qos_show()


def test_duplicate_source_rejected(tgen):
    "The same daemon cannot be given twice"
    out = vtysh_conf("interface {}".format(INTF), "qos bandwidth detected ospf ospf")
    assert "twice" in out or "%" in out, out
    out = tgen.gears["r1"].vtysh_cmd("show running-config")
    assert "qos bandwidth detected" not in out, out


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
