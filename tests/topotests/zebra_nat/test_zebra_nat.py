#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_nat.py
#
"""
Test zebra stateful NAT ("ip nat inside" / "ip nat outside") implemented
with tc flower and act_ct.

    h1 (10.0.1.2) --- s1 --- r1 --- s2 --- h2 (192.0.2.2)
                     r1-eth0      r1-eth1
                     inside       outside (192.0.2.1)

h2 has no route back to 10.0.1.0/24, so h1 can only reach h2 if r1
translates h1's traffic to its outside address.
"""

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.mgmtd]

OUTSIDE_IF = "r1-eth1"
OUTSIDE_ADDR = "192.0.2.1"
INSIDE_HOST = "10.0.1.2"
OUTSIDE_HOST = "192.0.2.2"
NAT_PRIOS = {48865, 48866}


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_host("h1", INSIDE_HOST + "/24", "via 10.0.1.1")
    # Deliberately no route back to the inside network
    tgen.add_host("h2", OUTSIDE_HOST + "/24", "via 192.0.2.254")

    s1 = tgen.add_switch("s1")
    s1.add_link(tgen.gears["h1"])
    s1.add_link(tgen.gears["r1"])

    s2 = tgen.add_switch("s2")
    s2.add_link(tgen.gears["r1"])
    s2.add_link(tgen.gears["h2"])


def kernel_supports_tc_ct(router):
    "Probe for clsact, cls_flower and act_ct support."
    router.cmd("ip link add natprobe0 type dummy")
    out = router.cmd(
        "tc qdisc add dev natprobe0 clsact && "
        "tc filter add dev natprobe0 egress protocol ip prio 1 flower "
        "skip_hw ct_state +trk+new action ct commit zone 1 nat src addr 192.0.2.9 "
        "&& echo NAT_PROBE_OK"
    )
    router.cmd("ip link del natprobe0")
    return "NAT_PROBE_OK" in out


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    if not kernel_supports_tc_ct(r1):
        tgen.set_error("kernel lacks clsact/flower/act_ct support")

    r1.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    return tgen


def nat_filters(router):
    "Return the set of (hook, chain, prio) for zebra's NAT filters."
    found = set()
    for hook in ("ingress", "egress"):
        for chain in (0, 0xBEE0):
            out = router.cmd(
                "tc -j filter show dev {} {} chain {}".format(OUTSIDE_IF, hook, chain)
            )
            try:
                filters = json.loads(out) if out.strip() else []
            except json.decoder.JSONDecodeError:
                filters = []
            for f in filters:
                if f.get("pref") in NAT_PRIOS:
                    found.add((hook, chain, f["pref"]))
    return found


EXPECTED_FILTERS = {
    ("egress", 0, 48865),
    ("egress", 0, 48866),
    ("egress", 0xBEE0, 48865),
    ("egress", 0xBEE0, 48866),
    ("ingress", 0, 48865),
}


def test_nat_installed():
    "zebra reports the outside interface as installed and programs tc."
    tgen = skip_on_failure()
    r1 = tgen.gears["r1"]

    expected = {
        "vrfs": {
            "default": {
                "outsideInterfaces": [
                    {
                        "interface": OUTSIDE_IF,
                        "status": "installed",
                        "address": OUTSIDE_ADDR,
                        "tcObjectsFailed": 0,
                        "insideInterfaces": 1,
                    }
                ],
                "insideInterfaces": [{"interface": "r1-eth0", "active": True}],
            }
        }
    }
    test_func = functools.partial(
        topotest.router_json_cmp, r1, "show ip nat statistics json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "NAT not installed on r1: {}".format(result)

    filters = nat_filters(r1)
    assert filters == EXPECTED_FILTERS, "unexpected tc filters: {}".format(filters)


def test_nat_translates():
    "Traffic from the inside host reaches the outside host and is translated."
    tgen = skip_on_failure()
    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]

    def _ping():
        out = h1.run("ping -c 3 -i 0.2 -W 1 {}".format(OUTSIDE_HOST))
        return " 0% packet loss" in out

    _, result = topotest.run_and_expect(_ping, True, count=10, wait=1)
    assert result, "h1 cannot reach h2 through the NAT"

    expected = {
        "translations": [
            {
                "protocol": "icmp",
                "insideLocalAddress": INSIDE_HOST,
                "insideGlobalAddress": OUTSIDE_ADDR,
                "outsideInterface": OUTSIDE_IF,
            }
        ]
    }
    test_func = functools.partial(
        topotest.router_json_cmp, r1, "show ip nat translations json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "translation not shown: {}".format(result)

    stats = json.loads(r1.vtysh_cmd("show ip nat statistics json"))
    vrf = stats["vrfs"]["default"]
    assert vrf["icmpTranslations"] >= 1
    assert "entries" in stats["conntrack"] or "error" not in stats["conntrack"]


def test_nat_clear():
    "clear ip nat translation * removes the conntrack entries."
    tgen = skip_on_failure()
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("clear ip nat translation *")
    out = json.loads(r1.vtysh_cmd("show ip nat translations json"))
    logger.info("translations after clear: %s", out)
    assert out["total"] == 0


def test_nat_port_forward():
    "A static tcp translation forwards the outside port to the inside host."
    tgen = skip_on_failure()
    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]
    h2 = tgen.gears["h2"]

    server = h1.popen(
        ["python3", "-m", "http.server", "8000", "--bind", INSIDE_HOST],
    )
    try:
        r1.vtysh_cmd("""
            configure terminal
             ip nat inside source static tcp {} 8000 interface {} 8080
            """.format(INSIDE_HOST, OUTSIDE_IF))

        expected = {
            "vrfs": {
                "default": {
                    "staticTranslations": [
                        {
                            "protocol": "tcp",
                            "localAddress": INSIDE_HOST,
                            "localPort": 8000,
                            "globalInterface": OUTSIDE_IF,
                            "globalPort": 8080,
                            "active": True,
                            "resolvedGlobalAddress": OUTSIDE_ADDR,
                        }
                    ]
                }
            }
        }
        test_func = functools.partial(
            topotest.router_json_cmp, r1, "show ip nat statistics json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "static translation not active: {}".format(result)

        def _fetch():
            out = h2.run(
                'python3 -c "import urllib.request; print(urllib.request.urlopen('
                "'http://{}:8080/', timeout=2).status)\"".format(OUTSIDE_ADDR)
            )
            return "200" in out

        _, result = topotest.run_and_expect(_fetch, True, count=10, wait=1)
        assert result, "port forward to the inside host does not work"

        expected = {
            "translations": [
                {
                    "protocol": "tcp",
                    "insideGlobal": "{}:8080".format(OUTSIDE_ADDR),
                    "insideLocal": "{}:8000".format(INSIDE_HOST),
                    "static": True,
                },
                {
                    "protocol": "tcp",
                    "insideGlobalAddress": OUTSIDE_ADDR,
                    "insideGlobalPort": 8080,
                    "insideLocalAddress": INSIDE_HOST,
                    "insideLocalPort": 8000,
                    "outsideAddress": OUTSIDE_HOST,
                    "inbound": True,
                },
            ]
        }
        test_func = functools.partial(
            topotest.router_json_cmp, r1, "show ip nat translations json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert result is None, "port forward translation not shown: {}".format(result)
    finally:
        r1.vtysh_cmd("""
            configure terminal
             no ip nat inside source static tcp {} 8000 interface {} 8080
            """.format(INSIDE_HOST, OUTSIDE_IF))
        server.terminate()
        server.wait()


def test_nat_unconfigure():
    "Removing ip nat outside removes zebra's filters and stops translation."
    tgen = skip_on_failure()
    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]

    r1.vtysh_cmd("""
        configure terminal
         interface {}
          no ip nat outside
        """.format(OUTSIDE_IF))

    def _no_filters():
        return nat_filters(r1)

    _, result = topotest.run_and_expect(_no_filters, set(), count=10, wait=1)
    assert result == set(), "NAT filters left behind: {}".format(result)

    out = h1.run("ping -c 2 -i 0.2 -W 1 {}".format(OUTSIDE_HOST))
    assert "100% packet loss" in out, "traffic still reaches h2 without NAT"

    r1.vtysh_cmd("""
        configure terminal
         interface {}
          ip nat outside
        """.format(OUTSIDE_IF))
    _, result = topotest.run_and_expect(
        lambda: nat_filters(r1), EXPECTED_FILTERS, count=10, wait=1
    )
    assert result == EXPECTED_FILTERS, "NAT filters not reinstalled: {}".format(result)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
