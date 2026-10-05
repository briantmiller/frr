#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_mtr_topo1.py
#
# OSPFv2 Multi-Topology Routing (RFC 4915).
#
#            (MT10 cost 100)
#        r1 ---------------- r2
#        |                    |
#        |                    |        area 0
#        r3 ---------------- r4 (legacy, ASBR: 192.168.4.0/24)
#        |
#        |                             area 1
#        r5 (legacy)
#
# r1, r2 and r3 run MTR with "mtr copy-base-topology" and
# "mtr-route-table-offset 255"; r4 and r5 have no MTR configuration.
# The r1-r2 link is expensive in topology 10 only, so topology 10 routes
# (kernel table 265) avoid it while the default topology still uses it.
#

"""
test_ospf_mtr_topo1.py: test OSPF multi-topology routing (RFC 4915).
"""

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ospfd]


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r1", "r3"),
        "s3": ("r2", "r4"),
        "s4": ("r3", "r4"),
        "s5": ("r3", "r5"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(router.name)))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def _expect(router, cmd, expected, msg, exact=False):
    def _check():
        output = json.loads(router.vtysh_cmd(cmd))
        return topotest.json_cmp(output, expected, exact=exact)

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, "{}: {}".format(router.name, msg)


def _expect_absent(router, cmd, prefix, msg):
    def _check():
        output = json.loads(router.vtysh_cmd(cmd))
        return None if prefix not in output else output[prefix]

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, "{}: {}".format(router.name, msg)


def _nh(ip, ifname):
    return {"ip": ip, "interfaceName": ifname, "fib": True}


def test_ospf_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _expect(
        r1,
        "show ip route 4.4.4.4/32 json",
        {
            "4.4.4.4/32": [
                {
                    "protocol": "ospf",
                    "metric": 20,
                    "nexthops": [
                        _nh("10.0.12.2", "r1-eth0"),
                        _nh("10.0.13.3", "r1-eth1"),
                    ],
                }
            ]
        },
        "default topology does not use ECMP towards 4.4.4.4",
    )


def test_ospf_mtr_lsas():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Router-LSA of r1 carries the MT-ID metrics of r1-eth0.
    def _check_router_lsa():
        output = r1.vtysh_cmd("show ip ospf database router 1.1.1.1")
        if "MTID 10 Metric: 100" in output and "MTID 20 Metric: 5" in output:
            return None
        return output

    _, result = topotest.run_and_expect(_check_router_lsa, None, count=30, wait=1)
    assert result is None, "Router-LSA of r1 lacks MT-ID metrics"

    # ABR r3 includes the topology 10 metric in its Summary-LSA for 5.5.5.5.
    def _check_summary_lsa():
        output = r1.vtysh_cmd("show ip ospf database summary 5.5.5.5")
        if "MTID: 10  Metric: 7" in output:
            return None
        return output

    _, result = topotest.run_and_expect(_check_summary_lsa, None, count=30, wait=1)
    assert result is None, "Summary-LSA of r3 lacks MT-ID 10 metric"


def test_ospf_mtr_tables():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    _expect(
        r1,
        "show ip ospf mt-topology json",
        {
            "default": {
                "copyBaseTopology": True,
                "routeTableOffset": 255,
                "topologies": {
                    "10": {"routeTable": 265, "installed": True},
                    "20": {"routeTable": 275, "installed": True},
                },
            }
        },
        "topologies 10 and 20 not present",
    )

    # Topology 10 avoids the r1-r2 link (MT-ID 10 cost 100).
    _expect(
        r1,
        "show ip route table 265 json",
        {
            "2.2.2.2/32": [
                {"protocol": "ospf", "metric": 30, "nexthops": [_nh("10.0.13.3", "r1-eth1")]}
            ],
            "4.4.4.4/32": [
                {
                    "protocol": "ospf",
                    "metric": 20,
                    "internalNextHopNum": 1,
                    "nexthops": [_nh("10.0.13.3", "r1-eth1")],
                }
            ],
            # inter-area route: r3's MT-ID 10 metric (7) is used
            "5.5.5.5/32": [{"protocol": "ospf", "metric": 17}],
            # external route from the legacy ASBR r4
            "192.168.4.0/24": [
                {"protocol": "ospf", "nexthops": [_nh("10.0.13.3", "r1-eth1")]}
            ],
        },
        "topology 10 routes not installed in table 265",
    )

    # Topology 20 prefers the r1-r2 link (MT-ID 20 cost 5).
    _expect(
        r1,
        "show ip route table 275 json",
        {
            "4.4.4.4/32": [
                {"protocol": "ospf", "metric": 15, "nexthops": [_nh("10.0.12.2", "r1-eth0")]}
            ],
        },
        "topology 20 routes not installed in table 275",
    )


def test_ospf_mtr_legacy_router():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r4 = tgen.gears["r4"]

    # Legacy routers keep normal routing and do not build topologies.
    _expect(
        r4,
        "show ip route 1.1.1.1/32 json",
        {"1.1.1.1/32": [{"protocol": "ospf", "metric": 20}]},
        "legacy router lost default topology routes",
    )
    output = json.loads(r4.vtysh_cmd("show ip ospf mt-topology json"))
    assert output["default"]["topologies"] == {}, "legacy router built topologies"


def test_ospf_mtr_copy_base():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Without copy-base, links of the legacy router r4 are not part of
    # topology 10 (RFC 4915 3.6).
    r1.vtysh_cmd("configure terminal\nrouter ospf\nno mtr copy-base-topology")
    _expect_absent(
        r1,
        "show ip route table 265 json",
        "4.4.4.4/32",
        "4.4.4.4 still in topology 10 without copy-base",
    )

    r1.vtysh_cmd("configure terminal\nrouter ospf\nmtr copy-base-topology")
    _expect(
        r1,
        "show ip route table 265 json",
        {"4.4.4.4/32": [{"protocol": "ospf", "metric": 20}]},
        "4.4.4.4 not back in topology 10 with copy-base",
    )


def test_ospf_mtr_table_offset():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("configure terminal\nrouter ospf\nmtr-route-table-offset 1000")
    _expect(
        r1,
        "show ip route table 1010 json",
        {"4.4.4.4/32": [{"protocol": "ospf"}]},
        "topology 10 routes not moved to table 1010",
    )
    _expect_absent(
        r1,
        "show ip route table 265 json",
        "4.4.4.4/32",
        "topology 10 routes not removed from table 265",
    )

    r1.vtysh_cmd("configure terminal\nrouter ospf\nmtr-route-table-offset 255")
    _expect(
        r1,
        "show ip route table 265 json",
        {"4.4.4.4/32": [{"protocol": "ospf"}]},
        "topology 10 routes not moved back to table 265",
    )


def test_ospf_mtr_topology_removal():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    # MT-ID 20 is only configured on r1-eth0: removing it removes the
    # topology from the whole domain and withdraws its routes.
    r1.vtysh_cmd("configure terminal\ninterface r1-eth0\nno ip ospf mt-id 20")

    for router in (r1, r3):
        _expect(
            router,
            "show ip ospf mt-topology json",
            {"default": {"topologies": {"20": None}}},
            "topology 20 not removed",
        )
    _expect_absent(
        r1,
        "show ip route table 275 json",
        "4.4.4.4/32",
        "topology 20 routes not withdrawn",
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
