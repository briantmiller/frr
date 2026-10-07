#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test OSPF per-neighbor administrative distance:

    router ospf
     distance (1-255) A.B.C.D A.B.C.D [ACCESSLIST4_NAME]

Topology:

    r2 (2.2.2.2) ---- r1 (1.1.1.1) ---- r3 (3.3.3.3)
     |                                   |
     intra-area 192.168.2.0/24,          inter-area 192.168.3.0/24 (area 1,
     172.16.2.0/24 and external          r3 is the ABR)
     203.0.113.0/24 (r2 is the ASBR)
"""

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.ospfd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

PREFIXES = ["192.168.2.0/24", "172.16.2.0/24", "203.0.113.0/24", "192.168.3.0/24"]


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r1", "r3"),
        "s3": ("r2",),
        "s4": ("r3",),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def _check_distances(router, expected_distances):
    def _check():
        output = json.loads(router.vtysh_cmd("show ip route ospf json"))
        expected = {
            prefix: [{"protocol": "ospf", "selected": True, "distance": distance}]
            for prefix, distance in expected_distances.items()
        }
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    return result


def _config(router, *cmds):
    router.vtysh_multicmd(
        "configure terminal\nrouter ospf\n" + "\n".join(cmds) + "\nend\n"
    )


def test_ospf_distance_default():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    result = _check_distances(r1, {p: 110 for p in PREFIXES})
    assert result is None, "OSPF routes did not converge with distance 110"


def test_ospf_distance_neighbor_exact():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _config(r1, "distance 200 2.2.2.2 0.0.0.0")

    # Intra-area and external routes originated by 2.2.2.2 get 200,
    # the inter-area route originated by ABR 3.3.3.3 does not.
    result = _check_distances(
        r1,
        {
            "192.168.2.0/24": 200,
            "172.16.2.0/24": 200,
            "203.0.113.0/24": 200,
            "192.168.3.0/24": 110,
        },
    )
    assert result is None, "Per-neighbor distance for 2.2.2.2 not applied"


def test_ospf_distance_neighbor_access_list():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        "configure terminal\naccess-list FROM-R2 seq 5 permit 192.168.0.0/16\n"
    )
    _config(r1, "distance 200 2.2.2.2 0.0.0.0 FROM-R2")

    result = _check_distances(
        r1,
        {
            "192.168.2.0/24": 200,
            "172.16.2.0/24": 110,
            "203.0.113.0/24": 110,
            "192.168.3.0/24": 110,
        },
    )
    assert result is None, "Access-list did not restrict per-neighbor distance"


def test_ospf_distance_neighbor_wildcard_fallback():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _config(r1, "distance 150 0.0.0.0 255.255.255.255")

    # ACL-denied routes from 2.2.2.2 fall back to the less specific entry.
    result = _check_distances(
        r1,
        {
            "192.168.2.0/24": 200,
            "172.16.2.0/24": 150,
            "203.0.113.0/24": 150,
            "192.168.3.0/24": 150,
        },
    )
    assert result is None, "Wildcard per-neighbor distance fallback failed"


def test_ospf_distance_neighbor_access_list_update():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        "configure terminal\naccess-list FROM-R2 seq 10 permit 172.16.0.0/16\n"
    )

    result = _check_distances(
        r1,
        {
            "192.168.2.0/24": 200,
            "172.16.2.0/24": 200,
            "203.0.113.0/24": 150,
            "192.168.3.0/24": 150,
        },
    )
    assert result is None, "Access-list change was not applied to distances"


def test_ospf_distance_neighbor_precedence_and_show():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _config(r1, "no distance 150 0.0.0.0 255.255.255.255", "distance ospf external 170")

    result = _check_distances(
        r1,
        {
            "192.168.2.0/24": 200,
            "172.16.2.0/24": 200,
            "203.0.113.0/24": 170,
            "192.168.3.0/24": 110,
        },
    )
    assert result is None, "Per-neighbor distance precedence is wrong"

    output = r1.vtysh_cmd("show running-config ospfd")
    assert " distance 200 2.2.2.2 0.0.0.0 FROM-R2\n" in output

    output = json.loads(r1.vtysh_cmd("show ip ospf json"))
    expected = {
        "distanceNeighbor": [
            {
                "distance": 200,
                "routerId": "2.2.2.2",
                "wildcardMask": "0.0.0.0",
                "accessList": "FROM-R2",
            }
        ]
    }
    assert topotest.json_cmp(output, expected) is None


def test_ospf_distance_neighbor_remove():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _config(r1, "no distance 200 2.2.2.2 0.0.0.0", "no distance ospf")

    result = _check_distances(r1, {p: 110 for p in PREFIXES})
    assert result is None, "Distances did not revert to 110"


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
