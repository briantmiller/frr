#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_sand_mixed_mesh.py
#
# SAND over a mix of one-way and two-way links, with two equal-cost
# one-way paths from r1 to r4:
#
#          +---> r2 ---+
#          |  (1-way)  | (1-way)
#          |           v
#     +-- r1           r4 <---> r5
#     |    |           ^         |
#     |    +---> r3 ---+         |
#     |      (1-way)  (1-way)    |
#     +--------------------------+
#              r5 <---> r1
#
# r5 receives from r1 at cost 20, so r1 -> r5 -> r4 (30) loses to the two
# one-way paths (20 each).
#
# Covers ECMP over one-way paths, failover when one path breaks, and a
# partition into {r1, r2, r3} and {r4, r5}: a change made on one side
# while apart must reach the other side after healing, and all
# databases must end up identical.
#

import os
import sys
import time
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib import sand

pytestmark = [pytest.mark.sandd]

ROUTERS = ["r1", "r2", "r3", "r4", "r5"]
LOOPBACK = {r: "10.255.0.{}".format(r[1:]) for r in ROUTERS}
LOOPBACK6 = {r: "2001:db8:ff::{}".format(r[1:]) for r in ROUTERS}
HOLD = 4

# every link, as (a, b); one-way ones only carry a -> b
LINKS = [
    ("r1", "r2"),
    ("r1", "r3"),
    ("r2", "r4"),
    ("r3", "r4"),
    ("r4", "r5"),
    ("r5", "r1"),
]
ONE_WAY = [("r1", "r2"), ("r1", "r3"), ("r2", "r4"), ("r3", "r4")]


def ifname(a, b):
    return "{}-{}".format(a, b)


def build_topo(tgen):
    for r in ROUTERS:
        tgen.add_router(r)
    for a, b in LINKS:
        tgen.add_link(tgen.gears[a], tgen.gears[b], ifname(a, b), ifname(b, a))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for name, router in tgen.routers().items():
        if not os.path.isfile(os.path.join(router.net.daemondir, "sandd")):
            tgen.set_error("sandd not built")
            pytest.skip("sandd is not installed")
        sand.prepare_router(router)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(name)))

    for sender, receiver in ONE_WAY:
        sand.block_tx(tgen.gears[receiver], ifname(receiver, sender))

    tgen.start_router()

    if sand.have_ipv6():
        for name, router in tgen.routers().items():
            router.cmd("ip -6 addr add {}/128 dev lo".format(LOOPBACK6[name]))


def teardown_module(_mod):
    get_topogen().stop_topology()


def skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    return tgen


def wait_converged(tgen, count=80):
    result = sand.wait_for(
        partial(sand.all_pairs_reachable, tgen, LOOPBACK), count=count
    )
    assert result is None, result


def cut(tgen, a, b):
    "Break the link a <-> b in both directions"
    sand.block_tx(tgen.gears[a], ifname(a, b))
    sand.block_tx(tgen.gears[b], ifname(b, a))


def heal(tgen, a, b):
    "Undo cut(); one-way links keep their permanent rule"
    sand.unblock_tx(tgen.gears[a], ifname(a, b))
    sand.unblock_tx(tgen.gears[b], ifname(b, a))


def nexthops(router, prefix):
    rt = sand.sand_json(router, "show sand route json").get(prefix, {})
    return sorted(nh["interface"] for nh in rt.get("nexthops", []))


def test_sand_converged():
    "Full reachability over one-way and two-way links"
    tgen = skip_on_failure()
    wait_converged(tgen)
    if sand.have_ipv6():
        result = sand.wait_for(
            partial(sand.all_pairs_reachable, tgen, LOOPBACK6, True), count=60
        )
        assert result is None, result
    else:
        logger.info("IPv6 disabled in this kernel, skipping IPv6 pings")


def test_sand_return_paths():
    "r2 has no link back to r1: its return path goes r2 -> r4 -> r5 -> r1"
    tgen = skip_on_failure()
    r2 = tgen.gears["r2"]
    expected = {
        "routers": {
            "10.255.0.1": {
                "cost": 30,
                "firstHops": [{"interface": "r2-r4", "neighbor": "10.255.0.4"}],
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r2, "show sand topology json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
    assert result is None, "r2: unexpected path to r1"


def test_sand_ecmp():
    "r1 reaches r4 over two equal-cost one-way paths"
    tgen = skip_on_failure()
    r1 = tgen.gears["r1"]

    def two_paths():
        nh = nexthops(r1, "10.255.0.4/32")
        return None if nh == ["r1-r2", "r1-r3"] else "next hops {}".format(nh)

    assert sand.wait_for(two_paths, count=40) is None, "no ECMP to r4"

    expected = {
        "10.255.0.4/32": [
            {
                "protocol": "sand",
                "installed": True,
                "nexthops": [
                    {"interfaceName": "r1-r2", "active": True},
                    {"interfaceName": "r1-r3", "active": True},
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 10.255.0.4/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "zebra did not install both next hops"


def test_sand_failover():
    "Breaking r2 -> r4 leaves r1 with the single path through r3"
    tgen = skip_on_failure()
    r1 = tgen.gears["r1"]
    cut(tgen, "r2", "r4")

    def one_path():
        nh = nexthops(r1, "10.255.0.4/32")
        return None if nh == ["r1-r3"] else "next hops {}".format(nh)

    assert (
        sand.wait_for(one_path, count=(HOLD * 3 + 5) * 2) is None
    ), "r1 did not fail over to r3"
    assert sand.ping_ok(r1, "10.255.0.1", "10.255.0.4")

    heal(tgen, "r2", "r4")

    def two_paths():
        nh = nexthops(r1, "10.255.0.4/32")
        return None if nh == ["r1-r2", "r1-r3"] else "next hops {}".format(nh)

    assert sand.wait_for(two_paths, count=60) is None, "ECMP not restored"


def test_sand_partition_and_heal():
    "A change made during a partition reaches the other side after healing"
    tgen = skip_on_failure()
    r1, r5 = tgen.gears["r1"], tgen.gears["r5"]
    boundary = [("r2", "r4"), ("r3", "r4"), ("r5", "r1")]

    for a, b in boundary:
        cut(tgen, a, b)

    def split():
        out = r1.cmd("ip route show 10.255.0.5 proto 199")
        return None if out.strip() == "" else "r1 still routes to r5"

    assert (
        sand.wait_for(split, count=(HOLD * 3 + 5) * 2) is None
    ), "partition not detected"

    # change state on the {r4, r5} side while apart
    r5.cmd("ip addr add 10.99.0.5/32 dev lo")
    r5.vtysh_multicmd("configure terminal\nrouter sand\nnetwork 10.99.0.5/32\n")
    time.sleep(2)

    for a, b in boundary:
        heal(tgen, a, b)

    wait_converged(tgen)

    def new_prefix():
        out = r1.cmd("ip route show 10.99.0.5 proto 199")
        return None if out.strip() else "10.99.0.5/32 not at r1"

    assert (
        sand.wait_for(new_prefix, count=40) is None
    ), "prefix added during the partition never arrived"

    def digests_equal():
        d = {r: sand.sand_digest(tgen.gears[r]) for r in ROUTERS}
        return None if len(set(d.values())) == 1 else "digests {}".format(d)

    assert (
        sand.wait_for(digests_equal, count=40) is None
    ), "databases differ after healing"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
