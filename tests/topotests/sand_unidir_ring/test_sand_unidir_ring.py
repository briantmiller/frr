#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_sand_unidir_ring.py
#
# SAND over a ring of one-way links: no link in this topology works in
# both directions, yet every router must reach every other one.
#
#            r1-r2 (10.12.0.0/30)
#     r1 ----------------------> r2
#      ^                          |
#      | r3-r1 (10.31.0.0/30)     | r2-r3 (10.23.0.0/30)
#      |                          v
#      +----------------------- r3
#
# Covers convergence, next hops and permanent neighbor entries, restart
# without cleanup (sequence numbers must jump past the old state),
# graceful leave, crash, emissions control (silent) and duplicate
# router-id detection.
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

ROUTERS = ["r1", "r2", "r3"]
LOOPBACK = {"r1": "10.255.0.1", "r2": "10.255.0.2", "r3": "10.255.0.3"}
LOOPBACK6 = {"r1": "2001:db8:ff::1", "r2": "2001:db8:ff::2", "r3": "2001:db8:ff::3"}
HOLD = 4

# (sender, receiver): traffic flows only sender -> receiver, so the
# receiver's transmissions on that link are dropped.
ONE_WAY = [("r1", "r2"), ("r2", "r3"), ("r3", "r1")]


def build_topo(tgen):
    for r in ROUTERS:
        tgen.add_router(r)
    for a, b in ONE_WAY:
        tgen.add_link(
            tgen.gears[a], tgen.gears[b], "{}-{}".format(a, b), "{}-{}".format(b, a)
        )


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
        sand.block_tx(tgen.gears[receiver], "{}-{}".format(receiver, sender))

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


def wait_converged(tgen, count=60):
    result = sand.wait_for(
        partial(sand.all_pairs_reachable, tgen, LOOPBACK), count=count
    )
    assert result is None, result


#
# Convergence
#


def test_sand_topology():
    "Every router sees every other one live and reachable"
    tgen = skip_on_failure()
    expected = {
        "routers": {lo: {"live": True, "reachable": True} for lo in LOOPBACK.values()}
    }
    for name in ROUTERS:
        router = tgen.gears[name]
        test_func = partial(
            topotest.router_json_cmp, router, "show sand topology json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, "{}: topology not complete".format(name)


def test_sand_heard_links():
    "Each router hears exactly one sender: the previous router on the ring"
    tgen = skip_on_failure()
    previous = {b: a for a, b in ONE_WAY}
    for name in ROUTERS:
        links = sand.sand_json(tgen.gears[name], "show sand neighbor json")
        senders = sorted({l["sender"] for l in links.get("links", [])})
        assert senders == [
            LOOPBACK[previous[name]]
        ], "{} hears {}, expected only {}".format(
            name, senders, LOOPBACK[previous[name]]
        )


def test_sand_routes():
    "r1 reaches r3 the long way round (via r2) and the route is in zebra"
    tgen = skip_on_failure()
    r1 = tgen.gears["r1"]

    expected = {
        "10.255.0.2/32": {"nexthops": [{"ip": "10.12.0.2", "interface": "r1-r2"}]},
        "10.255.0.3/32": {"nexthops": [{"ip": "10.12.0.2", "interface": "r1-r2"}]},
        # host route to r3's address on the r3->r1 link: replies to it
        # must not use the connected route out of the receive-only link
        "10.31.0.1/32": {"nexthops": [{"ip": "10.12.0.2", "interface": "r1-r2"}]},
    }
    test_func = partial(topotest.router_json_cmp, r1, "show sand route json", expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "r1: unexpected SAND routes"

    expected = {
        "10.255.0.3/32": [
            {
                "protocol": "sand",
                "installed": True,
                "nexthops": [
                    {"ip": "10.12.0.2", "interfaceName": "r1-r2", "onLink": True}
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 10.255.0.3/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "r1: route to r3 not installed by zebra"


def test_sand_permanent_neighbor():
    "One-way next hops never answer ARP: SAND installs the neighbor entry"
    tgen = skip_on_failure()
    out = tgen.gears["r1"].cmd("ip neigh show 10.12.0.2 dev r1-r2")
    assert "PERMANENT" in out, "no permanent neighbor entry: {}".format(out)


def test_sand_reachability():
    "All pairs reachable over IPv4 (and IPv6 when the kernel has it)"
    tgen = skip_on_failure()
    wait_converged(tgen)
    if not sand.have_ipv6():
        logger.info("IPv6 disabled in this kernel, skipping IPv6 pings")
        return
    result = sand.wait_for(
        partial(sand.all_pairs_reachable, tgen, LOOPBACK6, True), count=60
    )
    assert result is None, result


#
# Restart, leave, crash
#


def r2_router_seq(router):
    return sand.records_of(router, "10.255.0.2").get(("router", 0), (0, None))[0]


def test_sand_restart_jumps_sequence():
    "A restarted router jumps past the sequence numbers of its old records"
    tgen = skip_on_failure()
    r1, r2, r3 = (tgen.gears[r] for r in ROUTERS)

    # Push r2's Router record sequence up (cost of links heard on r2-r1)
    for cost in (11, 12, 13, 14):
        r2.vtysh_multicmd(
            "configure terminal\ninterface r2-r1\nsand cost {}\n".format(cost)
        )
        time.sleep(1.2)

    def seq_at_least(n):
        return (
            None
            if r2_router_seq(r1) >= n
            else "r1 has seq {}".format(r2_router_seq(r1))
        )

    assert sand.wait_for(partial(seq_at_least, 4), count=30) is None
    before = r2_router_seq(r1)
    logger.info("r2 Router record sequence before restart: %d", before)

    r2.killDaemons(["sandd"])
    r2.startDaemons(["sandd"])

    # the restarted r2 starts at 1, sees its old record and goes past it
    assert (
        sand.wait_for(partial(seq_at_least, before + 1), count=60) is None
    ), "r2's sequence did not move past {}".format(before)
    wait_converged(tgen)

    def copies_agree():
        a, b = sand.records_of(r1, "10.255.0.2"), sand.records_of(r3, "10.255.0.2")
        return None if a and a == b else "r1 {} != r3 {}".format(a, b)

    assert (
        sand.wait_for(copies_agree, count=30) is None
    ), "r1 and r3 hold different copies of r2's records"


def route_absent(router, prefix):
    out = router.cmd("ip route show {} proto 199".format(prefix))
    return None if out.strip() == "" else "still installed: " + out


def test_sand_graceful_leave():
    "A clean shutdown purges records: others withdraw at once, not after hold"
    tgen = skip_on_failure()
    r1, r3 = tgen.gears["r1"], tgen.gears["r3"]

    r3.cmd("kill -TERM $(cat /var/run/frr/sandd.pid)")
    result = sand.wait_for(
        partial(route_absent, r1, "10.255.0.3"), count=int(HOLD / 0.5) - 2
    )
    assert result is None, "r1 kept r3's route after a graceful stop: " + result

    r3.startDaemons(["sandd"])
    wait_converged(tgen)


def test_sand_crash_liveness():
    "A crashed router is withdrawn once nobody hears it (liveness rule)"
    tgen = skip_on_failure()
    r1, r3 = tgen.gears["r1"], tgen.gears["r3"]

    r3.killDaemons(["sandd"])
    result = sand.wait_for(
        partial(route_absent, r1, "10.255.0.3"), count=(HOLD * 3 + 5) * 2
    )
    assert result is None, "r1 kept routes to crashed r3: " + result

    r3.startDaemons(["sandd"])
    wait_converged(tgen)


#
# Emissions control
#


def test_sand_silent():
    "Others keep routing to a silent router, and its records say so"
    tgen = skip_on_failure()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    r2.vtysh_multicmd("configure terminal\nrouter sand\nsilent hold 120\n")
    time.sleep(HOLD * 2 + 2)  # well past the hold time

    out = r1.cmd("ip route show 10.255.0.2 proto 199")
    assert "10.12.0.2" in out, "r1 lost its route to silent r2"

    # r2 cannot answer (nobody can hear it), so check one-way delivery
    rx = "cat /sys/class/net/r2-r1/statistics/rx_packets"
    before = int(r2.cmd(rx))
    r1.cmd("ping -c 3 -i 0.2 -W 1 -I 10.255.0.1 10.255.0.2")
    after = int(r2.cmd(rx))
    assert after - before >= 3, "r1's packets no longer reach silent r2"

    recs = sand.sand_json(r1, "show sand database json")["records"]
    flags = [x["silent"] for x in recs if x["originator"] == "10.255.0.2"]
    assert flags and all(flags), "r2's records do not carry the Silent flag"

    r2.vtysh_multicmd("configure terminal\nrouter sand\nno silent\n")
    wait_converged(tgen)


#
# Duplicate router-id
#


def test_sand_duplicate_router_id():
    "Two routers with one router-id are detected and logged"
    tgen = skip_on_failure()
    r2, r3 = tgen.gears["r2"], tgen.gears["r3"]
    logs = [os.path.join(r.logdir, r.name, "sandd.log") for r in (r2, r3)]

    r3.vtysh_multicmd("configure terminal\nrouter sand\nrouter-id 10.255.0.2\n")

    def detected():
        for log in logs:
            if os.path.exists(log) and "appears to be in use" in open(log).read():
                return None
        return "no duplicate router-id message yet"

    assert sand.wait_for(detected, count=60) is None, "duplicate router-id not reported"

    r3.vtysh_multicmd("configure terminal\nrouter sand\nrouter-id 10.255.0.3\n")
    wait_converged(tgen, count=180)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
