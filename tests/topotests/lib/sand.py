# SPDX-License-Identifier: ISC
#
# Helpers for SAND (sandd) topotests: one-way links, reachability and
# database checks.
#

"""
SAND test helpers.

One-way links are made by dropping everything a router transmits on an
interface (OUTPUT for its own packets, FORWARD for routed traffic).  The
other direction is untouched, so the link works only toward that router.
"""

import json
import os

from lib import topotest


def have_ipv6():
    "True if the kernel has IPv6 (it may be booted with ipv6.disable=1)."
    return os.path.isdir("/proc/sys/net/ipv6")


def prepare_router(router):
    "Kernel settings SAND needs: forwarding on, reverse-path filtering off."
    router.cmd("sysctl -qw net.ipv4.ip_forward=1")
    router.cmd("sysctl -qw net.ipv4.conf.all.rp_filter=0")
    router.cmd("sysctl -qw net.ipv4.conf.default.rp_filter=0")
    if have_ipv6():
        router.cmd("sysctl -qw net.ipv6.conf.all.forwarding=1")


def _tables():
    return ["iptables", "ip6tables"] if have_ipv6() else ["iptables"]


def block_tx(router, ifname):
    """
    Drop everything `router` transmits on `ifname`.  Calling it twice adds
    two rules; unblock_tx() removes one, so a temporary cut on top of a
    permanent one-way rule can be undone without losing the latter.
    """
    for t in _tables():
        router.cmd("{} -A OUTPUT -o {} -j DROP".format(t, ifname))
        router.cmd("{} -A FORWARD -o {} -j DROP".format(t, ifname))


def unblock_tx(router, ifname):
    "Remove one block_tx() rule pair for `ifname`."
    for t in _tables():
        router.cmd("{} -D OUTPUT -o {} -j DROP".format(t, ifname), warn=False)
        router.cmd("{} -D FORWARD -o {} -j DROP".format(t, ifname), warn=False)


def ping_ok(router, src, dst, ipv6=False):
    "One ping from loopback `src` to `dst`; True if answered."
    out = router.cmd(
        "ping {} -c 1 -W 1 -I {} {}".format("-6" if ipv6 else "", src, dst),
        warn=False,
    )
    return " 0% packet loss" in out


def all_pairs_reachable(tgen, loopbacks, ipv6=False):
    """
    `loopbacks` maps router name -> loopback address.  Returns None when
    every router reaches every other one, else a description of the first
    failure (the run_and_expect() convention).
    """
    for src_name, src in loopbacks.items():
        router = tgen.gears[src_name]
        for dst_name, dst in loopbacks.items():
            if src_name == dst_name:
                continue
            if not ping_ok(router, src, dst, ipv6):
                return "{} cannot reach {} ({})".format(src_name, dst_name, dst)
    return None


def sand_json(router, cmd):
    "Run a 'show sand ... json' command and return the parsed output."
    out = router.vtysh_cmd(cmd)
    try:
        return json.loads(out)
    except ValueError:
        return {}


def records_of(router, originator):
    """
    (type, fragment) -> (sequence, checksum) for every live record of
    `originator` in `router`'s database.
    """
    db = sand_json(router, "show sand database json")
    recs = {}
    for r in db.get("records", []):
        if r["originator"] == originator and not r["purged"] and not r["expired"]:
            recs[(r["type"], r["fragment"])] = (r["sequence"], r["checksum"])
    return recs


def sand_digest(router):
    return sand_json(router, "show sand json").get("digest")


def wait_for(func, count=60, wait=0.5):
    "run_and_expect() for a function that returns None on success."
    _, result = topotest.run_and_expect(func, None, count=count, wait=wait)
    return result
