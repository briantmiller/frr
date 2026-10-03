#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_link_create.py
#
# Test zebra creating Linux interfaces (bridge, veth, vlan, gre) via netlink
# using the interface "link-type" and "master" configuration commands.
#

"""
test_zebra_link_create.py: configure link-type / master on interfaces and
verify the kernel state, dependency ordering, re-creation and removal.
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter
from lib.topolog import logger

pytestmark = [pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Sets up the pytest environment"
    tgen = Topogen({"s1": ("r1")}, request.module.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def conf(r1, *cmds):
    r1.vtysh_cmd("configure terminal\n" + "\n".join(cmds))


def link(r1, name):
    "Return kernel link info dict for NAME, or None if it does not exist."
    out = r1.cmd("ip -d -j link show dev {} 2>/dev/null".format(name))
    try:
        return json.loads(out)[0]
    except (ValueError, IndexError):
        return None


def wait_link(r1, name, expect, timeout=15):
    "Wait until link NAME matches EXPECT (a dict subset, or None for absent)."

    def check():
        got = link(r1, name)
        if expect is None:
            return None if got is None else got
        if got is None:
            return "missing"
        return topotest.json_cmp(got, expect)

    _, result = topotest.run_and_expect(check, None, count=timeout * 2, wait=0.5)
    return result


def kind_supported(r1, kind, args="", pre_args=""):
    "Probe whether the test host kernel supports link KIND."
    ok = r1.cmd(
        "ip link add probe0 {} type {} {} 2>&1 && echo OK; ip link del probe0 2>/dev/null".format(
            pre_args, kind, args
        )
    )
    return "OK" in ok


def test_bridge(tgen):
    r1 = tgen.gears["r1"]
    conf(r1, "interface br0", "link-type bridge")
    assert wait_link(r1, "br0", {"linkinfo": {"info_kind": "bridge"}}) is None


def test_veth_and_master(tgen):
    r1 = tgen.gears["r1"]
    conf(r1, "interface vA", "link-type veth peer vB", "master br0")
    assert (
        wait_link(r1, "vA", {"linkinfo": {"info_kind": "veth"}, "master": "br0"})
        is None
    )
    assert wait_link(r1, "vB", {"linkinfo": {"info_kind": "veth"}}) is None


def test_master_generic(tgen):
    "master works on interfaces zebra did not create"
    r1 = tgen.gears["r1"]
    r1.cmd("ip link add dum9 type dummy")
    conf(r1, "interface dum9", "master br0")
    assert wait_link(r1, "dum9", {"master": "br0"}) is None
    conf(r1, "interface dum9", "no master")
    def no_master():
        return None if "master" not in link(r1, "dum9") else "still enslaved"

    _, res = topotest.run_and_expect(no_master, None, count=30, wait=0.5)
    assert res is None
    r1.cmd("ip link del dum9")
    conf(r1, "no interface dum9")


def test_vlan_dependency_and_encap(tgen):
    r1 = tgen.gears["r1"]
    r1.cmd("ip link add dum10 type dummy")
    if not kind_supported(r1, "vlan", "id 5", pre_args="link dum10"):
        r1.cmd("ip link del dum10")
        pytest.skip("kernel lacks vlan support")
    r1.cmd("ip link del dum10")

    # Configured before the parent exists: must wait, then be created.
    conf(r1, "interface br1.10", "link-type vlan parent br1 id 10")
    assert link(r1, "br1.10") is None
    conf(r1, "interface br1", "link-type bridge")
    exp = {
        "link": "br1",
        "linkinfo": {
            "info_kind": "vlan",
            "info_data": {"protocol": "802.1Q", "id": 10},
        },
    }
    assert wait_link(r1, "br1.10", exp) is None

    conf(
        r1,
        "interface br1.20",
        "link-type vlan parent br1 id 20 encapsulation q-in-q",
    )
    exp["linkinfo"]["info_data"] = {"protocol": "802.1ad", "id": 20}
    assert wait_link(r1, "br1.20", exp) is None


def test_gre(tgen):
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "gre", "local 10.0.0.1 remote 10.0.0.2"):
        pytest.skip("kernel lacks gre support")

    conf(
        r1,
        "interface gre1",
        "link-type gre local 10.255.0.1 remote 10.255.0.2 key 42 ttl 16 tos 4",
    )
    exp = {
        "linkinfo": {
            "info_kind": "gre",
            "info_data": {
                "local": "10.255.0.1",
                "remote": "10.255.0.2",
                "ttl": 16,
                "tos": "0x4",
            },
        }
    }
    assert wait_link(r1, "gre1", exp) is None

    # remote "any" with a bound device
    conf(r1, "interface gre2", "link-type gre dev r1-eth0 remote any")
    assert wait_link(r1, "gre2", {"linkinfo": {"info_kind": "gre"}}) is None


def test_param_change_recreates(tgen):
    r1 = tgen.gears["r1"]
    if link(r1, "gre1") is None:
        pytest.skip("gre not available")
    conf(r1, "interface gre1", "link-type gre local 10.255.0.1 remote 10.255.0.9 ttl 8")
    exp = {"linkinfo": {"info_data": {"remote": "10.255.0.9", "ttl": 8}}}
    assert wait_link(r1, "gre1", exp) is None


def test_validation(tgen):
    "Invalid configuration is rejected and nothing is created."
    r1 = tgen.gears["r1"]
    # veth peer == own name; gre without local/dev; vlan id out of range
    for cmds in (
        ("interface bad0", "link-type veth peer bad0"),
        ("interface bad1", "link-type gre remote 1.2.3.4"),
        ("interface bad2", "link-type vlan parent br0 id 5000"),
    ):
        conf(r1, *cmds)
    for n in ("bad0", "bad1", "bad2"):
        assert link(r1, n) is None


def test_recreate_when_deleted_externally(tgen):
    r1 = tgen.gears["r1"]
    r1.cmd("ip link del vA")
    assert wait_link(r1, "vA", {"linkinfo": {"info_kind": "veth"}, "master": "br0"}) is None


def test_running_config(tgen):
    r1 = tgen.gears["r1"]
    out = r1.vtysh_cmd("show running-config")
    assert "interface br0\n link-type bridge" in out
    assert "link-type veth peer vB" in out
    assert " master br0" in out


def port_vlans(r1, name):
    "Return {vid: set(flags)} of the bridge vlans of port NAME."
    out = r1.cmd("bridge -j vlan show dev {} 2>/dev/null".format(name))
    try:
        entries = json.loads(out)
    except ValueError:
        return {}
    vlans = {}
    for ent in entries:
        for v in ent.get("vlans", []):
            for vid in range(v["vlan"], v.get("vlanEnd", v["vlan"]) + 1):
                vlans[vid] = set(v.get("flags", []))
    return vlans


def wait_port_vlans(r1, name, expect, timeout=15):
    "Wait until the vlans of NAME are exactly EXPECT ({vid: set(flags)})."

    def check():
        got = port_vlans(r1, name)
        return None if got == expect else got

    _, result = topotest.run_and_expect(check, None, count=timeout * 2, wait=0.5)
    return result


def port_isolated(r1, name):
    link_info = link(r1, name) or {}
    data = link_info.get("linkinfo", {}).get("info_slave_data", {})
    return bool(data.get("isolated"))


def test_bridge_vlans(tgen):
    "bridge-vlan on/off/untagged, ranges and pvid on a bridge port"
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "bridge", ""):
        pytest.skip("kernel lacks bridge support")
    r1.cmd("ip link add probe1 type bridge vlan_filtering 1")
    probe = link(r1, "probe1")
    r1.cmd("ip link del probe1")
    if probe is None:
        pytest.skip("kernel lacks bridge vlan filtering")

    conf(r1, "interface br2", "link-type bridge", "bridge vlan-filtering on")
    assert (
        wait_link(r1, "br2", {"linkinfo": {"info_data": {"vlan_filtering": 1}}})
        is None
    )

    # Configure the vlans first; they must be applied once enslaved.
    conf(
        r1,
        "interface p1",
        "link-type veth peer p2",
        "bridge-vlan 1 off",
        "bridge-vlan 10 on",
        "bridge-vlan 20 untagged",
        "bridge-pvid 20",
        "bridge-vlan 30 to 32 on",
    )
    assert wait_link(r1, "p1", {"linkinfo": {"info_kind": "veth"}}) is None
    assert port_vlans(r1, "p1") == {}

    conf(r1, "interface p1", "master br2")
    expect = {
        10: set(),
        20: {"PVID", "Egress Untagged"},
        30: set(),
        31: set(),
        32: set(),
    }
    assert wait_port_vlans(r1, "p1", expect) is None

    # change a mode, remove one vlan
    conf(r1, "interface p1", "bridge-vlan 10 untagged", "no bridge-vlan 31")
    expect[10] = {"Egress Untagged"}
    del expect[31]
    assert wait_port_vlans(r1, "p1", expect) is None

    out = r1.vtysh_cmd("show running-config")
    assert " bridge-vlan 10 untagged" in out
    assert " bridge-pvid 20" in out
    assert " bridge vlan-filtering on" in out


def test_bridge_vlan_private(tgen):
    "A private vlan isolates the port; dropping it clears the isolation"
    r1 = tgen.gears["r1"]
    if link(r1, "p1") is None or "master" not in link(r1, "p1"):
        pytest.skip("bridge vlan setup not available")

    conf(r1, "interface p1", "bridge-vlan 40 private")

    def isolated():
        return None if port_isolated(r1, "p1") else "not isolated"

    _, res = topotest.run_and_expect(isolated, None, count=30, wait=0.5)
    assert res is None
    assert 40 in port_vlans(r1, "p1")

    conf(r1, "interface p1", "no bridge-vlan 40")

    def not_isolated():
        return None if not port_isolated(r1, "p1") else "still isolated"

    _, res = topotest.run_and_expect(not_isolated, None, count=30, wait=0.5)
    assert res is None
    assert 40 not in port_vlans(r1, "p1")


def test_bridge_vlans_reapplied(tgen):
    "VLANs are applied again when the port is re-created"
    r1 = tgen.gears["r1"]
    if link(r1, "p1") is None or "master" not in link(r1, "p1"):
        pytest.skip("bridge vlan setup not available")

    r1.cmd("ip link del p1")
    assert wait_link(r1, "p1", {"master": "br2"}) is None
    expect = {
        10: {"Egress Untagged"},
        20: {"PVID", "Egress Untagged"},
        30: set(),
        32: set(),
    }
    assert wait_port_vlans(r1, "p1", expect) is None

    conf(r1, "interface p1", "no link-type", "no master")
    assert wait_link(r1, "p1", None) is None
    conf(r1, "interface br2", "no link-type")
    assert wait_link(r1, "br2", None) is None
    conf(r1, "no interface p1", "no interface br2")


def link_data(r1, name, which):
    "info_data (bridge) or info_slave_data (port) of link NAME"
    return (link(r1, name) or {}).get("linkinfo", {}).get(which, {})


def wait_data(r1, name, which, expect, timeout=15):
    def check():
        return topotest.json_cmp(link_data(r1, name, which), expect)

    _, result = topotest.run_and_expect(check, None, count=timeout * 2, wait=0.5)
    return result


def test_bridge_options(tgen):
    "bridge <setting> on a bridge: set, change, remove restores the default"
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "bridge", ""):
        pytest.skip("kernel lacks bridge support")

    conf(
        r1,
        "interface br3",
        "link-type bridge",
        "bridge stp on",
        "bridge ageing-time 120",
        "bridge priority 4096",
        "bridge forward-delay 10",
        "bridge multicast-snooping off",
        "bridge multicast-querier on",
        "bridge multicast-router enabled",
        "bridge multicast-query-interval 6000",
    )
    expect = {
        "stp_state": 1,
        "ageing_time": 12000,
        "priority": 4096,
        "forward_delay": 1000,
        "mcast_snooping": 0,
        "mcast_querier": 1,
        "mcast_router": 2,
        "mcast_query_intvl": 6000,
    }
    assert wait_data(r1, "br3", "info_data", expect) is None

    # change one, remove others: the kernel defaults come back
    conf(
        r1,
        "interface br3",
        "bridge ageing-time 60",
        "no bridge stp",
        "no bridge multicast-snooping",
    )
    expect = {
        "stp_state": 0,
        "ageing_time": 6000,
        "mcast_snooping": 1,
        "priority": 4096,
    }
    assert wait_data(r1, "br3", "info_data", expect) is None

    out = r1.vtysh_cmd("show running-config")
    assert " bridge ageing-time 60" in out
    assert " bridge priority 4096" in out
    assert " bridge stp" not in out


def test_bridge_port_options(tgen):
    "bridge-port <setting> on a bridge port, applied once enslaved"
    r1 = tgen.gears["r1"]
    if link(r1, "br3") is None:
        pytest.skip("bridge not available")

    conf(
        r1,
        "interface q1",
        "link-type veth peer q2",
        "bridge-port learning off",
        "bridge-port hairpin on",
        "bridge-port bpdu-guard on",
        "bridge-port priority 7",
        "bridge-port cost 55",
        "bridge-port multicast-flood off",
        "bridge-port unicast-flood off",
        "bridge-port broadcast-flood off",
        "bridge-port fast-leave on",
        "bridge-port isolated on",
        "bridge-port multicast-router permanent",
    )
    assert wait_link(r1, "q1", {"linkinfo": {"info_kind": "veth"}}) is None
    assert link_data(r1, "q1", "info_slave_data") == {}

    conf(r1, "interface q1", "master br3")
    expect = {
        "learning": False,
        "hairpin": True,
        "guard": True,
        "priority": 7,
        "cost": 55,
        "mcast_flood": False,
        "flood": False,
        "bcast_flood": False,
        "fastleave": True,
        "isolated": True,
    }
    assert wait_data(r1, "q1", "info_slave_data", expect) is None

    conf(
        r1,
        "interface q1",
        "no bridge-port learning",
        "no bridge-port hairpin",
        "no bridge-port isolated",
        "no bridge-port priority",
    )
    expect = {"learning": True, "hairpin": False, "isolated": False, "cost": 55}
    assert wait_data(r1, "q1", "info_slave_data", expect) is None

    # settings are applied again when the port is re-created
    r1.cmd("ip link del q1")
    expect = {"guard": True, "cost": 55, "flood": False, "fastleave": True}
    assert wait_data(r1, "q1", "info_slave_data", expect) is None

    out = r1.vtysh_cmd("show running-config")
    assert " bridge-port cost 55" in out
    assert " bridge-port multicast-router permanent" in out

    conf(r1, "interface q1", "no link-type", "no master")
    assert wait_link(r1, "q1", None) is None
    conf(r1, "interface br3", "no link-type")
    assert wait_link(r1, "br3", None) is None
    conf(r1, "no interface q1", "no interface br3")


def test_dummy(tgen):
    "link-type dummy: create, recreate when removed behind our back, remove"
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "dummy"):
        pytest.skip("kernel lacks dummy support")

    conf(r1, "interface dm0", "link-type dummy", "exit", "interface dm1", "link-type dummy")
    assert wait_link(r1, "dm0", {"linkinfo": {"info_kind": "dummy"}}) is None
    assert wait_link(r1, "dm1", {"linkinfo": {"info_kind": "dummy"}}) is None

    # a dummy can be a bridge port like any interface
    conf(r1, "interface br4", "link-type bridge", "exit", "interface dm0", "master br4")
    assert wait_link(r1, "dm0", {"master": "br4"}) is None

    # removed behind our back: created again, and enslaved again
    r1.cmd("ip link del dm0")
    assert (
        wait_link(r1, "dm0", {"linkinfo": {"info_kind": "dummy"}, "master": "br4"})
        is None
    )

    # replacing the kind removes the dummy and creates the new link
    conf(r1, "interface dm1", "link-type bridge")
    assert wait_link(r1, "dm1", {"linkinfo": {"info_kind": "bridge"}}) is None

    out = r1.vtysh_cmd("show running-config")
    assert " link-type dummy" in out

    conf(r1, "interface dm0", "no link-type", "no master")
    assert wait_link(r1, "dm0", None) is None
    conf(r1, "interface dm1", "no link-type")
    conf(r1, "interface br4", "no link-type")
    assert wait_link(r1, "dm1", None) is None
    assert wait_link(r1, "br4", None) is None
    conf(r1, "no interface dm0", "no interface dm1", "no interface br4")


def test_vxlan(tgen):
    "link-type vxlan: unicast, parameter change, multicast group on a dev"
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "vxlan", "id 99 dstport 4789 local 10.0.0.1 remote 10.0.0.2"):
        pytest.skip("kernel lacks vxlan support")

    conf(
        r1,
        "interface vx0",
        "link-type vxlan vni 100 local 10.255.1.1 remote 10.255.1.2 ttl 8 learning off",
    )
    exp = {
        "linkinfo": {
            "info_kind": "vxlan",
            "info_data": {
                "id": 100,
                "local": "10.255.1.1",
                "remote": "10.255.1.2",
                "ttl": 8,
                "learning": False,
                "port": 4789,
            },
        }
    }
    assert wait_link(r1, "vx0", exp) is None

    # a changed definition re-creates the interface
    conf(r1, "interface vx0", "link-type vxlan vni 101 dstport 4790 remote 10.255.1.2")  # any order after vni
    exp = {"linkinfo": {"info_data": {"id": 101, "port": 4790, "remote": "10.255.1.2"}}}
    assert wait_link(r1, "vx0", exp) is None

    # a multicast group needs an underlay device; created once it exists
    conf(r1, "interface vx5", "link-type vxlan vni 7 remote 239.1.1.1 dev ul0")
    assert link(r1, "vx5") is None
    conf(r1, "interface ul0", "link-type bridge")
    exp = {
        "linkinfo": {"info_kind": "vxlan", "info_data": {"link": "ul0", "id": 7, "group": "239.1.1.1"}},
    }
    assert wait_link(r1, "vx5", exp) is None

    out = r1.vtysh_cmd("show running-config")
    assert " link-type vxlan vni 101 remote 10.255.1.2 dstport 4790" in out

    for name in ("vx0", "vx5", "ul0"):
        conf(r1, "interface " + name, "no link-type")
        assert wait_link(r1, name, None) is None
    conf(r1, "no interface vx0", "no interface vx5", "no interface ul0")


def test_bareudp(tgen):
    "link-type bareudp: create, parameter change, validation, remove"
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "bareudp", "dstport 6635 ethertype mpls_uc"):
        pytest.skip("kernel lacks bareudp support")

    conf(r1, "interface bu0", "link-type bareudp dstport 6635 ethertype mpls-unicast srcport-min 1024 multiproto")
    exp = {
        "linkinfo": {
            "info_kind": "bareudp",
            "info_data": {"dstport": 6635, "ethertype": "mpls_uc", "srcportmin": 1024, "multiproto": True},
        }
    }
    assert wait_link(r1, "bu0", exp) is None

    # a changed definition re-creates the interface
    conf(r1, "interface bu0", "link-type bareudp dstport 4754 ethertype ipv4")
    exp = {"linkinfo": {"info_data": {"dstport": 4754}}}
    assert wait_link(r1, "bu0", exp) is None

    out = r1.vtysh_cmd("show running-config")
    assert " link-type bareudp dstport 4754 ethertype ipv4" in out

    conf(r1, "interface bu0", "no link-type")
    assert wait_link(r1, "bu0", None) is None
    conf(r1, "no interface bu0")


def test_mtu(tgen):
    "mtu: applied on creation, changed, restored, re-applied on re-creation"
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "bridge"):
        pytest.skip("kernel lacks bridge support")

    conf(r1, "interface mt0", "link-type bridge", "mtu 1400")
    assert wait_link(r1, "mt0", {"mtu": 1400}) is None

    conf(r1, "interface mt0", "mtu 1300")
    assert wait_link(r1, "mt0", {"mtu": 1300}) is None
    assert " mtu 1300" in r1.vtysh_cmd("show running-config")

    # removed behind our back: re-created with the configured MTU
    r1.cmd("ip link del mt0")
    assert wait_link(r1, "mt0", {"mtu": 1300}) is None

    # no mtu restores the MTU the interface had before zebra changed it
    conf(r1, "interface mt0", "no mtu")
    assert wait_link(r1, "mt0", {"mtu": 1500}) is None

    # a link zebra did not create can be given an MTU too
    r1.cmd("ip link add mt1 type bridge")
    conf(r1, "interface mt1", "mtu 1280")
    assert wait_link(r1, "mt1", {"mtu": 1280}) is None
    conf(r1, "interface mt1", "no mtu")
    assert wait_link(r1, "mt1", {"mtu": 1500}) is None
    r1.cmd("ip link del mt1")

    # out-of-range values are rejected by the CLI
    out = r1.vtysh_cmd("configure terminal\ninterface mt0\nmtu 10")
    assert "Unknown command" in out or "range" in out.lower() or "%" in out

    conf(r1, "interface mt0", "no link-type")
    assert wait_link(r1, "mt0", None) is None
    conf(r1, "no interface mt0", "no interface mt1")


def test_removal(tgen):
    r1 = tgen.gears["r1"]
    # no link-type deletes the kernel link; then the interface can be removed.
    conf(r1, "interface vA", "no link-type")
    assert wait_link(r1, "vA", None) is None
    conf(r1, "interface br0", "no link-type")
    assert wait_link(r1, "br0", None) is None
    conf(r1, "no interface vA", "no interface br0")
    out = r1.vtysh_cmd("show running-config")
    assert "interface vA" not in out and "interface br0" not in out


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
