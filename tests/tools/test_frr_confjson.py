# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for tools/frr-confjson (frr.conf <-> JSON driven by frr.xref).

Runs from <builddir>/tests like the other unit tests; needs the built
tools/frr-confjson and the build's frr.xref.
"""

import json
import os
import subprocess

import pytest

BUILD = os.path.abspath(os.path.join(os.getcwd(), ".."))
TOOL = os.path.join(BUILD, "tools", "frr-confjson")
XREF = os.path.join(BUILD, "frr.xref")

pytestmark = pytest.mark.skipif(
    not (os.path.exists(TOOL) and os.path.exists(XREF)),
    reason="tools/frr-confjson or frr.xref not built",
)

CONF = """\
frr defaults traditional
hostname r1
log syslog informational
ip prefix-list OWN seq 5 permit 198.51.100.0/24
route-map OUT permit 10
 match ip address prefix-list OWN
 set community 65000:1 65000:2
exit
!
ip route 0.0.0.0/0 192.0.2.254 tag 5 200
interface eth0
 description uplink to core
 ip address 192.0.2.1/24
 ip ospf area 0.0.0.0
exit
!
router bgp 65001
 bgp router-id 10.0.0.1
 no bgp ebgp-requires-policy
 neighbor 192.0.2.2 remote-as external
 neighbor 192.0.2.2 timers 10 30
 address-family ipv4 unicast
  network 198.51.100.0/24
  neighbor 192.0.2.2 route-map OUT out
 exit-address-family
exit
!
router ospf
 ospf router-id 10.0.0.1
exit
!
"""


def run(*args, stdin=None):
    p = subprocess.run(
        [TOOL, "-x", XREF] + list(args),
        input=stdin,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return p.returncode, p.stdout, p.stderr


def lines(text):
    return [l.rstrip() for l in text.splitlines() if l.strip() not in ("", "!")]


def test_self_test():
    rc, _, err = run("--self-test=2")
    assert rc == 0, err


def test_round_trip():
    rc, out, err = run("to-json", "-", stdin=CONF)
    assert rc == 0, err
    doc = json.loads(out)
    rc, conf, err = run("to-conf", "-", stdin=out)
    assert rc == 0, err
    # commands sharing leading words are grouped, so compare as sets
    assert sorted(lines(conf)) == sorted(lines(CONF))
    # text -> JSON -> text -> JSON is stable
    rc, out2, err = run("to-json", "-", stdin=conf)
    assert rc == 0, err
    assert json.loads(out2) == doc


def test_hierarchy_follows_command_line():
    rc, out, err = run("to-json", "-", stdin=CONF)
    assert rc == 0, err
    cfg = json.loads(out)["config"]
    assert cfg["hostname"] == "r1"
    assert cfg["log"] == {"syslog": "informational"}
    assert cfg["interface"]["eth0"] == {
        "description": "uplink to core",
        "ip": {"address": "192.0.2.1/24", "ospf": {"area": "0.0.0.0"}},
    }
    bgp = cfg["router"]["bgp"]["65001"]
    assert bgp["no"] == {"bgp": {"ebgp-requires-policy": True}}
    assert bgp["neighbor"]["192.0.2.2"] == {"remote-as": "external", "timers": "10 30"}
    assert bgp["address-family"]["ipv4"]["unicast"] == {
        "network": "198.51.100.0/24",
        "neighbor": {"192.0.2.2": {"route-map": {"OUT": "out"}}},
    }
    assert cfg["route-map"]["OUT"]["permit"]["10"]["set"] == {
        "community": "65000:1 65000:2"
    }
    assert cfg["router"]["ospf"] == {"ospf": {"router-id": "10.0.0.1"}}


def test_user_example():
    doc = {"config": {"interface": {"eth0": {"ip": {"address": "1.2.3.4/24"}}}}}
    rc, conf, err = run("to-conf", "-", stdin=json.dumps(doc))
    assert rc == 0, err
    assert lines(conf) == ["interface eth0", " ip address 1.2.3.4/24", "exit"]


def test_lists_and_forms():
    doc = {"config": {
        "ip": {"route": {"10.0.0.0/8": ["192.0.2.1", {"192.0.2.3": {"tag": 7}}]}},
        "router": {"ospf": {}},
        "interface": {"lo": {"shutdown": False, "description": "a b c"}},
        "route-map": {"RM": {"permit": {"10": {"set": {"metric": 5}}}}},
        "bgp": ["as-path access-list AP seq 5 permit ^65001_"],
    }}
    rc, conf, err = run("to-conf", "-", stdin=json.dumps(doc))
    assert rc == 0, err
    assert lines(conf) == [
        "ip route 10.0.0.0/8 192.0.2.1",
        "ip route 10.0.0.0/8 192.0.2.3 tag 7",
        "router ospf",
        "exit",
        "interface lo",
        " description a b c",
        "exit",
        "route-map RM permit 10",
        " set metric 5",
        "exit",
        "bgp as-path access-list AP seq 5 permit ^65001_",
    ]


def test_no_statements():
    doc = {"config": {
        "no": {"ip": {"route": {"0.0.0.0/0": {"192.0.2.254": {"tag": {"5": 200}}}}}},
        "interface": {"eth0": {"no": {"description": "uplink to core"}}},
        "router": {"bgp": {"65001": {
            "no": {"neighbor": {"192.0.2.2": {"timers": "10 30", "remote-as": 2}}},
            "bgp": {"ebgp-requires-policy": True},
        }}},
        "pbr-map": {"P": {"no": {}}},
    }}
    doc["config"]["no"]["log"] = {"syslog": "informational"}
    doc["config"]["no"]["pbr-map"] = {"P": {"seq": 1}}
    rc, conf, err = run("to-conf", "-", stdin=json.dumps(doc))
    assert rc == 1  # "pbr-map P" + {"no": {}} is not a command
    doc["config"].pop("pbr-map")
    rc, conf, err = run("to-conf", "-", stdin=json.dumps(doc))
    assert rc == 0, err
    assert lines(conf) == [
        "no ip route 0.0.0.0/0 192.0.2.254 tag 5 200",
        "no log syslog informational",
        "no pbr-map P seq 1",
        "interface eth0",
        " no description",
        "exit",
        "router bgp 65001",
        " no neighbor 192.0.2.2 timers 10 30",
        # never shortened below the command's keywords ("no neighbor X")
        " no neighbor 192.0.2.2 remote-as 2",
        " bgp ebgp-requires-policy",
        "exit",
    ]


@pytest.mark.parametrize(
    "cfg,where,needle",
    [
        ({"interface": {"eth0": {"ip": {"adress": "1.2.3.4/24"}}}},
         "/config/interface/eth0/ip/adress", "after 'interface eth0'"),
        ({"neighbor": {"192.0.2.1": {"remote-as": 1}}},
         "/config/neighbor/192.0.2.1/remote-as", "valid in: bgp"),
        ({"router": {"ospf": {"exit": True}}},
         "/config/router/ospf/exit", "not with exit"),
        # (a bad gateway would still be a valid interface name)
        ({"ip": {"route": {"10.0.0.0/99": "Null0"}}},
         "/config/ip/route/10.0.0.0~199", "unknown command"),
    ],
)
def test_errors(cfg, where, needle):
    rc, out, err = run("to-conf", "-", stdin=json.dumps({"config": cfg}))
    assert rc == 1
    assert out == ""
    e = json.loads(err)[0]
    assert needle in e["error"], e
    assert e["path"] == where


def test_text_errors_name_the_line():
    rc, out, err = run("to-json", "-", stdin="router ospf\n router-info area 1.1.1.1\n")
    assert rc == 1
    e = json.loads(err)[0]
    assert e["path"] == "line 2" and "unknown command" in e["error"]
    # the words are kept in the output
    assert json.loads(out)["config"]["router"]["ospf"] == {
        "router-info": {"area": "1.1.1.1"}
    }
