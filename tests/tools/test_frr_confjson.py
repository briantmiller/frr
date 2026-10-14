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
    assert lines(conf) == lines(CONF)
    # structure and parameter names
    bgp = [s for s in doc["config"] if s.get("cmd") == "router bgp"][0]
    assert bgp["params"] == {"instasn": 65001}
    assert {"cmd": "bgp ebgp-requires-policy", "no": True} in bgp["config"]
    af = [s for s in bgp["config"] if "config" in s][0]
    assert af["config"][0] == {"cmd": "network", "params": {"prefix": "198.51.100.0/24"}}


def test_no_statements():
    doc = {
        "config": [
            {"cmd": "ip route", "no": True,
             "params": {"prefix": "0.0.0.0/0", "gate": "192.0.2.254", "tag": 5, "distance": 200}},
            {"cmd": "interface", "params": {"ifname": "eth0"}, "config": [
                {"cmd": "description", "no": True, "params": {"line": "uplink to core"}}]},
            {"cmd": "router bgp", "params": {"instasn": 65001}, "config": [
                {"cmd": "neighbor timers", "no": True,
                 "params": {"neighbor": "192.0.2.2", "timers": 10, "holdtime": 30}},
                {"cmd": "bgp ebgp-requires-policy"},
                {"cmd": "neighbor 192.0.2.2 timers 10 30", "no": True}]},
            {"cmd": "log syslog", "no": True, "params": {"levelarg": "informational"}},
            {"cmd": "pbr-map seq", "no": True, "params": {"pbrmap": "P", "seq": 1}},
            "no ip prefix-list OWN seq 5 permit 198.51.100.0/24",
        ]
    }
    rc, conf, err = run("to-conf", "-", stdin=json.dumps(doc))
    assert rc == 0, err
    assert lines(conf) == [
        "no ip route 0.0.0.0/0 192.0.2.254 tag 5 200",
        "interface eth0",
        " no description",
        "exit",
        "router bgp 65001",
        " no neighbor 192.0.2.2 timers 10 30",
        " bgp ebgp-requires-policy",
        " no neighbor 192.0.2.2 timers 10 30",
        "exit",
        "no log syslog informational",
        "no pbr-map P seq 1",
        "no ip prefix-list OWN seq 5 permit 198.51.100.0/24",
    ]


def test_no_never_widens():
    # "no neighbor X remote-as ..." must not turn into "no neighbor X"
    doc = [{"cmd": "router bgp", "params": {"instasn": 1}, "config": [
        {"cmd": "neighbor remote-as", "no": True,
         "params": {"neighbor": "192.0.2.2", "remote_as": 2}}]}]
    rc, conf, err = run("to-conf", "-", stdin=json.dumps(doc))
    assert rc == 0, err
    assert " no neighbor 192.0.2.2 remote-as 2" in conf.splitlines()


@pytest.mark.parametrize(
    "doc,needle",
    [
        ([{"cmd": "router bgp", "params": {"instasn": "x"}}], "not accepted by 'router bgp"),
        ([{"cmd": "router bgp", "params": {"asn": 1}}], "unknown parameter 'asn'"),
        (["neighbor 192.0.2.1 remote-as 1"], "unknown command in config"),
        ([{"cmd": "hostname", "params": {"hostname": "x"}, "config": ["x"]}],
         "does not enter a sub-mode"),
        ([{"cmd": "router ospf", "config": ["exit"]}], "leaves the current mode"),
        ([{"cmd": "frr version", "no": True, "params": {"version": "1"}}], 'has no "no" form'),
    ],
)
def test_errors(doc, needle):
    rc, out, err = run("to-conf", "-", stdin=json.dumps(doc))
    assert rc == 1
    assert out == ""
    e = json.loads(err)[0]
    assert needle in e["error"], e
    assert e["path"].startswith("/config/0")


def test_text_errors_name_the_line():
    rc, out, err = run("to-json", "-", stdin="router ospf\n router-info area 1.1.1.1\n")
    assert rc == 1
    e = json.loads(err)[0]
    assert e["path"] == "line 2" and "unknown command" in e["error"]
    # the line is kept, as a string, in the output
    assert json.loads(out)["config"][0]["config"] == ["router-info area 1.1.1.1"]
