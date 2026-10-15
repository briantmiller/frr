<p align="center">
<img src="https://docs.frrouting.org/en/latest/_static/frr-icon.svg" alt="Icon" width="20%"/>
</p>

FRRouting
=========

[![github-ci](https://github.com/FRRouting/frr/actions/workflows/github-ci.yml/badge.svg?branch=master)](https://github.com/FRRouting/frr/actions/workflows/github-ci.yml)
[![Documentation Status](https://readthedocs.org/projects/frrouting/badge/?version=latest)](https://docs.frrouting.org/en/latest/)

FRR is free software that implements and manages various IPv4 and IPv6 routing
protocols. It runs on nearly all distributions of Linux and BSD and
supports all modern CPU architectures. The project website is
[frrouting.org](https://frrouting.org/).

FRR currently supports the following protocols:

* BGP
* OSPFv2
* OSPFv3
* RIPv1
* RIPv2
* RIPng
* IS-IS
* PIM (SM, DM, SSM, MSDP)
* LDP
* BFD
* Babel
* PBR
* OpenFabric
* VRRP
* EIGRP (alpha)
* NHRP (alpha)

Not every protocol or feature is available on every platform; see the
[feature matrix](https://docs.frrouting.org/en/latest/about.html#feature-matrix)
in the user guide.

**Centralized FRR configuration (work in progress):** the **mgmtd** daemon
applies **YANG** configuration to the routing protocol daemons through the
**northbound** API (instead of each daemon only having its own legacy
configuration path). **Not all daemons are migrated yet**; expect ongoing
changes. See [mgmtd](https://docs.frrouting.org/en/latest/mgmtd.html) in the
user guide.

Installation & Use
------------------

For source tarballs, see the
[releases page](https://github.com/FRRouting/frr/releases).

Pre-built packages: APT for Debian and derivatives
([deb.frrouting.org](https://deb.frrouting.org/)), and RPM for RHEL, Fedora,
and related distributions ([rpm.frrouting.org](https://rpm.frrouting.org/)).

Instructions on building and installing from source for supported platforms may
be found in the
[developer docs](https://docs.frrouting.org/projects/dev-guide/en/latest/building.html).

Once installed, please refer to the [user guide](https://docs.frrouting.org/)
for instructions on use.

Community
---------

See [lists.frrouting.org](https://lists.frrouting.org/) for the list index,
subscription, and archives. The public lists include:

| Topic             | List                         |
|-------------------|------------------------------|
| Development       | dev@lists.frrouting.org      |
| Users & Operators | frog@lists.frrouting.org     |
| Announcements     | announce@lists.frrouting.org |

For chat, we use [Slack](https://frrouting.slack.com). New members can join
via the invite link on the [community](https://frrouting.org/community/) page.


Contributing
------------

See [submitting patches and enhancements](https://docs.frrouting.org/projects/dev-guide/en/latest/workflow.html#submitting-patches-and-enhancements)
and the [commit guidelines](https://docs.frrouting.org/projects/dev-guide/en/latest/workflow.html#commit-guidelines)
when contributing. FRR maintains
[developer's documentation](https://docs.frrouting.org/projects/dev-guide/en/latest/index.html)
with the full [project workflow](https://docs.frrouting.org/projects/dev-guide/en/latest/workflow.html)
and contributor expectations; technical documentation on internals is also
available.

We welcome and appreciate all contributions, no matter how small!


License
-------

Per-file licenses use SPDX identifiers; see `COPYING` and `doc/licenses/`.
The combined work is generally understood to be distributable under **GNU
General Public License version 2 or later** (GPLv2+); see `COPYING` for
details. FRR's documentation uses a separate custom permissive license (see
`COPYING` for background).


Security
--------

To report security issues, please use our security mailing list:

```
security [at] lists.frrouting.org
```

QoS using Linux HTB or HFSC
--------

This feature allows for configuration of the Linux queueing disciplines such 
as HTB or HFSC.  The following example will configure a parent and child policy-map
and attach it to an interface with a specific bandwidth. 

```
interface eth0
 ip address 10.0.0.1/30
 qos bandwidth 10m
 service-policy output PARENT
exit
access-list VOICE seq 5 deny 10.1.1.0/24
access-list VOICE seq 10 permit 10.0.0.0/8
access-list MGMT seq 5 permit ip 10.0.0.0 0.0.0.255 any
access-list WEB seq 5 permit ip 10.0.1.0 0.0.0.255 any
!
ipv6 access-list VOICE seq 5 permit 2001:db8:99::/48
!
ip access-list extended WEBX
 10 permit tcp 10.0.1.0 0.0.0.255 any
exit
!
class-map match-any VOICE
 match ip dscp ef
exit
!
class-map match-all MGMT
 match access-group name MGMT
 match ip dscp cs6
exit
!
class-map match-all WEB
 match access-group name WEBX
exit
!
class-map match-all BULK
 match ip dscp cs1
exit
!
policy-map CHILD
 class BULK
  bandwidth percent 30
  queue-limit 200 packets
 exit
 class class-default
  bandwidth percent 70
 exit
exit
!
policy-map PARENT
 class VOICE
  bandwidth 5mbps
  max-bandwidth percent 50
  priority 0
  queue-limit 64 packets
 exit
 class MGMT
  bandwidth percent 5
  priority 1
 exit
 class WEB
  bandwidth percent 20
  priority 2
  service-policy CHILD
 exit
 class class-default
  bandwidth percent 10
  max-bandwidth 15mbps
 exit
exit
!
```

Bandwidth detection and QoS
--------

This feature uses packet-pair probes to measure the interface bandwidth to a neighbor, 
specifically an OSPF or NHRp neighbor. Once measured, this value can be used to configure
the HTB or HFSC bandwidth on the interface. The following configuration will send probes
to the remote OSPF neighbor and automatically set the outgoing bandwidth to the probed
value. The probes are sent very 5 seconds with 20 probes each. The bandwidth is calculated
at 95% of the measured value and only increase the bandwidth if the measured amount is 
greater than 10% of the existing value. However, it will lower the bandwidth immediately
if it decreases. If no OSPF neighbor is found or the probes fail, it will default to 5Mbps.

Note that probes are sent using the PACKET_QDISC_BYPASS sockopt. This will ensure the probes
are not affected by the installed queueing discipline.

```
interface eth0
 ip address 10.0.0.2/30
 ip ospf area 0
 ip ospf dead-interval 8
 ip ospf hello-interval 2
 ip ospf packet-pair interval 5 probes 20
 link-type vlan parent wan2 id 100
 qos bandwidth detected ospf percent 95 hysteresis increase 10 default 5mbps
 service-policy output PARENT
exit
!
router ospf
exit
!
access-list VOICE seq 5 deny 10.1.1.0/24
access-list VOICE seq 10 permit 10.0.0.0/8
access-list MGMT seq 5 permit ip 10.0.0.0 0.0.0.255 any
access-list WEB seq 5 permit ip 10.0.2.0 0.0.0.255 any
!
ipv6 access-list VOICE seq 5 permit 2001:db8:99::/48
!
class-map match-any VOICE
 match ip dscp ef
exit
!
class-map match-all MGMT
 match access-group name MGMT
 match ip dscp cs6
exit
!
class-map match-all WEB
 match access-group name WEB
exit
!
class-map match-all BULK
 match ip dscp cs1
exit
!
policy-map CHILD
 class BULK
  bandwidth percent 30
  queue-limit 200 packets
 exit
 class class-default
  bandwidth percent 70
 exit
exit
!
policy-map PARENT
 class VOICE
  bandwidth 5mbps
  max-bandwidth percent 50
  priority 0
  queue-limit 64 packets
 exit
 class MGMT
  bandwidth percent 5
  priority 1
 exit
 class WEB
  bandwidth percent 20
  priority 2
  service-policy CHILD
 exit
 class class-default
  bandwidth percent 10
  max-bandwidth 15mbps
 exit
exit
``` 

