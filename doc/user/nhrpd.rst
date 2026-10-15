.. _nhrp:

****
NHRP
****

*nhrpd* is an implementation of the :abbr:`NHRP (Next Hop Routing Protocol)`.
NHRP is described in :rfc:`2332`.

NHRP is used to improve the efficiency of routing computer network traffic over
:abbr:`NBMA (Non-Broadcast, Multiple Access)` networks. NHRP provides an
ARP-like solution that allows a system to dynamically learn the NBMA address of
the other systems that are part of that network, allowing these systems to
directly communicate without requiring traffic to use an intermediate hop.

NHRP is a client-server protocol. The server side is called the :abbr:`NHS
(Next Hop Server)` or the hub, while a client is referred to as the :abbr:`NHC
(Next Hop Client)` or the spoke. When a node is configured as an NHC, it
registers its address with the NHS which keeps track of all registered spokes.
An NHC client can then query the addresses of other clients from NHS allowing
all spokes to communicate directly with each other.

Cisco Dynamic Multipoint VPN (DMVPN) is based on NHRP, and |PACKAGE_NAME| nhrpd
implements this scenario.

.. _routing-design:

Routing Design
==============

nhrpd never handles routing of prefixes itself. You need to run some
real routing protocol (e.g. BGP) to advertise routes over the tunnels.
What nhrpd does it establishes 'shortcut routes' that optimizes the
routing protocol to avoid going through extra nodes in NBMA GRE mesh.

nhrpd does route NHRP domain addresses individually using per-host prefixes.
This is similar to Cisco FlexVPN; but in contrast to opennhrp which uses
a generic subnet route.

To create NBMA GRE tunnel you might use the following (Linux terminal
commands):

.. code-block:: console

   ip tunnel add gre1 mode gre key 42 ttl 64
   ip addr add 10.255.255.2/32 dev gre1
   ip link set gre1 up


Note that the IP-address is assigned as host prefix to gre1. nhrpd will
automatically create additional host routes pointing to gre1 when
a connection with these hosts is established.

The gre1 subnet prefix should be announced by routing protocol from the
hub nodes (e.g. BGP 'network' announce). This allows the routing protocol
to decide which is the closest hub and determine the relay hub on prefix
basis when direct tunnel is not established.

nhrpd will redistribute directly connected neighbors to zebra. Within
hub nodes, these routes should be internally redistributed using some
routing protocol (e.g. iBGP) to allow hubs to be able to relay all traffic.

This can be achieved in hubs with the following bgp configuration (network
command defines the GRE subnet):

.. code-block:: frr

  router bgp 65555
   address-family ipv4 unicast
     network 172.16.0.0/16
     redistribute nhrp
   exit-address-family


.. _configuring-nhrp:

Configuring NHRP
================

.. clicmd:: ip nhrp holdtime (1-65000)

   Holdtime is the number of seconds that have to pass before stopping to
   advertise an NHRP NBMA address as valid. It also controls how often NHRP
   registration requests are sent. By default registrations are sent every one
   third of the holdtime.

.. clicmd:: ip nhrp authentication PASSWORD

   Enables Cisco style authentication on NHRP packets. This embeds the
   plaintext password to the outgoing NHRP packets.
   Maximum length of the password is 8 characters.

.. clicmd:: ip nhrp map A.B.C.D|X:X::X:X A.B.C.D|local

   Map an IP address of a station to the station's NBMA address.

.. clicmd:: ip nhrp network-id (1-4294967295)

   Enable NHRP on this interface and set the interface's network ID.  The
   network ID is used to allow creating multiple nhrp domains on a router when
   multiple interfaces are configured on the router.  Interfaces configured
   with the same ID are part of the same logical NBMA network. The ID is a
   local only parameter and is not sent to other NHRP nodes and so IDs on
   different nodes do not need to match. When NHRP packets are received on an
   interface they are assigned to the local NHRP domain for that interface.

.. clicmd:: ip nhrp nhs A.B.C.D nbma A.B.C.D|FQDN [priority (0-255)]

   Configure the Next Hop Server address and its NBMA address. The optional
   priority controls the order in which spokes select hubs. The lower values
   are attempted first, moving to higher numbered servers when lower numbered
   ones are not reachable. When unreachable, lower value servers are rechecked
   at the interval of holdtime / 4.

.. clicmd:: ip nhrp nhs dynamic nbma A.B.C.D [priority (0-255)]

   Configure the Next Hop Server to have a dynamic address and set its NBMA
   address.

.. clicmd:: ip nhrp registration no-unique

   Allow the client to not set the unique flag in the NHRP packets. This is
   useful when a station has a dynamic IP address that could change over time.

.. clicmd:: ip nhrp shortcut

   Enable shortcut (spoke-to-spoke) tunnels to allow NHC to talk to each others
   directly after establishing a connection without going through the hub.

.. clicmd:: ip nhrp mtu

   Configure NHRP advertised MTU.

.. clicmd:: ip nhrp packet-pair [{interval (1-3600)|probes (2-64)|dscp (0-63)}]

   Periodically estimate the speed of the path to each NHRP peer on this
   tunnel using packet pairs, and measure its round trip time and jitter.
   A client (spoke) probes every NHS it is registered with; an NHS (hub)
   probes every client registered with it. Spoke-to-spoke shortcut peers
   are not probed.

   Every ``interval`` seconds (default 60) ``probes`` pairs (default 10)
   of back-to-back ICMP echo requests, the size of the tunnel MTU, are
   sent through the tunnel to each peer's protocol address. The inner
   probe is marked with the given ``dscp`` value (default 0); the outer
   header's DSCP follows the tunnel's ``tos`` setting, as for any other
   tunnel traffic. Peers only need to answer ICMP echo requests. The
   estimated speed is the probe size divided by the gap between the two
   replies of a pair, reported as the median over a sample and smoothed
   across samples (see ``ip nhrp packet-pair smoothing``). Options
   omitted from the command revert to their
   defaults. IPv4 only.

   Probes are sent with ``PACKET_QDISC_BYPASS``, so local egress QoS does
   not affect the estimate, which can then be used to size such a policy:

   - Normally nhrpd builds the complete frame (outer IPv4, GRE header with
     the tunnel's key, and the probe) and writes it directly to the
     underlay Ethernet interface, bypassing both the tunnel's and the
     underlay interface's qdisc.
   - When that is not possible the probe is written to the GRE interface
     instead, like NHRP packets themselves: the tunnel's qdisc is bypassed
     but the underlay's applies. This happens when the tunnel is protected
     by IPsec (``tunnel protection``, or any IPsec SA to the peer), since a
     frame written to the underlay would skip encryption; when the tunnel
     uses GRE checksums, sequence numbers or FOU/GUE encapsulation; when
     the underlay interface is not Ethernet; when the underlay next hop's
     MAC address is not resolved; or when the probe would exceed the
     underlay MTU.

   When the peer also runs packet-pair, probing or as a responder, each
   direction is measured separately: the peer times the arrival of this
   router's probe pairs inside the tunnel and reports the one-way speed
   and jitter back (an ICMP echo reply carrying this router's probe
   identifier). ``show ip nhrp packet-pair`` then shows an *outbound*
   speed (reported by the peer) and an *inbound* speed (measured locally
   from the peer's probes), which differ on asymmetric links such as
   DSL or cable access. Only probes from NHSes and registered clients
   are measured. The results are also reported to zebra, per peer, as
   detected bandwidth towards that next hop on the tunnel (see
   ``detected-bandwidth aggregate`` and ``show zebra detected-bandwidth``).
   Probes and reports carry a payload format version
   (currently 1); messages of another version are ignored and counted in
   ``show ip nhrp packet-pair`` (``versionMismatches`` in JSON), so
   one-way results need both ends to use the same version.

   Frames written to the underlay skip netfilter output hooks, and
   bypassed probes are not seen by packet captures on the sending
   interfaces. QoS elsewhere on the path, including the peer's egress
   for the replies, still affects the measurement. On a hub with many
   clients, pairs are spaced more closely so a sample still fits in the
   interval.


.. clicmd:: ip nhrp packet-pair smoothing {weight (1-100)|step-threshold (0-1000)|step-samples (1-16)}

   Smooth the per-sample speed estimates (outbound, inbound and round
   trip) across samples. The smoothed value is what is shown as
   "smoothed" and what is reported to zebra.

   Each new sample enters a moving average with ``weight`` percent
   (default 25; 100 uses the latest sample only). The average is taken
   over the time per bit rather than over the speed, i.e. it is a weighted
   harmonic mean, so a single sample that came out too fast (for example
   because receive interrupt coalescing squeezed a pair together) moves it
   much less than averaging speeds would.

   A real change in link speed would only fade in slowly, so when
   ``step-samples`` consecutive samples (default 2) all deviate from the
   smoothed value by more than ``step-threshold`` percent (default 30) in
   the same direction, it is reset to their mean. With the default
   settings a speed change is followed within about two samples; with
   ``step-threshold 0`` resets are disabled and a fourfold increase is
   only about half way there after four samples. Resets are counted in
   ``smoothingResets`` in the JSON output. Options omitted from the
   command revert to their defaults.

.. clicmd:: ip nhrp packet-pair responder

   Measure the packet-pair probes of NHSes and registered clients on this
   tunnel and report the one-way results back to them, without sending
   probes. For example, spokes configured as responders let the hub learn
   its outbound speed to each spoke.

.. _hub-functionality:

Hub Functionality
=================

In addition to routing nhrp redistributed host prefixes, the hub nodes
are also responsible to send NHRP Traffic Indication messages that
trigger creation of the shortcut tunnels.

nhrpd sends Traffic Indication messages based on network traffic captured
using NFLOG. Typically you want to send Traffic Indications for network
traffic that is routed from gre1 back to gre1 in rate limited manner.
This can be achieved with the following iptables rule.

.. code-block:: shell

   iptables -A FORWARD -i gre1 -o gre1 \\
       -m hashlimit --hashlimit-upto 4/minute --hashlimit-burst 1 \\
       --hashlimit-mode srcip,dstip --hashlimit-srcmask 24 --hashlimit-dstmask 24 \\
       --hashlimit-name loglimit-0 -j NFLOG --nflog-group 1 --nflog-range 128


You can fine tune the src/dstmask according to the prefix lengths you announce
internal, add additional IP range matches, or rate limitation if needed.
However, the above should be good in most cases.

This kernel NFLOG target's nflog-group is configured in global nhrp config
with:

.. clicmd:: nhrp nflog-group (1-65535)

To start sending these traffic notices out from hubs, use the nhrp
per-interface directive:

.. clicmd:: ip nhrp redirect

This enable redirect replies on the NHS similar to ICMP redirects except this
is managed by the nhrp protocol. This setting allows spokes to communicate with
each others directly.

.. _integration-with-ike:

Integration with IKE
====================

nhrpd needs tight integration with IKE daemon for various reasons.
Currently only strongSwan is supported as IKE daemon.

nhrpd connects to strongSwan using VICI protocol based on UNIX socket which
can be configured using the command below (default to /var/run/charon.vici).

strongSwan currently needs few patches applied. Please check out the
original patches at:
https://git-old.alpinelinux.org/user/tteras/strongswan/

Actively maintained patches are also available at:
https://gitlab.alpinelinux.org/alpine/aports/-/tree/master/main/strongswan

.. _multicast-functionality:

Multicast Functionality
=======================

nhrpd can be configured to forward multicast packets, allowing routing
protocols that use multicast (such as OSPF) to be supported in the DMVPN
network.

This support requires an iptables NFLOG rule to allow nhrpd to intercept
multicast packets. A second iptables rule is also usually used to drop the
original multicast packet.

 .. code-block:: shell

   iptables -A OUTPUT -d 224.0.0.0/24 -o gre1 -j NFLOG --nflog-group 2
   iptables -A OUTPUT -d 224.0.0.0/24 -o gre1 -j DROP

.. clicmd:: nhrp multicast-nflog-group (1-65535)

   Sets the nflog group that nhrpd will listen on for multicast packets. This
   value must match the nflog-group value set in the iptables rule.

.. clicmd:: ip nhrp map multicast A.B.C.D|X:X::X:X A.B.C.D|dynamic|nhs

   Sends multicast packets to the specified NBMA address. If dynamic is
   specified then destination NBMA address (or addresses) are learnt
   dynamically. If nhs is specified, then active NHS address(es) are used
   if they are reachable.

.. _nhrp-events:

NHRP Events
===========

.. clicmd:: nhrp event socket SOCKET

   Configure the Unix path for the event socket.

.. _show-nhrp:

Show  NHRP
==========

.. clicmd:: show [ip|ipv6] nhrp cache [json]

   Dump the cache entries.

.. clicmd:: show [ip|ipv6] nhrp opennhrp [json]

   Dump the cache entries with opennhrp format.

.. clicmd:: show [ip|ipv6] nhrp nhs [json]

   Dump the hub context.

.. clicmd:: show ip nhrp packet-pair [json]

   Show packet-pair probing per tunnel interface and, for each NHS or
   registered client, the latest RTT, jitter, inter-packet delay and
   estimated speed, and how probes were sent (``txPath`` in JSON:
   ``underlay-bypass``, ``tunnel-bypass`` or ``ip-stack``, with the reason
   in ``txQdiscBypassReason`` when bypass was partial). One-way results
   appear as ``outbound`` and ``inbound`` objects in JSON.

.. clicmd:: show dmvpn [json]

   Dump the security contexts.

Configuration Example
=====================

.. figure:: ../figures/fig_dmvpn_topologies.png
   :alt: image

   image

IPSec configuration example
----------------------------

This changes required on all nodes as HUB and Spokes.

ipsec.conf file

.. code-block:: shell

  config setup
  conn dmvpn
      authby=secret
      auto=add
      keyexchange=ikev2
      ike=aes256-aes256-sha256-modp2048
      esp=aes256-aes256-sha256-modp2048
      dpdaction=clear
      dpddelay=300s
      left=%any
      leftid=%any
      right=%any
      rightid=%any
      leftprotoport=gre
      rightprotoport=gre
      type=transport
      keyingtries=%forever

ipsec.secrets file

.. code-block:: shell

  %any : PSK "some_s3cret!"


HUB configuration example
-------------------------

Creating gre interface

.. code-block:: console

   ip tunnel add gre1 mode gre key 42 ttl 64
   ip addr add 10.0.0.254/32 dev gre1
   ip link set gre1 up

Adding iptables rules to provide possibility shortcut tunnels and connect spokes directly

.. code-block:: shell

   iptables -A FORWARD -i gre1 -o gre1 \\
       -m hashlimit --hashlimit-upto 4/minute --hashlimit-burst 1 \\
       --hashlimit-mode srcip,dstip --hashlimit-srcmask 24 --hashlimit-dstmask 24 \\
       --hashlimit-name loglimit-0 -j NFLOG --nflog-group 1 --nflog-range 128

FRR config on HUB

.. code-block:: frr

  nhrp nflog-group 1
  !
  interface gre1
   description DMVPN Tunnel Interface
   ip address 10.0.0.254/32
   ip nhrp network-id 1
   ip nhrp redirect
   ip nhrp registration no-unique
   ip nhrp shortcut
   tunnel protection vici profile dmvpn
   tunnel source eth0
   !
   router bgp 65000
    bgp router-id 10.0.0.254
    no bgp ebgp-requires-policy
    neighbor SPOKES peer-group
    neighbor SPOKES disable-connected-check
    neighbor 10.0.0.1 remote-as 65001
    neighbor 10.0.0.1 peer-group SPOKES
    neighbor 10.0.0.2 remote-as 65002
    neighbor 10.0.0.2 peer-group SPOKES
    neighbor 10.0.0.3 remote-as 65003
    neighbor 10.0.0.3 peer-group SPOKES
    !
    address-family ipv4 unicast
     network 172.16.0.0/24
     redistribute nhrp
    exit-address-family

Spoke1 configuration
--------------------

Creating gre interface

.. code-block:: console

   ip tunnel add gre1 mode gre key 42 ttl 64
   ip addr add 10.0.0.1/32 dev gre1
   ip link set gre1 up


FRR config on Spoke1

.. code-block:: frr

  interface gre1
   description DMVPN Tunnel Interface
   ip address 10.0.0.1/32
   ip nhrp network-id 1
   ip nhrp nhs dynamic nbma 198.51.100.1
   ip nhrp redirect
   ip nhrp registration no-unique
   ip nhrp shortcut
   no link-detect
   tunnel protection vici profile dmvpn
   tunnel source eth0
  !
  router bgp 65001
   no bgp ebgp-requires-policy
   neighbor 10.0.0.254 remote-as 65000
   neighbor 10.0.0.254 disable-connected-check
   !
   address-family ipv4 unicast
    network 172.16.1.0/24
   exit-address-family


Spoke2 configuration
--------------------

Creating gre interface

.. code-block:: console

   ip tunnel add gre1 mode gre key 42 ttl 64
   ip addr add 10.0.0.2/32 dev gre1
   ip link set gre1 up

FRR config on Spoke2

.. code-block:: frr

  interface gre1
   description DMVPN Tunnel Interface
   ip address 10.0.0.2/32
   ip nhrp network-id 1
   ip nhrp nhs dynamic nbma 198.51.100.1
   ip nhrp redirect
   ip nhrp registration no-unique
   ip nhrp shortcut
   no link-detect
   tunnel protection vici profile dmvpn
   tunnel source eth0
  !
  router bgp 65002
   no bgp ebgp-requires-policy
   neighbor 10.0.0.254 remote-as 65000
   neighbor 10.0.0.254 disable-connected-check
   !
   address-family ipv4 unicast
    network 172.16.2.0/24
   exit-address-family


Spoke3 configuration
--------------------

Creating gre interface

.. code-block:: console

   ip tunnel add gre1 mode gre key 42 ttl 64
   ip addr add 10.0.0.3/32 dev gre1
   ip link set gre1 up

FRR config on Spoke3

.. code-block:: frr

  interface gre1
   description DMVPN Tunnel Interface
   ip address 10.0.0.3/32
   ip nhrp network-id 1
   ip nhrp nhs dynamic nbma 198.51.100.1
   ip nhrp redirect
   ip nhrp registration no-unique
   ip nhrp shortcut
   no link-detect
   tunnel protection vici profile dmvpn
   tunnel source eth0
  !
  router bgp 65003
   no bgp ebgp-requires-policy
   neighbor 10.0.0.254 remote-as 65000
   neighbor 10.0.0.254 disable-connected-check
   !
   address-family ipv4 unicast
    network 172.16.3.0/24
   exit-address-family

