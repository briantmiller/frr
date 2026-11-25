# sandd: SAND v2 for FRR

SAND (Stateful Asymmetric Network Discovery) is a link-state routing protocol
for networks whose links may work in only one direction. Each router reports
the links it *hears*, every record has exactly one writer, and routes are
computed on the directed graph, so traffic can follow paths made entirely of
one-way links. The protocol is specified in the SAND v2 design document.

## Quick start

```
router sand
 router-id 10.255.0.1
 network 10.255.0.1/32
 network 2001:db8:ff::1/128
exit
!
interface eth1
 sand
exit
interface eth2
 sand
 sand cost 50
exit
```

Enable it in `/etc/frr/daemons` with `sandd=yes`. sandd needs zebra.

## Commands

| Command | Where | Meaning |
| --- | --- | --- |
| `router sand` | config | Start SAND |
| `router-id A.B.C.D` | router | Router ID (default: zebra's) |
| `network PREFIX [metric N]` | router | Advertise an IPv4 or IPv6 prefix |
| `redistribute <ipv4\|ipv6> <connected\|static\|kernel>` | router | Advertise routes from another source |
| `lifetime (300-65535)` | router | Record lifetime in seconds (default 3600) |
| `summary-interval (5-6553)` | router | Seconds between Summaries (default 60) |
| `silent [hold (60-65535)]` | router | Emissions control: stop transmitting; others keep routes to us for `hold` seconds |
| `sand` | interface | Run SAND here (interface needs an IPv4 address) |
| `sand cost (1-65535)` | interface | Cost of links heard on this interface (default 10) |
| `sand hello-interval (1-6553)` | interface | Default 10 s |
| `sand hold-time (3-6553)` | interface | Default 40 s |
| `show sand [interface\|neighbor\|database [detail]\|topology\|route] [json]` | view | State |
| `debug sand <packet\|flood\|spf\|zebra\|events\|all>` | enable/config | Debugging |

## Notes

- Transport is UDP port 1000 to 224.0.0.69 with TTL 1, so every SAND
  interface needs an IPv4 address. IPv4 and IPv6 prefixes are both routed.
- Next hops over one-way links never answer ARP or ND, so sandd installs
  permanent neighbor entries from the Interface records it learns and marks
  next hops `onlink`. Routes appear in the kernel as `proto 199`.
- Host routes to every remote SAND interface's IPv4 address are installed
  so that replies take the return path instead of the connected route.
- No authentication yet. Run only where every transmitter is trusted.

## Testing

Topotests (run as root from `tests/topotests`):

```
python3 -m pytest -v sand_unidir_ring sand_mixed_mesh
```

- `sand_unidir_ring`: a ring of three one-way links. Convergence, routes
  and permanent neighbor entries, restart without cleanup, graceful leave,
  crash, emissions control and duplicate router IDs.
- `sand_mixed_mesh`: five routers, one-way and two-way links. ECMP over
  one-way paths, failover, and partition and heal.

One-way links are made with iptables drop rules on the receiver's egress
(`lib/sand.py`). The `show sand` commands all take `json`.

A standalone script with the same checks plus a 20-node scale test,
for machines without the topotest framework:

`test/netns-test.sh` builds topologies in network namespaces, makes chosen
directions one-way with nftables, and checks convergence, restart, graceful
and ungraceful leave, emissions control, duplicate router IDs, partition and
rejoin, and a 20-node ring with 20% one-way links:

```
sudo sandd/test/netns-test.sh all
```
