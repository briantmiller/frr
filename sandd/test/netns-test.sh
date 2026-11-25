#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# SAND v2 functional test in Linux network namespaces.
#
# Builds topologies out of veth pairs and makes chosen directions one-way
# with an nftables drop rule on the sender's egress, then runs zebra and
# sandd in every namespace and checks convergence, reachability, restart,
# graceful leave, emissions control and partition/rejoin.
#
# Usage: sudo ./netns-test.sh [all|ring|restart|leave|silent|partition|mesh]
# Needs: ip, nft, ping, and FRR installed with sandd (default /usr/local).

set -u

SBIN=${SBIN:-/usr/local/sbin}
BIN=${BIN:-/usr/local/bin}
WORK=${WORK:-/tmp/sandtest}
HELLO=${HELLO:-1}
HOLD=${HOLD:-4}
SUMMARY=${SUMMARY:-5}
NODES=()
HAVE6=0
[ -d /proc/sys/net/ipv6 ] && HAVE6=1
PASS=0
FAIL=0

log() { echo "[$(date +%T)] $*"; }
ok() { PASS=$((PASS + 1)); echo "  PASS: $*"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL: $*"; }

vsh() { # node command...
	local n=$1
	shift
	ip netns exec "$n" "$BIN/vtysh" -N "$n" -c "$*" 2>/dev/null
}

cleanup() {
	local n
	for n in $(ip netns list 2>/dev/null | awk '/^sand[0-9]/{print $1}'); do
		ip netns pids "$n" 2>/dev/null | xargs -r kill -9 2>/dev/null
		ip netns del "$n" 2>/dev/null
	done
	rm -rf "$WORK" /var/run/frr/sand[0-9]*
	NODES=()
}

add_node() { # name id
	local n=$1 id=$2
	ip netns add "$n"
	NODES+=("$n")
	ip -n "$n" link set lo up
	ip -n "$n" addr add "10.255.0.$id/32" dev lo
	[ $HAVE6 = 1 ] && ip -n "$n" addr add "2001:db8:ff::$id/128" dev lo
	ip netns exec "$n" sysctl -qw net.ipv4.ip_forward=1
	[ $HAVE6 = 1 ] && ip netns exec "$n" sysctl -qw net.ipv6.conf.all.forwarding=1
	ip netns exec "$n" sysctl -qw net.ipv4.conf.all.rp_filter=0
	ip netns exec "$n" sysctl -qw net.ipv4.conf.default.rp_filter=0
	ip netns exec "$n" nft add table inet sand
	ip netns exec "$n" nft add chain inet sand post \
		'{ type filter hook postrouting priority 0; policy accept; }'
	mkdir -p "$WORK/$n" "/var/run/frr/$n" "/var/lib/frr/$n"
	chown frr:frr "/var/run/frr/$n" "/var/lib/frr/$n" "$WORK/$n"
	chmod 777 "/var/run/frr/$n" "/var/lib/frr/$n" "$WORK/$n"
	cat >"$WORK/$n/zebra.conf" <<EOF
hostname $n
log file $WORK/$n/zebra.log
EOF
	cat >"$WORK/$n/sandd.conf" <<EOF
hostname $n
log file $WORK/$n/sandd.log
!
router sand
 router-id 10.255.0.$id
 network 10.255.0.$id/32
 network 2001:db8:ff::$id/128
 summary-interval $SUMMARY
exit
EOF
}

# link a b subnet-octet [oneway]: veth a<->b, 10.$oct.0.0/30.
# oneway=1 means only a->b works (b's transmissions on it are dropped).
link() {
	local a=$1 b=$2 oct=$3 oneway=${4:-0}
	local ia="${a}-${b}" ib="${b}-${a}"
	ip link add "$ia" netns "$a" type veth peer name "$ib" netns "$b"
	ip -n "$a" addr add "10.$oct.0.1/30" dev "$ia"
	ip -n "$b" addr add "10.$oct.0.2/30" dev "$ib"
	ip -n "$a" link set "$ia" up
	ip -n "$b" link set "$ib" up
	if [ "$oneway" = 1 ]; then
		ip netns exec "$b" nft add rule inet sand post oifname "$ib" drop
	fi
	for x in "$a:$ia" "$b:$ib"; do
		cat >>"$WORK/${x%%:*}/sandd.conf" <<EOF
interface ${x#*:}
 sand
 sand hello-interval $HELLO
 sand hold-time $HOLD
exit
EOF
	done
}

# cut a direction: drop everything n sends on interface
cut() { ip netns exec "$1" nft add rule inet sand post oifname "$2" drop; }
heal() { # remove all drop rules on interface in n
	local h
	for h in $(ip netns exec "$1" nft -a list chain inet sand post |
		awk -v i="\"$2\"" '$0 ~ i {print $NF}'); do
		ip netns exec "$1" nft delete rule inet sand post handle "$h"
	done
}

start_zebra() {
	local n=$1
	ip netns exec "$n" "$SBIN/zebra" -d -N "$n" -u root -g root \
		-f "$WORK/$n/zebra.conf" -i "$WORK/$n/zebra.pid" \
		--log file:"$WORK/$n/zebra.log" >/dev/null 2>&1
}

start_sandd() {
	local n=$1
	ip netns exec "$n" "$SBIN/sandd" -d -N "$n" -u root -g root \
		-f "$WORK/$n/sandd.conf" -i "$WORK/$n/sandd.pid" \
		--log file:"$WORK/$n/sandd.log" >/dev/null 2>&1
}

stop_sandd() { # node [signal]
	local n=$1 sig=${2:-TERM}
	[ -f "$WORK/$n/sandd.pid" ] && kill -"$sig" "$(cat "$WORK/$n/sandd.pid")" 2>/dev/null
	sleep 0.5
}

start_all() {
	local n
	for n in "${NODES[@]}"; do start_zebra "$n"; done
	sleep 1
	for n in "${NODES[@]}"; do start_sandd "$n"; done
}

# reach from to-id: ping loopback of node id, sourced from our loopback
reach4() { ip netns exec "$1" ping -c1 -W1 -I "10.255.0.$3" "10.255.0.$2" >/dev/null 2>&1; }
reach6() { ip netns exec "$1" ping -6 -c1 -W1 -I "2001:db8:ff::$3" "2001:db8:ff::$2" >/dev/null 2>&1; }

# wait until a condition holds, up to N seconds; prints the time taken
wait_for() { # secs cmd...
	local secs=$1 t0 now
	shift
	t0=$(date +%s%N)
	while :; do
		if "$@"; then
			now=$(date +%s%N)
			printf "%d.%d" $(((now - t0) / 1000000000)) $((((now - t0) / 100000000) % 10))
			return 0
		fi
		now=$(date +%s%N)
		if [ $(((now - t0) / 1000000000)) -ge "$secs" ]; then
			return 1
		fi
		sleep 0.25
	done
}

# all-pairs reachability over the node list (ids 1..N), both families
full_mesh_ok() {
	local i j n=${#NODES[@]}
	for ((i = 1; i <= n; i++)); do
		for ((j = 1; j <= n; j++)); do
			[ $i = $j ] && continue
			reach4 "sand$i" "$j" "$i" || return 1
			if [ $HAVE6 = 1 ]; then reach6 "sand$i" "$j" "$i" || return 1; fi
		done
	done
	return 0
}

has_route() { ip -n "$1" route show "$2" proto 199 | grep -q .; }
no_route() { ! has_route "$1" "$2"; }

# ---------------------------------------------------------------------
# Topologies
# ---------------------------------------------------------------------

# The one-way ring: 1 -> 2 -> 3 -> 1. No link works in both directions.
topo_ring() {
	cleanup
	mkdir -p "$WORK"
	add_node sand1 1
	add_node sand2 2
	add_node sand3 3
	link sand1 sand2 12 1
	link sand2 sand3 23 1
	link sand3 sand1 31 1
}

# Five nodes, a mix of one-way and two-way links:
#   1 -> 2, 2 <-> 3, 3 -> 4, 4 -> 5, 5 <-> 1, 4 -> 1
topo_mesh() {
	cleanup
	mkdir -p "$WORK"
	local i
	for i in 1 2 3 4 5; do add_node "sand$i" "$i"; done
	link sand1 sand2 12 1
	link sand2 sand3 23 0
	link sand3 sand4 34 1
	link sand4 sand5 45 1
	link sand5 sand1 51 0
	link sand4 sand1 41 1
}

# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------

test_ring() {
	log "TEST ring: one-way ring 1->2->3->1"
	topo_ring
	start_all
	local t
	if t=$(wait_for 30 full_mesh_ok); then
		ok "all pairs reachable ($([ $HAVE6 = 1 ] && echo IPv4+IPv6 || echo IPv4)) after ${t}s"
	else
		bad "ring did not converge in 30s"
		vsh sand1 "show sand topology"
	fi
	# sand1 -> sand3 must go the long way round: 1 -> 2 -> 3
	if ip -n sand1 route show 10.255.0.3 | grep -q "10.12.0.2"; then
		ok "sand1 reaches sand3 via sand2 (only one-way paths exist)"
	else
		bad "unexpected path from sand1 to sand3"
		ip -n sand1 route show 10.255.0.3
	fi
	if ip -n sand1 neigh show 10.12.0.2 | grep -q PERMANENT; then
		ok "permanent neighbor entry installed for the one-way next hop"
	else
		bad "no permanent neighbor entry on sand1"
	fi
	vsh sand1 "show sand topology"
	vsh sand1 "show sand route"
}

test_restart() {
	log "TEST restart: sand2 killed (no purge) and restarted"
	local before after t i
	# push sand2's sequence numbers up first, so the old state is clearly
	# "newer" than what a freshly booted sand2 would start with
	for i in 1 2 3 4; do
		ip netns exec sand2 "$BIN/vtysh" -N sand2 -c "configure terminal" \
			-c "interface sand2-sand1" -c "sand cost $((10 + i))" >/dev/null 2>&1
		sleep 1.2
	done
	sleep 1
	before=$(vsh sand1 "show sand database" | awk '$1=="10.255.0.2" && $2=="router"{print $4}')
	stop_sandd sand2 KILL
	sleep 1
	start_sandd sand2
	if t=$(wait_for 30 full_mesh_ok); then
		ok "reconverged ${t}s after restart"
	else
		bad "no reconvergence after restart"
	fi
	sleep 2
	after=$(vsh sand1 "show sand database" | awk '$1=="10.255.0.2" && $2=="router"{print $4}')
	if [ -n "$before" ] && [ -n "$after" ] && [ "$before" -gt 2 ] && [ "$after" -gt "$before" ]; then
		ok "sand2's Router record seq jumped past its pre-restart value ($before -> $after)"
	else
		bad "sand2's sequence did not move past the old one ($before -> $after)"
	fi
	# all three must agree on sand2's record
	local s1 s3
	s1=$(vsh sand1 "show sand database" | awk '$1=="10.255.0.2"{print $2,$4,$6}' | sort)
	s3=$(vsh sand3 "show sand database" | awk '$1=="10.255.0.2"{print $2,$4,$6}' | sort)
	if [ "$s1" = "$s3" ]; then
		ok "sand1 and sand3 hold identical copies of sand2's records"
	else
		bad "copies of sand2's records differ"
		echo "$s1"
		echo "$s3"
	fi
}

test_leave() {
	log "TEST leave: graceful stop of sand3 purges its records"
	local t
	stop_sandd sand3 TERM
	if t=$(wait_for 3 no_route sand1 10.255.0.3); then
		ok "sand1 withdrew sand3's prefix ${t}s after graceful stop (hold time ${HOLD}s)"
	else
		bad "sand1 still routes to sand3 after graceful stop"
	fi
	start_sandd sand3
	if t=$(wait_for 30 full_mesh_ok); then
		ok "sand3 rejoined in ${t}s"
	else
		bad "sand3 did not rejoin"
	fi
}

test_crash() {
	log "TEST crash: sand3 killed, liveness rule withdraws it after hold time"
	local t
	stop_sandd sand3 KILL
	if t=$(wait_for $((HOLD * 3 + 5)) no_route sand1 10.255.0.3); then
		ok "sand1 withdrew crashed sand3's prefix after ${t}s"
	else
		bad "sand1 kept routes to crashed sand3"
	fi
	start_sandd sand3
	wait_for 30 full_mesh_ok >/dev/null
}

test_silent() {
	log "TEST silent: sand2 goes silent, others keep routes to it"
	ip netns exec sand2 "$BIN/vtysh" -N sand2 -c "configure terminal" \
		-c "router sand" -c "silent hold 120" >/dev/null 2>&1
	sleep $((HOLD * 2 + 2))
	# EMCON is one-way by nature: check sand1's traffic still arrives at
	# sand2 (sand2 cannot answer; nobody can hear it to confirm a path)
	local rx0 rx1
	rx0=$(ip netns exec sand2 cat /sys/class/net/sand2-sand1/statistics/rx_packets)
	ip netns exec sand1 ping -c3 -i0.2 -W1 -I 10.255.0.1 10.255.0.2 >/dev/null 2>&1
	rx1=$(ip netns exec sand2 cat /sys/class/net/sand2-sand1/statistics/rx_packets)
	if has_route sand1 10.255.0.2 && [ $((rx1 - rx0)) -ge 3 ]; then
		ok "sand1 still routes to silent sand2 after $((HOLD * 2 + 2))s and its packets arrive"
	else
		bad "routes to silent sand2 lost (rx delta $((rx1 - rx0)))"
	fi
	if vsh sand1 "show sand database" | awk '$1=="10.255.0.2"' | grep -q silent; then
		ok "sand2's records carry the Silent flag"
	else
		bad "Silent flag missing"
	fi
	ip netns exec sand2 "$BIN/vtysh" -N sand2 -c "configure terminal" \
		-c "router sand" -c "no silent" >/dev/null 2>&1
	local t
	if t=$(wait_for 30 full_mesh_ok); then
		ok "back to normal ${t}s after leaving silence"
	else
		bad "did not recover after silence"
	fi
}

test_partition() {
	log "TEST partition: 5-node mesh split into {1,5} and {2,3,4}, then healed"
	topo_mesh
	start_all
	local t
	if t=$(wait_for 40 full_mesh_ok); then
		ok "5-node mixed mesh converged in ${t}s"
	else
		bad "mesh did not converge"
		vsh sand1 "show sand topology"
		return
	fi
	# Cut every link between the parts, in both directions
	cut sand1 sand1-sand2
	cut sand2 sand2-sand1
	cut sand4 sand4-sand5
	cut sand5 sand5-sand4
	cut sand4 sand4-sand1
	cut sand1 sand1-sand4
	if t=$(wait_for $((HOLD * 3 + 5)) no_route sand1 10.255.0.3); then
		ok "partition detected by sand1 after ${t}s"
	else
		bad "sand1 still routes across the partition"
	fi
	# Change state on one side while apart: sand3 adds a prefix
	ip -n sand3 addr add 10.99.0.1/32 dev lo
	ip netns exec sand3 "$BIN/vtysh" -N sand3 -c "configure terminal" \
		-c "router sand" -c "network 10.99.0.1/32" >/dev/null 2>&1
	sleep 2
	heal sand1 sand1-sand2
	heal sand2 sand2-sand1
	heal sand4 sand4-sand5
	heal sand5 sand5-sand4
	heal sand4 sand4-sand1
	heal sand1 sand1-sand4
	# put back the original one-way rules (1->2, 4->5, 4->1)
	cut sand2 sand2-sand1
	cut sand5 sand5-sand4
	cut sand1 sand1-sand4
	if t=$(wait_for 40 full_mesh_ok); then
		ok "partition healed, full reachability in ${t}s"
	else
		bad "no full reachability after healing"
	fi
	if t=$(wait_for 20 has_route sand1 10.99.0.1/32); then
		ok "prefix added during the partition reached sand1 ${t}s after healing"
	else
		bad "change made during partition never arrived"
	fi
	local d1 d5
	sleep 3
	d1=$(vsh sand1 "show sand" | awk '/digest/{print $NF}')
	d5=$(vsh sand5 "show sand" | awk '/digest/{print $NF}')
	if [ "$d1" = "$d5" ]; then
		ok "sand1 and sand5 have identical database digests ($d1)"
	else
		bad "database digests differ ($d1 vs $d5)"
	fi
	if vsh sand1 "show sand topology" | grep -q .; then
		vsh sand1 "show sand topology"
	fi
}

test_duprid() {
	log "TEST duplicate router-id: sand3 misconfigured with sand2's id"
	ip netns exec sand3 "$BIN/vtysh" -N sand3 -c "configure terminal" \
		-c "router sand" -c "router-id 10.255.0.2" >/dev/null 2>&1
	local t
	if t=$(wait_for 30 grep -q "appears to be in use" "$WORK/sand2/sandd.log" "$WORK/sand3/sandd.log"); then
		ok "duplicate router-id detected and logged after ${t}s"
	else
		bad "duplicate router-id not detected"
	fi
	ip netns exec sand3 "$BIN/vtysh" -N sand3 -c "configure terminal" \
		-c "router sand" -c "router-id 10.255.0.3" >/dev/null 2>&1
	if t=$(wait_for 90 full_mesh_ok); then
		ok "recovered ${t}s after fixing the router-id"
	else
		bad "no recovery after fixing the router-id"
	fi
}

# N nodes, two interfaces each (a ring), PCT% of links one-way, like the
# SAND v1 whitepaper's large-scale tests.
topo_random() { # n pct seed
	local n=$1 pct=$2 i j ow
	cleanup
	mkdir -p "$WORK"
	RANDOM=$3
	for ((i = 1; i <= n; i++)); do add_node "sand$i" "$i"; done
	for ((i = 1; i <= n; i++)); do
		j=$((i % n + 1))
		ow=0
		[ $((RANDOM % 100)) -lt "$pct" ] && ow=1
		# one-way links all point "clockwise" (i -> i+1), so the ring
		# stays strongly connected; counter-clockwise traffic must go
		# the long way round
		link "sand$i" "sand$j" "$((100 + i))" $ow
	done
}

# Strongly connected? (every node can reach every other over SAND)
test_scale() { # n pct seed
	local n=${1:-20} pct=${2:-20} seed=${3:-7} t bytes=0 pk=0 x
	log "TEST scale: $n nodes, 2 interfaces each, ${pct}% one-way links (seed $seed)"
	topo_random "$n" "$pct" "$seed"
	start_all
	if t=$(wait_for 120 full_mesh_ok); then
		for x in "${NODES[@]}"; do
			bytes=$((bytes + $(vsh "$x" "show sand interface" | awk 'NR>1{s+=$8} END{print s+0}')))
		done
		ok "$n nodes converged in ${t}s; $((bytes / n)) bytes sent per node on average"
		vsh sand1 "show sand" | grep Sent
	else
		bad "$n-node topology did not reach full reachability in 120s"
	fi
}

stats() {
	local n
	echo
	echo "Bytes sent by sandd per node:"
	for n in "${NODES[@]}"; do
		printf "  %s: " "$n"
		vsh "$n" "show sand interface" | awk 'NR>1{p+=$7; b+=$8} END{print p" packets, "b" bytes sent"}'
	done
}

main() {
	local what=${1:-all}
	command -v nft >/dev/null || { echo "nft not found"; exit 2; }
	[ -x "$SBIN/sandd" ] || { echo "sandd not found in $SBIN"; exit 2; }
	[ "${KEEP:-0}" = 1 ] || trap cleanup EXIT
	[ $HAVE6 = 1 ] || echo "NOTE: IPv6 is disabled in this kernel; testing IPv4 only"
	case $what in
	ring) test_ring ;;
	restart) test_ring; test_restart ;;
	leave) test_ring; test_leave; test_crash ;;
	silent) test_ring; test_silent ;;
	partition | mesh) test_partition ;;
	duprid) test_ring; test_duprid ;;
	scale) test_scale "${2:-20}" "${3:-20}" "${4:-7}" ;;
	all)
		test_ring
		test_restart
		test_leave
		test_crash
		test_silent
		test_duprid
		stats
		test_partition
		test_scale 20 20 7
		;;
	*) echo "unknown test $what"; exit 2 ;;
	esac
	echo
	echo "Passed: $PASS  Failed: $FAIL"
	[ "$FAIL" = 0 ]
}

main "$@"
