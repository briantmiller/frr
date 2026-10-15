#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""
Forge packet-pair messages for tests.

  forge_probes.py probe IFNAME SRC DST [VERSION]
      Send two well-formed probe pairs from SRC to DST, then print how many
      plain echo replies (from DST's kernel: the probes arrived) and how
      many one-way reports (from a packet-pair session on DST) came back.

  forge_probes.py report IFNAME SRC DST [VERSION]
      Wait for a probe from DST to SRC (this host), then send DST a report
      for that sample from SRC.  Prints the sample it answered.
"""

import struct
import sys
import threading
import time

from scapy.all import ICMP, IP, Raw, conf, send, sniff

conf.verb = 0
MAGIC, REPORT = 0x4F505052, 0x4F505054


def addr(a):
    return bytes(int(o) for o in a.split("."))


def probe_payload(version, dst, sample, pair, which, npairs=2, size=200):
    now = time.time()
    # magic, version, flags, interval, sample, dst, pair, which, npairs,
    # rsvd, tx_sec, tx_nsec
    hdr = struct.pack(
        "!IBBHI4sBBBBII",
        MAGIC,
        version,
        0,
        2,
        sample,
        addr(dst),
        pair,
        which,
        npairs,
        0,
        int(now),
        int((now % 1) * 1e9),
    )
    return hdr + b"\0" * (size - 28 - len(hdr))


def report_payload(version, src, sample):
    # magic, version, rsvd, pkt_size, sample, dst, npairs, seen, valid,
    # rcvd, bw_kbps, ipd_usec, jitter_usec
    return struct.pack(
        "!IBBHI4sBBBBIII",
        REPORT,
        version,
        0,
        1500,
        sample,
        addr(src),
        8,
        8,
        8,
        16,
        123,
        97561,
        1,
    )


def do_probe(ifname, src, dst, version):
    probes = [
        IP(src=src, dst=dst)
        / ICMP(type=8, id=0x4242, seq=i)
        / Raw(probe_payload(version, dst, 77, i // 2, i % 2))
        for i in range(4)
    ]
    captured = []

    def _sniff():
        captured.extend(
            sniff(
                iface=ifname,
                timeout=4,
                lfilter=lambda p: p.haslayer(ICMP) and p[ICMP].type == 0,
            )
        )

    t = threading.Thread(target=_sniff)
    t.start()
    time.sleep(0.5)
    send(probes)
    t.join()
    magics = [bytes(p[ICMP].payload)[:4] for p in captured]
    print("REPLIES {}".format(magics.count(struct.pack("!I", MAGIC))))
    print("REPORTS {}".format(magics.count(struct.pack("!I", REPORT))))


def do_report(ifname, src, dst, version):
    pkts = sniff(
        iface=ifname,
        timeout=10,
        count=1,
        lfilter=lambda p: p.haslayer(ICMP)
        and p[ICMP].type == 8
        and p[IP].src == dst
        and bytes(p[ICMP].payload)[:4] == struct.pack("!I", MAGIC),
    )
    if not pkts:
        print("NOPROBE")
        return
    icmp = pkts[0][ICMP]
    sample = struct.unpack("!I", bytes(icmp.payload)[8:12])[0]
    send(
        IP(src=src, dst=dst)
        / ICMP(type=0, id=icmp.id, seq=0)
        / Raw(report_payload(version, src, sample))
    )
    print("REPORTED id {} sample {}".format(icmp.id, sample))


if __name__ == "__main__":
    mode, ifname, src, dst = sys.argv[1:5]
    version = int(sys.argv[5]) if len(sys.argv) > 5 else 1
    {"probe": do_probe, "report": do_report}[mode](ifname, src, dst, version)
