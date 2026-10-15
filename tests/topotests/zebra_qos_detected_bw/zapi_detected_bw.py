#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# zapi_detected_bw.py
#
# Copyright (c) 2026 FRRouting
#
"""
Minimal ZAPI client that says hello to zebra as a given routing protocol
(e.g. ospf or nhrp) and reports detected bandwidth
(ZEBRA_DETECTED_BW_UPDATE) as that protocol would, so that tests can
drive zebra's per-daemon detected bandwidth deterministically.

The connection stays open (zebra drops a daemon's values when it goes
away).  Commands are read, one per line, from a FIFO:

    set IFINDEX NEXTHOP OUT_KBPS     report a next hop's outbound bandwidth
    del IFINDEX NEXTHOP              withdraw a next hop
    clear IFINDEX                    withdraw every next hop on IFINDEX
    quit                             close the connection and exit

Message and protocol numbers are taken from the FRR source tree, so the
script follows changes to lib/zclient.h and lib/route_types.txt.
"""

import argparse
import ipaddress
import os
import re
import socket
import struct
import threading

ZEBRA_HEADER_MARKER = 254
ZSERV_VERSION = 6
ZAPI_DETECTED_BW_DELETE = 0x01
ZAPI_DETECTED_BW_CLEAR = 0x02
IPADDR_V4 = socket.AF_INET
IPADDR_V6 = socket.AF_INET6


def zapi_numbers(srcdir):
    "Command numbers and protocol numbers from the source tree"
    with open(os.path.join(srcdir, "lib", "zclient.h"), encoding="utf-8") as f:
        text = f.read()
    body = text[text.index("typedef enum {") : text.index("} zebra_message_types_t;")]
    commands = re.findall(r"^\s*(ZEBRA_[A-Z0-9_]+)\s*,", body, re.M)

    # the type list comes first; the help strings repeat the names later
    routes = []
    with open(os.path.join(srcdir, "lib", "route_types.txt"), encoding="utf-8") as f:
        for line in f:
            if line.startswith("ZEBRA_ROUTE_"):
                name = line.split(",")[0].strip()
                if name in routes:
                    break
                routes.append(name)

    return (
        commands.index("ZEBRA_HELLO"),
        commands.index("ZEBRA_DETECTED_BW_UPDATE"),
        {r[len("ZEBRA_ROUTE_") :].lower(): i for i, r in enumerate(routes)},
    )


def message(command, body):
    length = 10 + len(body)
    return (
        struct.pack("!HBBIH", length, ZEBRA_HEADER_MARKER, ZSERV_VERSION, 0, command)
        + body
    )


def detected_bw(cmd, ifindex, flags, nexthop=None, out_kbps=0):
    body = struct.pack("!IB", ifindex, flags)
    if not flags & ZAPI_DETECTED_BW_CLEAR:
        addr = ipaddress.ip_address(nexthop)
        family = IPADDR_V4 if addr.version == 4 else IPADDR_V6
        body += struct.pack("!H", family) + addr.packed
    # round trip, outbound one-way, inbound one-way
    body += struct.pack("!QQQ", 0, out_kbps, 0)
    return message(cmd, body)


def drain(sock):
    "zebra sends capabilities, interfaces etc.; read and ignore them"
    try:
        while sock.recv(65536):
            pass
    except OSError:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zserv", required=True, help="zebra ZAPI socket")
    ap.add_argument("--srcdir", required=True, help="FRR source tree")
    ap.add_argument("--proto", required=True, help="protocol to say hello as")
    ap.add_argument("--fifo", required=True, help="command FIFO")
    args = ap.parse_args()

    hello, update, protos = zapi_numbers(args.srcdir)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(args.zserv)
    # proto, instance, session id, synchronous
    sock.sendall(message(hello, struct.pack("!BHIB", protos[args.proto], 0, 0, 0)))
    threading.Thread(target=drain, args=(sock,), daemon=True).start()

    if not os.path.exists(args.fifo):
        os.mkfifo(args.fifo)

    while True:
        with open(args.fifo, encoding="utf-8") as fifo:
            for line in fifo:
                words = line.split()
                if not words:
                    continue
                if words[0] == "quit":
                    sock.close()
                    return
                if words[0] == "set":
                    msg = detected_bw(update, int(words[1]), 0, words[2], int(words[3]))
                elif words[0] == "del":
                    msg = detected_bw(
                        update, int(words[1]), ZAPI_DETECTED_BW_DELETE, words[2]
                    )
                elif words[0] == "clear":
                    msg = detected_bw(update, int(words[1]), ZAPI_DETECTED_BW_CLEAR)
                else:
                    continue
                sock.sendall(msg)


if __name__ == "__main__":
    main()
