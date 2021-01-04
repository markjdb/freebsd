#!/usr/bin/env python
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2020 Klara, Inc.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

import argparse
import scapy.all as sp

def main():
    parser = argparse.ArgumentParser("nd6.py",
        description="Send Neighbour Discovery packets")
    parser.add_argument('--sendif', nargs=1, required=True,
        help="The interface through which to send the packet")
    parser.add_argument('--src', nargs=1, required=True,
        help="The source IP address")
    parser.add_argument('--dst', nargs=1, required=True,
        help="The destination IP address")
    parser.add_argument('--prefix', nargs=1,
        help="The prefix to advertise, if sending an RA, e.g. 2001:db8:42::/64")
    args = parser.parse_args()

    prefix = args.prefix[0].split("/")
    prefixlen = int(prefix[1]) if len(prefix) == 2 else 64

    pkt = sp.Ether() / \
        sp.IPv6(src=args.src[0], dst=args.dst[0], hlim=255) / \
        sp.ICMPv6ND_RA() / \
        sp.ICMPv6NDOptPrefixInfo(prefix=prefix[0], prefixlen=prefixlen)

    sp.sendp(pkt, iface=args.sendif[0], verbose=False)

if __name__ == '__main__':
    main()
