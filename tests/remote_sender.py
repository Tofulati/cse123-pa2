#!/usr/bin/python3

import sys
from scapy.all import Ether, sendp

pkt_bytes = bytes(sys.stdin.buffer.read())
pkt = Ether(pkt_bytes)
sendp(pkt, verbose=False)
sys.stdout.write("sent {} bytes".format(len(pkt_bytes)))
