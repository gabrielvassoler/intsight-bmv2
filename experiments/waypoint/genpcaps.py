#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct
import string
import math
import os

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.utils import wrpcap
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, UDP


def Yred(x):
    return 30

def Yblue(x):
    return 30

def Yteal(x):
    return 30

def Ygreen(x):
    return 30

def Yorange(x):
    return 30


def gen_pkts(src_addr, dst_addr, src_port, dst_port, yfunc, lorem, seconds, msglen, hdslen, add_noise=True):
    random.seed(42)
    x = 0
    i = 0
    pkts = []
    while (x < 15.0):
        # build packet
        beg = random.randint(0, 1e6 - msglen - 1)
        pkt = Ether() / IP(src=src_addr, dst=dst_addr) / \
            UDP(sport=src_port, dport=dst_port) / lorem[beg:beg+msglen]
        pkt.time = x
        pkts.append(pkt)
        # calculate arrival time for next packet
        delay = 1.0/((yfunc(x)*1e6)/(8*(hdslen + msglen)))
        if add_noise is True:
            noise = random.gauss(1, 0.1)
        else:
            noise = 1.0
        x = x + noise*delay
        # count pkts
        i = i + 1
        # if i%1000 == 0:
        #     print(i, end='', flush=True)
        # elif i%100 == 0:
        #     print(end='.', flush=True)
    print('done')
    return pkts

def main():
    print('Building random string')
    letters = string.ascii_letters + string.digits
    lorem = ''.join(random.choice(letters) for i in range(int(1e6)))
    print('done')

    seconds = 15.0
    maxframesize = 1518 - 4  # Frame Check Sequence
    hdslen = 14 + 20 + 8  # Eth + IPv4 + UDP
    tellen = 36  # IntSight
    msglen = maxframesize - hdslen - tellen

    os.makedirs('../../resources/workloads/waypoint')

    print('Generating traffic for RED flow (h1-h11)')
    pkts = gen_pkts('10.0.1.1', '10.0.6.11', 1234, 1234, Yred, lorem, seconds, msglen, hdslen)
    #print('Writting traffic to pcap file', flush=True)
    wrpcap('../../resources/workloads/waypoint/red.pcp', pkts)
    print('done')

    print('Generating traffic for BLACK flow (h12-h2)')
    pkts = gen_pkts('10.0.6.12', '10.0.1.2', 1234, 1234, Yblue, lorem, seconds, msglen, hdslen)
    print('Writting traffic to pcap file')
    wrpcap('../../resources/workloads/waypoint/black.pcp', pkts)
    print('done')

    print('Generating traffic for PURPLE flow (h3-h10)')
    pkts = gen_pkts('10.0.2.3', '10.0.5.10', 1234, 1234, Yteal, lorem, seconds, msglen, hdslen)
    print('Writting traffic to pcap file')
    wrpcap('../../resources/workloads/waypoint/purple.pcp', pkts)
    print('done')

    print('Generating traffic for GREEN flow (h6-h12)')
    pkts = gen_pkts('10.0.3.6', '10.0.6.12', 1235, 1235, Ygreen, lorem, seconds, msglen, hdslen)
    print('Writting traffic to pcap file')
    wrpcap('../../resources/workloads/waypoint/green.pcp', pkts)
    print('done')

    print('Generating traffic for ORANGE flow (h7-h5)')
    pkts = gen_pkts('10.0.4.7', '10.0.3.5', 1234, 1234, Yorange, lorem, seconds, msglen, hdslen)
    print('Writting traffic to pcap file')
    wrpcap('../../resources/workloads/waypoint/orange.pcp', pkts)
    print('done')


if __name__ == '__main__':
    main()
