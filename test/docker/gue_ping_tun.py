#!/usr/bin/python

import sys
import time
import codecs

from scapy.all import *


conf.verb = 0

GUE_PORT = 6080

#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#| 0 |C|   Hlen  |  Proto/ctype  |G| SEC |F|T|R|K|N|A|   Rsvd    |
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#|    *  |      *|       |      *|*   *  |       |       |       |
#|   2   |   1   |   0   |   1   |   a   |   0   |   0   |   0   |
class GUE(Packet):
    name = "GUE "
    fields_desc=[BitField("version", 0, 2),
                   BitField("control", 0, 1),
                   BitField("Hlen", 0, 5),
                   BitField("Proto_ctype", 0, 8),
                   BitField("G", 0, 1),
                   BitField("SEC", 0, 3),
                   BitField("F", 0, 1),
                   BitField("T", 0, 1),
                   BitField("R", 0, 1),
                   BitField("K", 0, 1),
                   BitField("N", 0, 1),
                   BitField("A", 0, 1),
                   BitField("Rsvd", 0, 6),
                   IntField("tun_id", 0)]
# don't know how to specify 128b field, therefore security key has to be specified separately
# GUE header size is hardcoded

# Create GUE control packet                 
def create_packet(iface, dst_ip, src_port, dst_port, tun_id):
    pkt  = Ether(src=get_if_hwaddr(iface), dst=getmacbyip(dst_ip))
    pkt /= IP(src=get_if_addr(iface), dst=dst_ip)
    pkt /= UDP(sport=src_port, dport=dst_port)
    pkt /= GUE(control=1, Hlen=1, Proto_ctype=1, tun_id=tun_id)
    return bytes(pkt)

# Check interface name
def get_if(if_name):
    iface=None
    for i in get_if_list():
        if if_name in i:
            iface=i
            break;
    if not iface:
        print("Cannot find %s interface" % (if_name))
        exit(1)
    print("Interface %s found" % (iface))
    return iface

def main(argv):
    print(argv)

    if (len(argv) < 7):
        print("Usage: %s <interface> <delay> <remote-ip> <remote-port> <local-port> <tunnel-id>" % argv[0])
        print("    <interface>                  - outgoing interface")
        print("    <delay>                      - delay between packets in seconds")
        print("    <remote-ip>:<remote-port>    - Tunnel remote endpoint")
        print("    <local-port>                 - Tunnel local endpoint")
        print("    <tunnel-id>                  - tunnel identifier")
        print("\nExample : %s ens33 10 5.5.5.5 6080 6080 1" % argv[0])
        return 1

    delay = int(argv[2])
    tun_id = int(argv[6])

    packet = create_packet(argv[1], argv[3], int(argv[4]), int(argv[5]), tun_id)
    try:
        print("Starting infinite loop to send GUE Control packet for tunnel-id %d to %s:%s every %s second(s)" % (tun_id, argv[3], argv[4], delay))
        while (1):
            print(".")
#            print(time.ctime())
            sendp(packet, iface=argv[1])
            time.sleep(delay)
    except KeyboardInterrupt:
        print("Interrupted by user")
#        raise 

if __name__ == '__main__':
    main(sys.argv)
