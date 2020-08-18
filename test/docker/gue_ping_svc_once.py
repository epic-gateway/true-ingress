#!/usr/bin/python

import sys
import time
import codecs

from scapy.all import *


conf.verb = 0

GUE_PORT = 6080

xsecurity_key = '01010101010101010101010101010101'

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
                   BitField("G", 1, 1),
                   BitField("SEC", 2, 3),
                   BitField("F", 0, 1),
                   BitField("T", 0, 1),
                   BitField("R", 0, 1),
                   BitField("K", 0, 1),
                   BitField("N", 0, 1),
                   BitField("A", 0, 1),
                   BitField("Rsvd", 0, 6),
                   IntField("group_id", 0)]
# don't know how to specify 128b field, therefore security key has to be specified separately
# GUE header size is hardcoded

# Create GUE control packet                 
def create_packet(iface, dst_ip, dst_port, src_port, group_id, security_key):
    pkt  = Ether(src=get_if_hwaddr(iface), dst=getmacbyip(dst_ip))
    pkt /= IP(src=get_if_addr(iface), dst=dst_ip)
    pkt /= UDP(sport=src_port, dport=dst_port)
    pkt /= GUE(control=1, Hlen=5, Proto_ctype=1, group_id=group_id)
#    pkt /= RadioTap(codecs.decode(security_key, 'hex'))
    pkt /= security_key
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

def usage(argv):
        print("Usage: %s <interface> <remote-ip> <remote-port> <local-port> <group-id> <service-id> <security-key>" % argv[0])
        print("    <interface>      - outgoing interface")
        print("    <remote-ip>      - IP destination")
        print("    <remote-port>    - UDP port destination")
        print("    <local-port>     - UDP port source")
        print("    <group-id>       - group identifier")
        print("    <service-id>     - service identifier")
        print("    <security-key>   - tunnel key (128b)")
        print("\nExample : %s eth0 5.5.5.5 6080 6080 1 1 'abcdefghijklmnop'" % argv[0])

def main(argv):
    print(argv)

    if (len(argv) < 8):
        usage(argv)
        return 1

    if (len(argv[7]) != 16):
        print("Security key must be 16 character (128b) long!")
        return 1

    gid = ((int(argv[5]) & 0xffff) << 16) + (int(argv[6]) & 0xffff)

    print("Sending GUE Control packet for group-id (%s,%s) to %s:%s" % (argv[5], argv[6], argv[2], argv[3]))
    packet = create_packet(argv[1], argv[2], int(argv[3]), int(argv[4]), gid, argv[7])
    sendp(packet, iface=argv[1])

if __name__ == '__main__':
    main(sys.argv)
