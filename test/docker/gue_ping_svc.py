#!/usr/bin/python

import sys
import time

from scapy.all import *

def usage(argv):
        print("Usage: %s <interface> <delay> <remote-ip> <remote-port> <local-port> <group-id> <service-id> <security-key>" % argv[0])
        print("    <delay>          - delay between packets in seconds")
        print("    <interface>      - outgoing interface")
        print("    <remote-ip>      - IP destination")
        print("    <remote-port>    - UDP port destination")
        print("    <local-port>     - UDP port source")
        print("    <group-id>       - group identifier")
        print("    <service-id>     - service identifier")
        print("    <security-key>   - tunnel key (128b)")
        print("\nExample : %s eth0 60 5.5.5.5 6080 6080 1 1 'abcdefghijklmnop'" % argv[0])

def main(argv):
    print(argv)

    if (len(argv) < 9):
        usage(argv)
        return 1

    if (len(argv[8]) != 16):
        print("Security key must be 16 character (128b) long!")
        return 1

    delay = int(argv[2])

    try:
        print("Starting infinite loop to send GUE Control packet for group-id %s service-id %s to %s:%s every %d second(s)" % (argv[6], argv[7], argv[3], argv[4], delay))
        while (1):
            print(".")

            #print("python3 /opt/acnodal/bin/gue_ping_svc_once.py %s %s %s %s 0 %s '%s'" % (argv[1], argv[3], argv[4], argv[5], argv[6], argv[7]))
            os.popen("python3 /opt/acnodal/bin/gue_ping_svc_once.py %s %s %s %s %s %s '%s'" % (argv[1], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8]))

            time.sleep(delay)
    except KeyboardInterrupt:
        print("Interrupted by user")
#        raise 

if __name__ == '__main__':
    main(sys.argv)
