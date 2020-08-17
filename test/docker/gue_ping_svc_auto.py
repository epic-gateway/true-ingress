#!/usr/bin/python

import sys
import time

from scapy.all import *

def usage():
        print("Usage: %s <delay>" % argv[0])
        print("    <delay> - delay between packets in seconds")
        print("\nExample : %s 10" % argv[0])

def main(argv):
    print(argv)

    if (len(argv) < 2):
        usage()
        return 1

    delay = int(argv[1])

    try:
        print("Starting infinite loop to send GUE Control packets every %s second(s)" % (delay))
        while (1):
            print(".")

            ifaces={}
            for i in get_if_list():
                ifaces[get_if_addr(i)] = i
            #print(ifaces)

            ret = os.popen("/tmp/.acnodal/bin/cli_service get all | grep 'VERIFY'").read()
            services = ret.split("\n")[1:-1]
            #print(services)

            verify={}
            for service in services:
                params = service.split(" ")
                #print(params)
                # >>>
                #group = int(params[1].split("{")[1].split(",")[0])
                #service = int(params[2].split("}")[0])
                # ===
                gid = int(params[10].split("{")[1], 16)
                # <<<
                pwd = params[4].split("'")[1]
                #print("id [%d], password [%s]" % (gid, pwd))
                verify[gid]=pwd
            print(verify)

            if len(verify) > 0:
                ret = os.popen("/tmp/.acnodal/bin/cli_tunnel get all | grep 'TUN'").read()
                tunnels = ret.split("\n")[1:-1]

                for tunnel in tunnels:
                    params = tunnel.split("\t")
                    if params[0] == "TUN":
                        tid = int(params[1])
                        #print("tunnel-id %d -> pwd '%s'" % (tid, verify[tid]))
                        ep = params[2].split(" ")
                        src = ep[7].split(":")
                        dst = ep[-2].split(":")
                        print("sending %s:%d -> %s:%d -> %d -> %s" % (ifaces[src[0]], int(src[1]), dst[0], int(dst[1]), tid, verify[tid]))
                        os.popen("python3 /tmp/.acnodal/bin/gue_ping_svc_once.py %s %s %s %s %d %d '%s'" %
                                       (ifaces[src[0]], dst[0], dst[1], src[1], tid >> 16, tid & 0xFFFF, verify[tid]))

            time.sleep(delay)
    except KeyboardInterrupt:
        print("Interrupted by user")
#        raise 

if __name__ == '__main__':
    main(sys.argv)
