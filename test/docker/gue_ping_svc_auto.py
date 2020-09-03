#!/usr/bin/python

import sys
import time

from scapy.all import *

def usage(argv):
    print("Usage: %s <ping-delay> <sweep-delay> <sweep-count>" % argv[0])
    print("    <ping-delay> - delay between GUE control packets (in seconds)")
    print("    <sweep-delay> - delay between session sweep checks (in seconds)")
    print("    <sweep-count> - number of inactive intervals for session expiration")
    print("\nExample : %s 10 10 60" % argv[0])

tunnels={}
encaps={}
nats={}
session_hash={}
session_ttl={}
sweep_counter=0

def tunnel_ping(timeout):
    global tunnels

    ifaces={}
    for i in get_if_list():
        ifaces[get_if_addr(i)] = i
    #print(ifaces)

    #print(tunnels)
    tmp = tunnels.copy()
    tunnels.clear()
    #print(tmp)

    ret = os.popen("/tmp/.acnodal/bin/cli_service get all | grep 'VERIFY'").read()
    services = ret.split("\n")[1:-1]
    #print(services)

    # read services for GUE HEADER info (group-id, service-id, key)"
    verify={}
    for service in services:
        params = service.split(" ")
        gid = int(params[8].split("{")[1], 16)
        pwd = params[4].split("'")[1]
        #print("id [%d], password [%s]" % (gid, pwd))
        verify[gid]=pwd
    print(verify)

    # read tunnels for outer header assembly
    if len(verify) == 0:
        return

    ret = os.popen("/tmp/.acnodal/bin/cli_tunnel get all | grep 'TUN'").read()
    tnls = ret.split("\n")[1:-1]
    #print(tnls)

    for tunnel in tnls:
        params = tunnel.split("\t")
        if params[0] != "TUN":
            continue

        tid = int(params[1])
        #print("tunnel-id %d -> pwd '%s'" % (tid, verify[tid]))
        ep = params[2].split(" ")
        src = ep[7].split(":")
        dst = ep[-2].split(":")

        if tid in tmp and tmp[tid] < timeout:
            tunnels[tid] = tmp[tid] + 1
        else:
            #print("sending %s:%s -> %s:%s -> %d -> %s" % (ifaces[src[0]], src[1], dst[0], dst[1], tid, verify[tid]))
            ret = os.popen("python3 /tmp/.acnodal/bin/gue_ping_svc_once.py %s %s %s %s %d %d '%s'" %
                       (ifaces[src[0]], dst[0], dst[1], src[1], tid >> 16, tid & 0xFFFF, verify[tid])).read()
            #print(ret)
            tunnels[tid] = 1
    #print(tunnels)

def session_sweep(expire):
    global session_hash
    global session_ttl

    #ret = os.popen("/tmp/.acnodal/bin/cli_service get all | grep 'ENCAP'").read()
    ret = os.popen("/tmp/.acnodal/bin/cli_gc get all | grep 'ENCAP'").read()
    services = ret.split("\n")[1:-1]
    #print(services)

    for service in services:
        params = service.split(" ")
        #print(params)
        if params[0] != "ENCAP":
            continue

        key = service.split("->")[0]
        #print(key)
        hash = int(params[6].split("\t")[2])
        #print(hash)
        if hash == 0:
            # static record
            continue

        if key in session_hash and session_hash[key] == hash:
            if session_ttl[key] >= expire:
                to_del = key.split("(")[1].split(")")[0].split(",")
                #print(to_del)
                del session_hash[key]
                del session_ttl[key]
                print("cli_gc del %s%s%s" % (to_del[0], to_del[1], to_del[2]))
                ret = os.popen("/tmp/.acnodal/bin/cli_gc del %s%s%s" % (to_del[0], to_del[1], to_del[2])).read()
            else:
                session_ttl[key] += 1
                #print("%s  ->  %d/%d" % (key, session_ttl[key], expire))
        else:
            session_hash[key] = hash
            session_ttl[key] = 1
            #print("%s  ->  %d/%d" % (key, session_ttl[key], expire))

def main(argv):
    print(argv)

    if (len(argv) < 4):
        usage(argv)
        return 1

    tun_delay = int(argv[1])
    sweep_delay = int(argv[2])
    sweep_count = int(argv[3])
    counter = sweep_delay

    try:
        print("Starting PFC daemon")
        while (1):
            print(".")

            # GUE ping
            tunnel_ping(tun_delay)

            # Session expiration
            if counter < sweep_delay:
                counter += 1
            else:
                session_sweep(sweep_count)
                counter = 1

            time.sleep(1)
    except KeyboardInterrupt:
        print("Interrupted by user")
#        raise 

if __name__ == '__main__':
    main(sys.argv)
