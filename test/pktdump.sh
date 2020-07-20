#!/bin/bash
# usage: $0 <docker-name> <interface> [<filter>]
# example:  tcpdump.sh client1 eth1 "arp or icmp"
# example:  tcpdump.sh client1 eth2

#VERBOSITY="-nvves 0"
VERBOSITY="-nvvvXXes 0"

if [ ! "$1" ]; then
    echo "Docker image name missing"
    echo "usage: $0 <docker-name> [<interface>] [<filter>]"
    echo "    <docker-name> - docker image name to attach to (required)"
    echo "    <interface>   - interface name to attach to (optional, default=eth0)"
    echo "    <filter>      - tcpdump filter to apply (optional, default=<empty> -> dump all)"
    echo ""
    echo "example: $0 client1 eth1"
    echo "example: $0 client1 eth2 'arp or icmp'"
    echo "example: $0 client1 eth2 'host 1.1.1.1 and (tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0)'"
    exit 1
fi

if [ "$2" ]; then
    nic=$2
else
    nic="eth1"
fi

echo "docker exec -it $1 tcpdump ${VERBOSITY} -i $nic \"$3\""
docker exec -it $1 tcpdump ${VERBOSITY} -i $nic "$3"

# using tshark instead
#VERBOSITY="-nxV"
#VERBOSITY="-nx"
#echo "docker exec -it $1 tshark ${VERBOSITY} -i $nic \"$3\""
#docker exec -it $1 tshark ${VERBOSITY} -i $nic "$3"

