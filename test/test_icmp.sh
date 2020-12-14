#!/bin/bash
# usage: $0 <ip> ["<node-list>"]
#
# example: ping from container "client1"
#   $0 1.1.1.1 client1
# example: ping from multiple containers
#   $0 1.1.1.1 "client1 client2 client3"
# example: ping fron host
#   $0 1.1.1.1

if [ ! "$1" ] ; then
    echo "usage: $0 <ip> \"<node list>\""
    exit 1
fi

IP=$1
NODES="$2"

if [ "${NODES}" ] ; then
    for NODE in ${NODES}
    do
        echo -e "\n# PING ${NODE} -> ${IP}"
        docker exec -it ${NODE} bash -c "ping -q -c3 ${IP}"
    done
else
    ping -q -c3 ${IP}
fi

