#!/bin/bash
# usage: $0 <ip> "<node-list>"
# example: $0 1.1.1.1 client1
# example: $0 1.1.1.1 "client1 client2 client3"

if [ ! "$1" ] ; then
    echo "usage: $0 <ip> \"<node list>\""
    exit 1
fi

IP=$1
NODES=$2

for NODE in ${NODES}
do
    echo -e "\n# PING ${NODE} -> ${IP}"
    docker exec -it ${NODE} bash -c "ping -c3 ${IP}"
    #docker exec -it ${NODE} bash -c "nping -c3 --icmp ${IP}"
done

echo -e "### Done ###\n"

