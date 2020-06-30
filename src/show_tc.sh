#!/bin/bash
#
# usage: $0 <interface> [<direction>]

NIC=$1
DIRECTION=$2

if [ "${DIRECTION}" ] ; then
    echo "${NIC} [${DIRECTION}]:"
    tc filter show dev ${NIC} ${DIRECTION}
else
    echo "${NIC} [ingress]:"
    tc filter show dev ${NIC} ingress
    echo "${NIC} [egress]:"
    tc filter show dev ${NIC} egress
fi

#bpftool prog show
