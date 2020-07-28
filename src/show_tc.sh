#!/bin/bash
#
# usage: $0 <interface> [<direction>]

DIRECTION=$2

if [ ! "$1" ] ; then
    NICS=$(ip link | grep "mtu" | sed 's/@/ /' | awk '{print $2}' | sed 's/:/ /')
else
    NICS=$1
fi

for NIC in $NICS
do
    NUM=$(ip link | grep "${NIC}" | awk '{print $1}' | sed 's/://')
    if [ "${DIRECTION}" ] ; then
        echo "${NIC} (${NUM})"
        OUT=$(tc filter show dev ${NIC} ${DIRECTION} | grep "pfc_${DIRECTION}_tc.o")
        if [ "${OUT}" ] ; then
            echo -e "    ${DIRECTION} : ${OUT}"
        fi
    else
        echo "${NIC} (${NUM})"
        OUT=$(tc filter show dev ${NIC} ingress | grep "pfc_ingress_tc.o")
        if [ "${OUT}" ] ; then
            echo -e "    ingress : ${OUT}"
        fi

        OUT=$(tc filter show dev ${NIC} egress | grep "pfc_egress_tc.o")
        if [ "${OUT}" ] ; then
            echo -e "    egress  : ${OUT}"
        fi
    fi
done

#bpftool prog show
