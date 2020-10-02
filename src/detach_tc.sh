#!/bin/bash
#
# usage: $0 <interface> [<direction>]

NIC=$1
DIRECTION=$2

function lookup()
{
    if [ -f "./$1" ] ; then
        FILE="./$1"
    elif [ -f "$1" ] ; then
        FILE="$1"
    elif [ -f $(which $1) ] ; then
        FILE=$(which $1)
#    else
#        echo "Cannot find '${BINARY}_${DIRECTION}_tc.o'"
#        exit 1
    fi
    echo "${FILE}"
}

if [ ! "${NIC}" ] ; then
    NIC=$(ip route | grep default | awk '{print $5}')
fi

if [ "${DIRECTION}" ] ; then
    sudo tc filter del dev ${NIC} ${DIRECTION}
else
    echo "Detaching bpf from ${NIC} ingress"
    sudo tc filter del dev ${NIC} ingress
    echo "Detaching bpf from ${NIC} egress"
    sudo tc filter del dev ${NIC} egress
    
    # whole qdisc
    #sudo tc qdisc del dev ${NIC} clsact
fi

$(lookup show_tc.sh) ${NIC} ${DIRECTION}

# unmount maps? not to mess with other eBPF?
sudo umount /sys/fs/bpf/

echo "DONE"
