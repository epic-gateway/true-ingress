#!/bin/bash
#
# usage: $0  [<interface>] [<direction>]

BINARY="pfc"
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

sudo mount -t bpf bpf /sys/fs/bpf/

if [ ! "${NIC}" ] ; then
    NIC=$(ip route | grep default | awk '{print $5}')
fi

echo "Loading TC to ${NIC}..."
CHECK=`tc qdisc show dev ${NIC} | grep clsact`
if [ "${CHECK}" ]; then
    echo "### Using existing clsact qdisc ###"
else
    echo "### Creating new clsact qdisc... ###"
    sudo tc qdisc add dev ${NIC} clsact
fi


if [ "${DIRECTION}" ] ; then
    echo "### Loading ${BINARY}_${DIRECTION}_tc.o to ${NIC} ${DIRECTION} ###"
    #sudo tc -d filter add dev ${NIC} ${DIRECTION} bpf direct-action object-file ${BINARY}_${DIRECTION}_tc.o sec .text
#    sudo tc filter add dev ${NIC} ${DIRECTION} bpf direct-action object-file $(lookup "${BINARY}_${DIRECTION}_tc.o") sec .text
    lookup "${BINARY}_${DIRECTION}_tc.o"
    echo "${FILE}"
    sudo tc filter add dev ${NIC} ${DIRECTION} bpf direct-action object-file ${FILE} sec .text
else
    echo "### Loading ${BINARY}_ingress_tc.o to ${NIC} ingress ###"
#    sudo tc filter add dev ${NIC} ingress bpf direct-action object-file $(lookup "${BINARY}_ingress_tc.o") sec .text
    lookup "${BINARY}_ingress_tc.o"
    echo "${FILE}"
    sudo tc filter add dev ${NIC} ingress bpf direct-action object-file ${FILE} sec .text
    echo "### Loading ${BINARY}_egress_tc.o to ${NIC} egress ###"
#    sudo tc filter add dev ${NIC} egress  bpf direct-action object-file $(lookup "${BINARY}_egress_tc.o") sec .text
    lookup "${BINARY}_egress_tc.o"
    echo "${FILE}"
    sudo tc filter add dev ${NIC} egress  bpf direct-action object-file ${FILE} sec .text
fi

echo "### Check ###"
$(lookup show_tc.sh) ${NIC} ${DIRECTION}
echo "DONE"
