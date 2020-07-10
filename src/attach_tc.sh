#!/bin/bash
#
# usage: $0 <interface> <ebpf-program> [<direction>]

NIC=$1
BINARY=$2
DIRECTION=$3

sudo mount -t bpf bpf /sys/fs/bpf/

echo "Loading PFC(TC) to ${NIC}..."
CHECK=`tc qdisc show | grep clsact | grep ${NIC}`
if [ "${CHECK}" ]; then
    echo "### Using existing clsact qdisc ###"
else
    echo "### Creating new clsact qdisc... ###"
    sudo tc qdisc add dev ${NIC} clsact
fi


if [ "${DIRECTION}" ] ; then
    echo "### Loading ${BINARY}_${DIRECTION}_tc.o to ${NIC} ${DIRECTION} ###"
    sudo tc -d filter add dev ${NIC} ${DIRECTION} bpf direct-action object-file ${BINARY}_${DIRECTION}_tc.o sec .text
else
    echo "### Loading ${BINARY}_ingress_tc.o to ${NIC} ingress ###"
    sudo tc -d filter add dev ${NIC} ingress bpf direct-action object-file ${BINARY}_ingress_tc.o sec .text
    echo "### Loading ${BINARY}_egress_tc.o to ${NIC} egress ###"
    sudo tc -d filter add dev ${NIC} egress  bpf direct-action object-file ${BINARY}_egress_tc.o sec .text
fi

echo "### Check ###"
./show_tc.sh ${NIC} ${DIRECTION}
echo "DONE"
