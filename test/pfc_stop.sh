#!/bin/bash
# syntax: $0 <nic>
#       <nic>       - Interface which PFC is bound to

NIC=$1

#set -Eeox pipefail

#VERBOSE="1"

if [ "${VERBOSE}" ]; then
    echo -e "\PFC.STOP : NIC='${NIC}'"
fi

# detach eBPF from interface
/opt/acnodal/bin/detach_tc.sh ${NIC}

# clean GUE port pool
rm -rf /opt/acnodal/cfg/gue_port.cfg
ls /opt/acnodal/cfg/

# stop GUE ping daemon
#ps aux | grep "gue_ping"
PID=$(ps aux | grep "gue_ping" | grep -v "grep" | awk '{print $2}')
if [ "${PID}" ]; then
    echo "PID to kill : ${PID}"
    kill -9 ${PID}
else
    echo "No PID to kill"
fi

echo "# PFC.STOP : DONE"
