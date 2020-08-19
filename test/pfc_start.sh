#!/bin/bash
# syntax: $0 <nic> <name> <conf-rx> <conf-tx> <port-min> <port-max> [<delay>]
#       <nic>       - Interface to bind PFC to
#       <name>      - Instance name
#       <conf-rx>   - PFC Inress configuration flags
#       <conf-tx>   - PFC Egress configuration flags
#       <port-min>  - Gue tunnel port range lower bound
#       <port-max>  - Gue tunnel port range upper bound
#       <delay>     - (Optional) Interval of sending GUE pings in seconds

NIC=$1
NAME=$2
CONF_RX=$3
CONF_TX=$4
PORT_MIN=$5
PORT_MAX=$6
DELAY=$7

#set -Eeo pipefail

#VERBOSE="1"

if [ "${VERBOSE}" ]; then
    echo -e "\PFC.START : NIC='${NIC}' NAME='${NAME}' CONF_RX='${CONF_RX}' CONF_TX='${CONF_TX}' PORT_MIN='${PORT_MIN}' PORT_MAX='${PORT_MAX}' DELAY='${DELAY}'"
fi

/tmp/.acnodal/bin/attach_tc.sh ${NIC}

/tmp/.acnodal/bin/cli_cfg set ${NIC} 0 0 ${CONF_RX} "${NAME} RX"
/tmp/.acnodal/bin/cli_cfg set ${NIC} 1 0 ${CONF_TX} "${NAME} TX"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    /tmp/.acnodal/bin/cli_cfg get all
fi

/tmp/.acnodal/bin/port_init.sh ${PORT_MIN} ${PORT_MAX}

if [ "${DELAY}" ]; then
    nohup bash -c "python3 /tmp/.acnodal/bin/gue_ping_svc_auto.py ${DELAY}" &
    #nohup bash -c "python3 /tmp/.acnodal/bin/gue_ping_svc_auto.py ${DELAY} &> /tmp/gue_ping.log" &
    #nohup python3 /tmp/.acnodal/bin/gue_ping_svc_auto.py ${DELAY} &
    ps aux | grep "gue_ping"
fi

echo "# PFC.START : DONE"
