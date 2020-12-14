#!/bin/bash
# syntax: $0 <nic> <name> <conf-rx> <conf-tx> <port-min> <port-max> [<gue-delay>] [<sweep-delay>] [<sweep-count>]
#       <nic>             - Interface to bind PFC to
#       <name>            - Instance name
#       <conf-rx>         - PFC Inress configuration flags
#       <conf-tx>         - PFC Egress configuration flags
#       <port-min>        - Gue tunnel port range lower bound
#       <port-max>        - Gue tunnel port range upper bound
#       <gue-delay>       - (Optional) Interval of sending GUE pings (in seconds)
#       <sweep-delay>     - (Optional) Interval of checking stale session (in seconds)
#       <sweep-count>     - (Optional) Number of inactivity cycles before expiration

NIC=$1
NAME=$2
CONF_RX=$3
CONF_TX=$4
PORT_MIN=$5
PORT_MAX=$6
GUE_DELAY=$7
if [ $8 ] ; then
    SWEEP_DELAY=$8
else
    SWEEP_DELAY=10
fi
if [ $9 ] ; then
    SWEEP_CNT=$9
else
    SWEEP_CNT=6
fi

#set -Eeo pipefail

#VERBOSE="1"

if [ "${VERBOSE}" ]; then
    echo -e "\PFC.START : NIC='${NIC}' NAME='${NAME}' CONF_RX='${CONF_RX}' CONF_TX='${CONF_TX}' PORT_MIN='${PORT_MIN}' PORT_MAX='${PORT_MAX}' GUE_DELAY='${GUE_DELAY}' SWEEP_DELAY='${SWEEP_DELAY}' SWEEP_CNT='${SWEEP_CNT}'"
fi

if [ "${GUE_DELAY}" ]; then
    nohup gue_ping_svc_auto ${GUE_DELAY} ${SWEEP_DELAY} ${SWEEP_CNT} &> /tmp/gue_ping.log &
fi

attach_tc.sh ${NIC}

cli_cfg set ${NIC} 0 0 ${CONF_RX} "${NAME} RX"
cli_cfg set ${NIC} 1 0 ${CONF_TX} "${NAME} TX"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    cli_cfg get all
fi

port_init.sh ${PORT_MIN} ${PORT_MAX}

echo "# PFC.START : DONE"
