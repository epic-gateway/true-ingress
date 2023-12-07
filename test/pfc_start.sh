#!/bin/bash
# syntax: $0 <nic> <name> <conf-rx> <conf-tx> <port-min> <port-max> [<gue-delay>]
#       <nic>             - Interface to bind to
#       <name>            - Instance name
#       <conf-rx>         - Inress configuration flags
#       <conf-tx>         - Egress configuration flags
#       <port-min>        - Gue tunnel port range lower bound
#       <port-max>        - Gue tunnel port range upper bound
#       <gue-delay>       - (Optional) Interval of sending GUE pings (in seconds)

NIC=$1
NAME=$2
CONF_RX=$3
CONF_TX=$4
PORT_MIN=$5
PORT_MAX=$6
GUE_DELAY=$7

#set -Eeo pipefail

#VERBOSE="1"

if [ "${VERBOSE}" ]; then
    echo -e "\PFC.START : NIC='${NIC}' NAME='${NAME}' CONF_RX='${CONF_RX}' CONF_TX='${CONF_TX}' PORT_MIN='${PORT_MIN}' PORT_MAX='${PORT_MAX}' GUE_DELAY='${GUE_DELAY}'"
fi

if [ "${GUE_DELAY}" ]; then
    nohup gue_ping_svc_auto ${GUE_DELAY} &> /tmp/gue_ping.log &
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
