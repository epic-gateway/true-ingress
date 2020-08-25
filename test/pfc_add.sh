#!/bin/bash
# syntax: $0 [-p] <nic> <group-id> <service-id> <passwd> <remote-tunnel-ip> <remote-tunnel-port> <proto> <proxy-ip> <proxy-port> <backend-ip> <backend-port>
#       <-p>                    - (Optional) Send one time GUE ping
#       <nic>                   - Interface to sending one time GUE ping from
#       <group-id>              - Group ID
#       <service-id>            - Service ID
#       <passwd>                - Security key
#       <remote-tunnel-ip>      - Remote GUE tunnel IPv4 address
#       <remote-tunnel-port>    - Remote GUE tunnel port
#       <proto>                 - Service IP protocol
#       <proxy-ip>              - Service proxy IPv4 address
#       <proxy-port>            - Service proxy port
#       <backend-ip>            - Service backend IPv4 address
#       <backend-port>          - Service backend port

set -Eeo pipefail

#VERBOSE="1"

# parse args
while getopts "p" opt; do
    case "$opt" in
    p)  PING=1
        shift
        ;;
    esac
done

NIC=$1
GROUP_ID=$2
SERVICE_ID=$3
PASSWD=$4
REMOTE_TUN_IP=$5
REMOTE_TUN_PORT=$6
PROTO=$7
PROXY_IP=$8
PROXY_PORT=$9
SERVICE_IP=${10}
SERVICE_PORT=${11}

TUNNEL_ID=${GROUP_ID}
((TUNNEL_ID <<= 16))
((TUNNEL_ID += ${SERVICE_ID}))
LOCAL_TUN_IP=$(ip addr show dev ${NIC} | grep inet | awk '{print $2}' | sed 's/\// /g' | awk '{print $1}')
LOCAL_TUN_PORT=$(/tmp/.acnodal/bin/port_alloc.sh)

if [ ! "${LOCAL_TUN_PORT}" ] ; then
    exit -1
fi

if [ "${VERBOSE}" ]; then
    echo -e "\nPFC.ADD : NIC='${NIC}' GROUP_ID='${GROUP_ID}' SERVICE_ID='${SERVICE_ID}' PASSWD='${PASSWD}' REMOTE_TUN_IP='${REMOTE_TUN_IP}' REMOTE_TUN_PORT='${REMOTE_TUN_PORT}' PROTO='${PROTO}' PROXY_IP='${PROXY_IP}' PROXY_PORT='${PROXY_PORT}' SERVICE_IP='${SERVICE_IP}' SERVICE_PORT='${SERVICE_PORT}'"
    echo "    Local IP : ${LOCAL_TUN_IP}"
    echo "    Allocated tunnel port : ${LOCAL_TUN_PORT}"
    echo "    Tunnel-ID : ${TUNNEL_ID}"
fi

## Setup GUE tunnel from ${NODE} to ${PROXY}
#                 cli_tunnel set  <id>         <ip-local>      <port-local>      <ip-remote>      <port-remote>
/tmp/.acnodal/bin/cli_tunnel set ${TUNNEL_ID} ${LOCAL_TUN_IP} ${LOCAL_TUN_PORT} ${REMOTE_TUN_IP} ${REMOTE_TUN_PORT}

## Setup service forwarding
#                 cli_service set  <group-id>  <service-id>  <proto>  <ip-proxy>  <port-proxy>  <ip-ep>       <port-ep>       <tunnel-id> <key>
/tmp/.acnodal/bin/cli_service set ${GROUP_ID} ${SERVICE_ID} ${PROTO} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT} ${TUNNEL_ID} ${PASSWD}

if [ "${PING}" ]; then
    if [ "${VERBOSE}" ]; then
        echo "Sending GUE one time ping..."
    fi
    python3 /tmp/.acnodal/bin/gue_ping_svc_once.py ${NIC} ${REMOTE_TUN_IP} ${REMOTE_TUN_PORT} ${LOCAL_TUN_PORT} ${GROUP_ID} ${SERVICE_ID} ${PASSWD}
fi

if [ "${VERBOSE}" ]; then
    echo "# PFC.ADD : DONE"
fi
