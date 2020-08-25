#!/bin/bash
# syntax: $0 <group-id> <service-id>
#       <group-id>              - Group ID
#       <service-id>            - Service ID

GROUP_ID=$1
SERVICE_ID=$2

set -Eeo pipefail

#VERBOSE="1"

#if [ "${VERBOSE}" ]; then
    echo -e "PFC.DEL : GROUP_ID='${GROUP_ID}' SERVICE_ID='${SERVICE_ID}'"
#fi

TUNNEL_ID=${GROUP_ID}
((TUNNEL_ID <<= 16))
((TUNNEL_ID += ${SERVICE_ID}))
LOCAL_TUN_PORT=$(/tmp/.acnodal/bin/cli_tunnel get ${TUNNEL_ID} | grep ${TUNNEL_ID} | awk '{print $3}' | sed 's/:/ /g' | awk '{print $2}')

#if [ "${VERBOSE}" ]; then
    echo "    Tunnel-ID : ${TUNNEL_ID}"
    echo "    Freeing port : ${LOCAL_TUN_PORT}"
#fi

## Remove service forwarding
#                 cli_service set  <group-id>  <service-id> 
/tmp/.acnodal/bin/cli_service del ${GROUP_ID} ${SERVICE_ID}

## Remove GUE tunnel from ${NODE} to ${PROXY}
#                 cli_tunnel set  <id> 
/tmp/.acnodal/bin/cli_tunnel del ${TUNNEL_ID}

/tmp/.acnodal/bin/port_free.sh ${LOCAL_TUN_PORT}

if [ "${VERBOSE}" ]; then
    echo "# PFC.DEL : DONE"
fi
