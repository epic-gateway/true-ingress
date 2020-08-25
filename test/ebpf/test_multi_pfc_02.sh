#!/bin/bash
# Setup HTTP service on NODE behind NAT, expose it on EGW and send request from CLIENT.
# Attach and configure PFC on NODE and EGW.
# Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
# Setup HTTP service and forwarding.
# Send HTTP request from client to *proxy ip:port*.
# usage: $0 [-v|-V]

set -Eeo pipefail

# parse args
while getopts "vV" opt; do
    case "$opt" in
    v)  VERBOSE=1
        shift
        ;;
    V)  export VERBOSE=1
        shift
        ;;
    esac
done

cd ..

RETURN=0

# INFRA: setup topology
if [ "${VERBOSE}" ]; then
    ./topo_setup.sh basic.cfg
else
    echo "Starting topology..."
    ./topo_setup.sh basic.cfg > /dev/null
fi

CLIENT="client"
PROXY="egw"
PROXY_IP="5.5.5.5"
GROUP_ID=1

NODE="node2"
SERVICE_TYPE="http"
SERVICE_PROTO="tcp"
SERVICE_ID="200"
SERVICE_NAME="foo"
SERVICE_IP="2.2.2.2"
SERVICE_PORT="4000"
PROXY_PORT="3200"
PASSWD='5erv1ceP@55w0rd1'

NODE2="node2"
SERVICE_TYPE2="http"
SERVICE_PROTO2="tcp"
SERVICE_ID2="210"
SERVICE_NAME2="bar"
SERVICE_IP2="2.2.2.2"
SERVICE_PORT2="4444"
PROXY_PORT2="3210"
PASSWD2='5erv1ceP@55w0rd2'

PROXY_PORT_MIN=5000
PROXY_PORT_MAX=5010
NODE_PORT_MIN=6000
NODE_PORT_MAX=6010

PROXY_NIC="eth1"
NODE_NIC="eth1"
DELAY=10

# PFC: Start PFC
if [ "${VERBOSE}" ]; then
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/pfc_start.sh ${PROXY_NIC} "${PROXY}" 9 9 ${PROXY_PORT_MIN} ${PROXY_PORT_MAX}"
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/pfc_start.sh ${NODE_NIC} "${NODE}" 9 8 ${NODE_PORT_MIN} ${NODE_PORT_MAX} ${DELAY}"

    docker exec -it ${NODE} bash -c "ps aux | grep 'gue_ping'"
else
    echo "Starting PFC..."
    echo "  ${PROXY}"
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/pfc_start.sh ${PROXY_NIC} "${PROXY}" 9 9 ${PROXY_PORT_MIN} ${PROXY_PORT_MAX}" > /dev/null
    echo "  ${NODE}"
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/pfc_start.sh ${NODE_NIC} "${NODE}" 9 8 ${NODE_PORT_MIN} ${NODE_PORT_MAX} ${DELAY}" > /dev/null
fi

# INFRA: Setup HTTP service on ${NODE}
if [ "${VERBOSE}" ]; then
    # service_start.sh  <node>  <ip>          <port>          <service-id>   <service>
    ./service_start.sh ${NODE} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_NAME} ${SERVICE_TYPE}
    ./service_start.sh ${NODE2} ${SERVICE_IP2} ${SERVICE_PORT2} ${SERVICE_NAME2} ${SERVICE_TYPE2}
else
    echo "Starting service(s)..."
    echo "  ${SERVICE_NAME}"
    echo "    Location '${NODE}', Type '${SERVICE_TYPE}', Endpoint '${SERVICE_PROTO}:${SERVICE_IP}:${SERVICE_PORT}'"
    ./service_start.sh ${NODE} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_NAME} ${SERVICE_TYPE} > /dev/null
    echo "  ${SERVICE_NAME2}"
    echo "    Location '${NODE2}', Type '${SERVICE_TYPE2}', Endpoint '${SERVICE_PROTO2}:${SERVICE_IP2}:${SERVICE_PORT2}'"
    ./service_start.sh ${NODE2} ${SERVICE_IP2} ${SERVICE_PORT2} ${SERVICE_NAME2} ${SERVICE_TYPE2} > /dev/null
fi

PROXY_TUN_IP="172.1.0.3"

TUNNEL_ID=${GROUP_ID}
((TUNNEL_ID <<= 16))
((TUNNEL_ID += ${SERVICE_ID}))

PROXY_TUN_PORT="?"
NODE_TUN_PORT="?"
NODE_TUN_IP="172.2.0.3"

TUNNEL_ID2=${GROUP_ID}
((TUNNEL_ID2 <<= 16))
((TUNNEL_ID2 += ${SERVICE_ID2}))

PROXY_TUN_PORT2="?"
NODE_TUN_PORT2="?"
NODE_TUN_IP2="172.2.0.3"

echo "Setup forwarding..."
echo "  ${SERVICE_NAME}"
echo "    Proxy   : ${PROXY}  ${SERVICE_PROTO}:${PROXY_IP}:${PROXY_PORT} -> ${NODE}  ${SERVICE_PROTO}:${SERVICE_IP}:${SERVICE_PORT}"
echo "    Service : (${GROUP_ID},${SERVICE_ID}) -> '${PASSWD}'"
echo "    Tunnel  : ${TUNNEL_ID} ${PROXY_TUN_IP}:${PROXY_TUN_PORT} -> ${NODE_TUN_IP}:${NODE_TUN_PORT}"
echo "  ${SERVICE_NAME2}"
echo "    Proxy   : ${PROXY}  ${SERVICE_PROTO2}:${PROXY_IP}:${PROXY_PORT2} -> ${NODE2}  ${SERVICE_PROTO2}:${SERVICE_IP2}:${SERVICE_PORT2}"
echo "    Service : (${GROUP_ID},${SERVICE_ID2}) -> '${PASSWD2}'"
echo "    Tunnel  : ${TUNNEL_ID2} ${PROXY_TUN_IP}:${PROXY_TUN_PORT2} -> ${NODE_TUN_IP2}:${NODE_TUN_PORT2}"

# INFRA: setup proxy
docker exec -it ${PROXY} bash -c "iptables -t nat -A PREROUTING -p ${SERVICE_PROTO} -i ${PROXY_NIC} --destination ${PROXY_IP} --dport ${PROXY_PORT} -j DNAT --to-destination ${SERVICE_IP}:${SERVICE_PORT}"
docker exec -it ${PROXY} bash -c "iptables -t nat -A POSTROUTING -p ${SERVICE_PROTO} -o ${PROXY_NIC} -s ${SERVICE_IP} --sport ${SERVICE_PORT} -j SNAT --to-source ${PROXY_IP}:${PROXY_PORT}"
docker exec -it ${PROXY} bash -c "iptables -t nat -A PREROUTING -p ${SERVICE_PROTO2} -i ${PROXY_NIC} --destination ${PROXY_IP} --dport ${PROXY_PORT2} -j DNAT --to-destination ${SERVICE_IP2}:${SERVICE_PORT2}"
docker exec -it ${PROXY} bash -c "iptables -t nat -A POSTROUTING -p ${SERVICE_PROTO2} -o ${PROXY_NIC} -s ${SERVICE_IP2} --sport ${SERVICE_PORT2} -j SNAT --to-source ${PROXY_IP}:${PROXY_PORT2}"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${PROXY} bash -c "iptables -t nat -L PREROUTING -vn --line-numbers"
    docker exec -it ${PROXY} bash -c "iptables -t nat -L POSTROUTING -vn --line-numbers"
fi

# PFC: configure forwarding
if [ "${VERBOSE}" ]; then
    # pfc_add.sh     <nic> <group-id> <service-id> <passwd> <remote-tunnel-ip> <remote-tunnel-port> <proto> <proxy-ip> <proxy-port> <backend-ip> <backend-port>
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/pfc_add.sh ${PROXY_NIC} ${GROUP_ID} ${SERVICE_ID} ${PASSWD} 0 0 ${SERVICE_PROTO} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT}"
    PROXY_TUN_PORT=$(docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get ${TUNNEL_ID}" | grep ${TUNNEL_ID} | awk '{print $3}' | sed 's/:/ /g' | awk '{print $2}')
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/pfc_add.sh -p ${NODE_NIC} ${GROUP_ID} ${SERVICE_ID} ${PASSWD} ${PROXY_TUN_IP} ${PROXY_TUN_PORT} ${SERVICE_PROTO} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT}"

    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/pfc_add.sh ${PROXY_NIC} ${GROUP_ID} ${SERVICE_ID2} ${PASSWD2} 0 0 ${SERVICE_PROTO2} ${PROXY_IP} ${PROXY_PORT2} ${SERVICE_IP2} ${SERVICE_PORT2}"
    PROXY_TUN_PORT2=$(docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get ${TUNNEL_ID2}" | grep ${TUNNEL_ID2} | awk '{print $3}' | sed 's/:/ /g' | awk '{print $2}')
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/pfc_add.sh -p ${NODE_NIC} ${GROUP_ID} ${SERVICE_ID2} ${PASSWD2} ${PROXY_TUN_IP} ${PROXY_TUN_PORT2} ${SERVICE_PROTO2} ${PROXY_IP} ${PROXY_PORT2} ${SERVICE_IP2} ${SERVICE_PORT2}"

    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/pfc_list.sh"
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/pfc_list.sh"
else
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/pfc_add.sh ${PROXY_NIC} ${GROUP_ID} ${SERVICE_ID} ${PASSWD} 0 0 ${SERVICE_PROTO} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT}" > /dev/null
    PROXY_TUN_PORT=$(docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get ${TUNNEL_ID}" | grep ${TUNNEL_ID} | awk '{print $3}' | sed 's/:/ /g' | awk '{print $2}')
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/pfc_add.sh -p ${NODE_NIC} ${GROUP_ID} ${SERVICE_ID} ${PASSWD} ${PROXY_TUN_IP} ${PROXY_TUN_PORT} ${SERVICE_PROTO} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT}" > /dev/null

    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/pfc_add.sh ${PROXY_NIC} ${GROUP_ID} ${SERVICE_ID2} ${PASSWD2} 0 0 ${SERVICE_PROTO2} ${PROXY_IP} ${PROXY_PORT2} ${SERVICE_IP2} ${SERVICE_PORT2}" > /dev/null
    PROXY_TUN_PORT2=$(docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get ${TUNNEL_ID2}" | grep ${TUNNEL_ID2} | awk '{print $3}' | sed 's/:/ /g' | awk '{print $2}')
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/pfc_add.sh -p ${NODE_NIC} ${GROUP_ID} ${SERVICE_ID2} ${PASSWD2} ${PROXY_TUN_IP} ${PROXY_TUN_PORT2} ${SERVICE_PROTO2} ${PROXY_IP} ${PROXY_PORT2} ${SERVICE_IP2} ${SERVICE_PORT2}" > /dev/null
fi

# INFRA: verify result
echo "Waiting for GUE ping..."
for (( i=1; i<10; i++ ))
do
    if [ "$(docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get ${TUNNEL_ID}" | grep "TUN" | grep ${TUNNEL_ID} | grep -v "0.0.0.0:0")" ] ; then
        break
    fi
    echo "."
    sleep 1
done

for (( i=1; i<10; i++ ))
do
    if [ "$(docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get ${TUNNEL_ID2}" | grep "TUN" | grep ${TUNNEL_ID2} | grep -v "0.0.0.0:0")" ] ; then
        break
    fi
    echo "."
    sleep 1
done

if [ ! "$(docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get ${TUNNEL_ID}" | grep "TUN" | grep ${TUNNEL_ID} | grep -v "0.0.0.0:0")" ] ; then
    echo -e "\nGUE Ping for '${SERVICE_NAME}' \e[31mFAILED\e[0m\n"
    RETURN=1
elif [ ! "$(docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get ${TUNNEL_ID2}" | grep "TUN" | grep ${TUNNEL_ID2} | grep -v "0.0.0.0:0")" ] ; then
    echo -e "\nGUE Ping for '${SERVICE_NAME2}' \e[31mFAILED\e[0m\n"
    RETURN=1
else
    # check traces before
#    tail -n60 /sys/kernel/debug/tracing/trace

    # generate ICMP ECHO REQUEST + RESPONSE packets
    # syntax: $0     <docker>  <ip>        <port>
    TMP=$(./${SERVICE_TYPE}_check.sh ${CLIENT} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_ID})
    if [ "${VERBOSE}" ]; then
        echo "${TMP}"
    fi
    if [ "$(echo "${TMP}" | grep ${SERVICE_NAME})" ] ; then
        echo -e "\nService '${SERVICE_NAME}' : \e[32mPASS\e[0m\n"
    else
        echo -e "\nService '${SERVICE_NAME}' : \e[31mFAILED\e[0m\n"
        RETURN=1
    fi

    TMP=$(./${SERVICE_TYPE2}_check.sh ${CLIENT} ${PROXY_IP} ${PROXY_PORT2} ${SERVICE_ID2})                                                                                                                                                                                       
    if [ "${VERBOSE}" ]; then                                                                                                                                                                                                                                                 
        echo "${TMP}"                                                                                                                                                                                                                                                         
    fi                                                                                                                                                                                                                                                                        
    if [ "$(echo "${TMP}" | grep ${SERVICE_NAME2})" ] ; then
        echo -e "\nService '${SERVICE_NAME2}' : \e[32mPASS\e[0m\n"
    else
        echo -e "\nService '${SERVICE_NAME2}' : \e[31mFAILED\e[0m\n"
        RETURN=1
    fi

    # check traces after
#    tail -n60 /sys/kernel/debug/tracing/trace
fi

# INFRA & PFC: cleanup topology
if [ "${VERBOSE}" ]; then
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/pfc_delete.sh ${GROUP_ID} ${SERVICE_ID}"
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/pfc_delete.sh ${GROUP_ID} ${SERVICE_ID}"
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/pfc_delete.sh ${GROUP_ID} ${SERVICE_ID2}"
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/pfc_delete.sh ${GROUP_ID} ${SERVICE_ID2}"

    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/pfc_list.sh"
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/pfc_list.sh"

    # Stop PFC
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/pfc_stop.sh ${PROXY_NIC}"
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/pfc_stop.sh ${NODE_NIC}"

    ./topo_cleanup.sh basic.cfg
else
    echo "Topology cleanup..."
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/pfc_delete.sh ${GROUP_ID} ${SERVICE_ID}" > /dev/null
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/pfc_delete.sh ${GROUP_ID} ${SERVICE_ID}" > /dev/null
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/pfc_delete.sh ${GROUP_ID} ${SERVICE_ID2}" > /dev/null
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/pfc_delete.sh ${GROUP_ID} ${SERVICE_ID2}" > /dev/null

    # Stop PFC
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/pfc_stop.sh ${PROXY_NIC}" > /dev/null
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/pfc_stop.sh ${NODE_NIC}" > /dev/null

    ./topo_cleanup.sh basic.cfg > /dev/null
fi

exit ${RETURN}
