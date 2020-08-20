#!/bin/bash
# Setup HTTP service on NODE behind NAT, expose it on EGW and send request from CLIENT.
# Attach and configure PFC on NODE and EGW.
# Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
# Setup HTTP service and forwarding.
# Send HTTP request from client to *proxy ip:port*.
# usage: $0 [-v|-V]

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

# setup topology
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
PASSWD='5erv1ceP@55w0rd!'

# setup HTTP service on ${NODE}
#                  <node>  <ip>          <port>          <service-id>  <service>
if [ "${VERBOSE}" ]; then
    ./service_start.sh ${NODE} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_NAME} ${SERVICE_TYPE}
else
    echo "Starting service(s)..."
    echo "  ${SERVICE_NAME}"
    echo "    Location '${NODE}', Type '${SERVICE_TYPE}', Endpoint '${SERVICE_PROTO}:${SERVICE_IP}:${SERVICE_PORT}'"
    ./service_start.sh ${NODE} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_NAME} ${SERVICE_TYPE} > /dev/null
fi

DELAY=10
PROXY_TUN_IP="172.1.0.3"

TUNNEL_ID=${GROUP_ID}
((TUNNEL_ID <<= 16))
((TUNNEL_ID += ${SERVICE_ID}))

PROXY_TUN_PORT="6080"
NODE_TUN_PORT="6080"
NODE_TUN_IP="172.2.0.3"

echo "Setup forwarding..."
echo "  ${SERVICE_NAME}"
echo "    Proxy   : ${PROXY}  ${SERVICE_PROTO}:${PROXY_IP}:${PROXY_PORT} -> ${NODE}  ${SERVICE_PROTO}:${SERVICE_IP}:${SERVICE_PORT}"
echo "    Service : (${GROUP_ID},${SERVICE_ID}) -> '${PASSWD}'"
echo "    Tunnel  : ${TUNNEL_ID} (${PROXY_TUN_IP}:${PROXY_TUN_PORT} -> ${NODE_TUN_IP}:${NODE_TUN_PORT})"

######## CONFIGURE PROXY ########
### Install & configure PFC (<node> <iface> <role> <mode> ...) ... using $name, ignoring $id
NIC="eth1"

docker exec -it ${PROXY} bash -c "iptables -t nat -A PREROUTING -p ${SERVICE_PROTO} -i ${NIC} --destination ${PROXY_IP} --dport ${PROXY_PORT} -j DNAT --to-destination ${SERVICE_IP}:${SERVICE_PORT}"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${PROXY} bash -c "iptables -t nat -L PREROUTING -vn --line-numbers"
fi

docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/attach_tc.sh ${NIC}"
# cli_cfg set <idx> <id> <flags> <name>
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set ${NIC} 0 5 9 '${PROXY} RX' && ./cli_cfg set ${NIC} 1 5 9 '${PROXY} TX'"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_cfg get all"
fi

### Setup GUE tunnel from ${NODE} to ${PROXY} (separate (shared tunnel) or combo (one tunnel per service))
# cli_tunnel set <id> <ip-local> <port-local> <ip-remote> <port-remote>
docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel set ${TUNNEL_ID} ${PROXY_TUN_IP} ${PROXY_TUN_PORT} 0 0"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get all"
fi

### Setup service forwarding (separate (shared tunnel) or combo (one tunnel per service))
# cli_service set <service-id> <group-id> <proto> <ip-proxy> <port-proxy> <ip-ep> <port-ep> <tunnel-id> <key>
docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_service set ${GROUP_ID} ${SERVICE_ID} ${SERVICE_PROTO} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT} ${TUNNEL_ID} ${PASSWD}"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_service get all"
fi

######## CONFIGURE NODE ########
### Install & configure PFC (<node> <iface> <role> <mode> ...)
NIC="eth1"

#docker exec -it ${NODE} bash -c "iptables -t nat -A POSTROUTING -p ${PROTO} -o ${NIC} -s ${SERVICE_IP} --sport ${SERVICE_PORT} -j SNAT --to-source ${PROXY_IP}:${PROXY_PORT}"
# check
#if [ "${VERBOSE}" ]; then
#    echo ""
#    docker exec -it ${NODE} bash -c "iptables -t nat -L POSTROUTING -vn --line-numbers"
#fi

docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/attach_tc.sh ${NIC}"
# cli_cfg set <idx> <id> <flags> <name>
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set ${NIC} 0 2 9 '${NODE} RX' && ./cli_cfg set ${NIC} 1 2 10 '${NODE} TX'"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/cli_cfg get all"
fi

docker exec -itd ${NODE} bash -c "python3 /tmp/.acnodal/bin/gue_ping_svc_auto.py ${DELAY} &> /tmp/gue_ping.log"

### Setup GUE tunnel from ${NODE} to ${PROXY} (separate (shared tunnel) or combo (one tunnel per service))
# cli_tunnel set <id> <ip-local> <port-local> <ip-remote> <port-remote>
docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/cli_tunnel set ${TUNNEL_ID} ${NODE_TUN_IP} ${NODE_TUN_PORT} ${PROXY_TUN_IP} ${PROXY_TUN_PORT}"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/cli_tunnel get all"
fi

### Setup service forwarding (separate (shared tunnel) or combo (one tunnel per service))
# cli_service set <service-id> <group-id> <proto> <ip-proxy> <port-proxy> <ip-ep> <port-ep> <tunnel-id> <key>
docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/cli_service set ${GROUP_ID} ${SERVICE_ID} ${SERVICE_PROTO} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT} ${TUNNEL_ID} ${PASSWD}"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/cli_service get all"
fi

docker exec -it ${NODE} bash -c "python3 /tmp/.acnodal/bin/gue_ping_svc_once.py ${NIC} ${PROXY_TUN_IP} ${PROXY_TUN_PORT} ${NODE_TUN_PORT} ${GROUP_ID} ${SERVICE_ID} ${PASSWD}"

echo "Waiting for GUE ping..."
for (( i=1; i<10; i++ ))
do
    if [ "$(docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get ${TUNNEL_ID}" | grep "TUN" | grep ${TUNNEL_ID} | grep -v "0.0.0.0:0")" ] ; then
        break
    fi
    echo "."
    sleep 1
done

if [ ! "$(docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get ${TUNNEL_ID}" | grep "TUN" | grep ${TUNNEL_ID} | grep -v "0.0.0.0:0")" ] ; then
    echo -e "\nGUE Ping for '${SERVICE_NAME}' \e[31mFAILED\e[0m\n"
    RETURN=1
else
    # check traces before
#    tail -n60 /sys/kernel/debug/tracing/trace

    # generate ICMP ECHO REQUEST + RESPONSE packets
    # syntax: $0     <docker>  <ip>        <port>
    if [ "$(./${SERVICE_TYPE}_check.sh ${CLIENT} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_ID} | grep ${SERVICE_NAME})" ] ; then
        echo -e "\nService '${SERVICE_NAME}' : \e[32mPASS\e[0m\n"
    else
        echo -e "\nService '${SERVICE_NAME}' : \e[31mFAILED\e[0m\n"
        RETURN=1
    fi

    # check traces after
#    tail -n60 /sys/kernel/debug/tracing/trace
fi

#docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/detach_tc.sh eth1"
#docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/detach_tc.sh eth1"

# cleanup topology
if [ "${VERBOSE}" ]; then
    ./topo_cleanup.sh basic.cfg
else
    echo "Topology cleanup..."
    ./topo_cleanup.sh basic.cfg > /dev/null
fi

exit ${RETURN}