#!/bin/bash
# Setup HTTP service on NODE on same network as EGW, expose it on EGW and send request from CLIENT.
# Attach and configure PFC on NODE and EGW.
# Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
# usage: $0

cd ..

#export VERBOSE="1"

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

NODE="node1"
SERVICE_TYPE="http"
SERVICE_PROTO="tcp"
SERVICE_ID="100"
SERVICE_NAME="foo"
SERVICE_IP="1.1.1.1"
SERVICE_PORT="4000"
PROXY_PORT="3100"
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

DELAY="10"
PROXY_TUN_IP="172.1.0.3"

TUNNEL_ID=${SERVICE_ID}
PROXY_TUN_PORT="6080"
NODE_TUN_PORT="6080"
NODE_TUN_IP="172.1.0.4"

echo "Setup forwarding..."
echo "  ${SERVICE_NAME}"
echo "    Proxy  : ${PROXY}  ${SERVICE_PROTO}:${PROXY_IP}:${PROXY_PORT} -> ${NODE}  ${SERVICE_PROTO}:${SERVICE_IP}:${SERVICE_PORT}"
echo "    Id     : ${SERVICE_ID} -> '${PASSWD}'"
echo "    Tunnel : ${PROXY_TUN_IP}:${PROXY_TUN_PORT} -> ${NODE_TUN_IP}:${NODE_TUN_PORT}"

######## CONFIGURE PROXY ########
### Install & configure PFC (<node> <iface> <role> <mode> ...) ... using $name, ignoring $id
NIC="eth1"

docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin ; ./attach_tc.sh ${NIC}"
# cli_cfg set <idx> <id> <flags> <name>
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set ${NIC} 0 5 11 '${PROXY} RX' && ./cli_cfg set ${NIC} 1 5 11 '${PROXY} TX'"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_cfg get all"
fi

### Setup GUE tunnel from ${NODE} to ${PROXY} (separate (shared tunnel) or combo (one tunnel per service))
# cli_tunnel set <id> <ip-local> <port-local> <ip-remote> <port-remote>
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_tunnel set ${TUNNEL_ID} ${PROXY_TUN_IP} ${PROXY_TUN_PORT} 0 0"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get all"
fi

### Setup service forwarding (separate (shared tunnel) or combo (one tunnel per service))
# cli_service set <service-id> <group-id> <proto> <ip-proxy> <port-proxy> <ip-ep> <port-ep> <tunnel-id> <key>
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_service set 0 ${SERVICE_ID} ${SERVICE_PROTO} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT} ${TUNNEL_ID} ${PASSWD}"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_service get all"
fi

######## CONFIGURE NODE ########
### Install & configure PFC (<node> <iface> <role> <mode> ...)
NIC="eth1"

docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin ; ./attach_tc.sh ${NIC}"
# cli_cfg set <idx> <id> <flags> <name>
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set ${NIC} 0 1 9 '${NODE} RX' && ./cli_cfg set ${NIC} 1 1 8 '${NODE} TX'"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/cli_cfg get all"
fi

### Setup GUE tunnel from ${NODE} to ${PROXY} (separate (shared tunnel) or combo (one tunnel per service))
# cli_tunnel set <id> <ip-local> <port-local> <ip-remote> <port-remote>
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin && ./cli_tunnel set ${TUNNEL_ID} ${NODE_TUN_IP} ${NODE_TUN_PORT} ${PROXY_TUN_IP} ${PROXY_TUN_PORT}"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/cli_tunnel get all"
fi

### Setup service forwarding (separate (shared tunnel) or combo (one tunnel per service))
# cli_service set <service-id> <group-id> <proto> <ip-proxy> <port-proxy> <ip-ep> <port-ep> <tunnel-id> <key>
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin && ./cli_service set 0 ${SERVICE_ID} ${SERVICE_PROTO} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT} ${TUNNEL_ID} ${PASSWD}"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${NODE} bash -c "/tmp/.acnodal/bin/cli_service get all"
fi

docker exec -itd ${NODE} bash -c "python3 /tmp/.acnodal/bin/gue_ping_tun.py ${NIC} ${DELAY} ${PROXY_TUN_IP} ${NODE_TUN_PORT} ${PROXY_TUN_PORT} ${TUNNEL_ID}"

echo "Waiting for GUE ping..."
for (( i=1; i<10; i++ ))
do
    TMP=$(docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get ${SERVICE_ID}" | grep "TUN" | grep ${SERVICE_ID} | grep -v "0.0.0.0:0")
    if [ "${TMP}" ] ; then
        break
    fi
    echo "."
    sleep 1
done

TMP=$(docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get ${SERVICE_ID}" | grep "TUN" | grep ${SERVICE_ID} | grep -v "0.0.0.0:0")
if [ "${TMP}" ] ; then
    echo "GUE Ping RESOLVED: ${TMP}"
else
    echo "GUE Ping FAILED"
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
