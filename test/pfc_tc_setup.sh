#!/bin/bash
# syntax: $0 <node> <service-id> <proto> <service-ip> <service-port> <remote-tunnel-ip> <remote-tunnel-port> <foo-ip>

# 1) setup GUE tunnel
# 2) add routing to the tunnel
# 3) send GUE ping

STEPS=4
TUNNEL_PREFIX="10.2.1."

NODE=$1
SERVICE_ID=$2
PROTO=$3
SERVICE_IP=$4
SERVICE_PORT=$5
# following information should be retrieved later from GUE ping
TUNNEL_REMOTE_IP=$6
#TUNNEL_REMOTE_PORT=${TUNNEL_PORT}
TUNNEL_REMOTE_PORT=$7
FOO_IP=$8

#VERBOSE="1"

if [ "${VERBOSE}" ]; then
    echo -e "\nPFC.TC.ADD : NODE='${NODE}' SERVICE_ID='${SERVICE_ID}' PROTO='${PROTO}' SERVICE_IP='${SERVICE_IP}' SERVICE_PORT='${SERVICE_PORT}' TUNNEL_REMOTE_IP='${TUNNEL_REMOTE_IP}' TUNNEL_REMOTE_PORT='${TUNNEL_REMOTE_PORT}' FOO_IP='${FOO_IP}'"
fi

TUNNEL_PORT=6080

IFNAME="gue${SERVICE_ID}"
CHECK=`docker exec -it ${NODE} bash -c "ip addr" | grep ${IFNAME}`
if [ "${CHECK}" ] ; then
    echo "Service ID ${SERVICE_ID} already exist"
    exit 1
fi

# careful! works only with small numbers
TUNNEL_LOCAL_IP=${TUNNEL_PREFIX}${SERVICE_ID}

echo -e "\n==============================================="
echo "# PFC.TC.ADD [1/${STEPS}] : Create GUE tunnel (${IFNAME}) to ${TUNNEL_REMOTE_IP}:${TUNNEL_REMOTE_PORT})"

docker exec -it ${NODE} bash -c "ip fou add port ${TUNNEL_PORT} gue"
docker exec -it ${NODE} bash -c "ip link add name ${IFNAME} type ipip remote ${TUNNEL_REMOTE_IP} encap gue encap-sport ${TUNNEL_PORT} encap-dport ${TUNNEL_REMOTE_PORT}"

CHECK=`docker exec -it ${NODE} bash -c "ip link" | grep ${IFNAME}`
if [ ! "${CHECK}" ] ; then
    echo "FAILED to create tunnel"
    exit 1
fi

echo -e "\n==============================================="
echo "# PFC.TC.ADD [2/${STEPS}] : Assign IP ${TUNNEL_LOCAL_IP} to ${IFNAME} and bring it up"

docker exec -it ${NODE} bash -c "ip addr add ${TUNNEL_LOCAL_IP}/24 dev ${IFNAME}"
docker exec -it ${NODE} bash -c "ip link set ${IFNAME} up"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${NODE} bash -c "ip addr"
fi

echo -e "\n==============================================="
echo "# PFC.TC.ADD [3/${STEPS}] : Set Route for service ${FOO_IP}/32 via ${IFNAME}"

docker exec -it ${NODE} bash -c "ip route add ${FOO_IP}/32 dev ${IFNAME}"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${NODE} bash -c "ip route"
fi

echo -e "\n==============================================="
echo "# PFC.ADD [4/${STEPS}] : Attach TC to ${IFNAME}"

docker exec -it ${NODE} bash -c "cd /opt/acnodal/bin && ./attach_tc.sh eth1"

# check
#if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${NODE} bash -c "ls -R /sys/fs/bpf/"
#fi

echo -e "\n==============================================="
echo "# PFC.TC.ADD : DONE"
