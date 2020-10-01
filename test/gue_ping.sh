#!/bin/bash
# syntax: $0 <node> <service-id> <remote-ip> <remote-port> <local-port> <delay>

STEPS=4
TUNNEL_PREFIX="10.2.1."

NODE=$1
SERVICE_ID=$2
REMOTE_IP=$3
REMOTE_PORT=$4
LOCAL_PORT=$5
DELAY=$6

echo "PFC: TUNNEL PING: NODE='${NODE}' SERVICE_ID='${SERVICE_ID}' PROTO='${PROTO}' REMOTE_IP='${REMOTE_IP}' REMOTE_PORT='${REMOTE_PORT}' LOCAL_PORT='${LOCAL_PORT}' DELAY='${DELAY}'"

#echo "docker exec -itd ${NODE} bash -c nping -c0 --delay ${DELAY}s --udp --source-port ${LOCAL_PORT} --dest-port ${REMOTE_PORT} ${REMOTE_IP}"
#docker exec -itd ${NODE} bash -c "sleep 3 ; nping -c0 --delay ${DELAY}s --udp --source-port ${LOCAL_PORT} --dest-port ${REMOTE_PORT} ${REMOTE_IP}"

docker exec -itd ${NODE} bash -c "python3 gue_ping_tun.py eth1 ${DELAY} ${REMOTE_IP} ${REMOTE_PORT} ${LOCAL_PORT} ${SERVICE_ID}"

echo -e "\n==============================================="
echo "# TUNNEL PING: DONE"
