#!/bin/bash
# syntax: $0 <service-id> <node> <proxy> <proto> <service-ip> <service-port> <proxy-ip> <proxy-port> <tunnel> [<client>] [<passwd>]
# 1) setup EGW on $PROXY
# 2) setup PFC on $NODE

while getopts "nr" opt; do
    case "$opt" in
    n)  NAT="x"
        shift
        ;;
    r)  RESOLVE=1
        shift
        ;;
    esac
done

SERVICE_ID=$1
NODE=$2
PROXY=$3
PROTO=$4
SERVICE_IP=$5
SERVICE_PORT=$6
PROXY_IP=$7
PROXY_PORT=$8
CLIENT=$9
PASSWD=${10}

#VERBOSE="1"

if [ "${VERBOSE}" ]; then
    echo -e "\nFORWARDING.TC.ADD : SERVICE_ID='${SERVICE_ID}' NODE='${NODE}' PROXY='${PROXY}' PROTO='${PROTO}' SERVICE_IP='${SERVICE_IP}' SERVICE_PORT='${SERVICE_PORT}' PROXY_IP='${PROXY_IP}' PROXY_PORT='${PROXY_PORT}' CLIENT='${CLIENT}' PASSWD='${PASSWD}'"
fi

STEPS=7
TUNNEL_PREFIX="10.1.1."
TUNNEL_PORT=6080
DELAY=10

DEFAULT_ROUTE=`docker exec -it ${PROXY} bash -c "ip addr" | grep "eth1" | grep inet | awk '{print $2}' | sed 's/\/16//g'`
PROXY_IFIP=`docker exec -it ${PROXY} bash -c "ip addr" | grep "eth1" | grep inet | awk '{print $2}' | sed 's/\/16//g'`
NODE_IP=`docker exec -it ${NODE} bash -c "ip addr" | grep "eth1" | grep inet | awk '{print $2}' | sed 's/\/16//g'`
FOO_IP=${TUNNEL_PREFIX}${SERVICE_ID}

echo "DEFAULT_ROUTE : [${DEFAULT_ROUTE}]"
echo "PROXY_IP      : [${PROXY_IP}]"
echo "TUNNEL_PORT   : [${TUNNEL_PORT}]"
echo "FOO_IP        : [${FOO_IP}]"

echo -e "\n==============================================="
echo "# FORWARDING.TC.ADD [1/${STEPS}] : Docker check"

CHECK=`docker ps | awk '{print $NF}' | grep "${NODE}"`
if [ "${CHECK}" ] ; then
    echo "'${NODE}' : running"
else
    echo "'${NODE}' : NOT running"
    exit 1
fi

CHECK=`docker ps | awk '{print $NF}' | grep "${PROXY}"`
if [ "${CHECK}" ] ; then
    echo "'${PROXY}' : running"
else
    echo "'${PROXY}' : NOT running"
    exit 1
fi

echo -e "\n==============================================="
echo "# FORWARDING.TC.ADD [2/${STEPS}] : Reachability check"

echo -e "\n### Ping '${NODE}' -> '${PROXY_IFIP}'"
docker exec -it ${NODE} bash -c "ping -c3 ${PROXY_IFIP}"
echo -e "\n### Ping '${PROXY}' -> '${NODE_IP}'"
docker exec -it ${PROXY} bash -c "ping -c3 ${NODE_IP}"

echo -e "\n==============================================="
echo "# FORWARDING.TC.ADD [3/${STEPS}] : Start GUE ping (in background) for service ID ${SERVICE_ID} every ${DELAY} seconds"
# syntax:  $0  <node>  <service-id>  <remote-ip>   <remote-port>  <local-ip>     <delay>
#./gue_ping.sh ${NODE} ${SERVICE_ID} ${PROXY_IFIP} ${TUNNEL_PORT} ${TUNNEL_PORT} ${DELAY}
if [ ! "${PASSWD}" ] ; then
    echo "Starting gue_ping_tun.py ..."
    docker exec -itd ${NODE} bash -c "python3 gue_ping_tun.py eth1 ${DELAY} ${PROXY_IFIP} ${TUNNEL_PORT} ${TUNNEL_PORT} ${SERVICE_ID}"
else
    echo "Starting gue_ping_svc.py ..."
    docker exec -itd ${NODE} bash -c "python3 gue_ping_svc.py eth1 ${DELAY} ${PROXY_IFIP} ${TUNNEL_PORT} ${TUNNEL_PORT} ${SERVICE_ID} ${PASSWD}"
fi

if [ ! ${RESOLVE} ] ; then
    echo -e "\n==============================================="
    echo "# FORWARDING.TC.ADD [4/${STEPS}] (FAKE) Early NAT address resolution (Waiting for GUE ping)"
    CHECK=`docker exec -it egw bash -c "tcpdump -ns 0 -c1 -i eth1 'udp and host ${PROXY_IFIP} and port ${TUNNEL_PORT}'" | grep "UDP" | awk '{print $3}' | sed -e 's/.\([^.]*\)$/ \1/'`
    echo "${CHECK}"
    REAL_IP=`echo "${CHECK}" | awk '{print $1}'`
    REAL_PORT=`echo "${CHECK}" | awk '{print $2}'`
    echo "REAL_IP       : [${REAL_IP}]"
    echo "REAL_PORT     : [${REAL_PORT}]"
fi

echo -e "\n==============================================="
echo "# FORWARDING.TC.ADD [5/${STEPS}] : Configure EGW on '${PROXY}'"
# syntax:  $0  <node>   <service-id>  <proto>  <service-ip>  <service-port>  <real-ip>  <real-port>  <proxy-ip>  <proxy-port>  <foo-ip>
./egw_tc_setup.sh ${PROXY} ${SERVICE_ID} ${PROTO} ${SERVICE_IP} ${SERVICE_PORT} ${REAL_IP} ${REAL_PORT} ${PROXY_IP} ${PROXY_PORT} ${FOO_IP} ${NAT}
# here should we receive EGW response
#PROXY_IP=$7
#PROXY_PORT=$8

echo -e "\n==============================================="
echo "# FORWARDING.TC.ADD [6/${STEPS}] : Configure PFC on '${NODE}'"
# syntax:  $0  <node>  <service-id>  <proto>  <service-ip>  <service-port>  <tunnel-ip>   <tunnel-port>  <foo-ip>
./pfc_tc_setup.sh ${NODE} ${SERVICE_ID} ${PROTO} ${SERVICE_IP} ${SERVICE_PORT} ${PROXY_IFIP} ${TUNNEL_PORT} ${FOO_IP}

echo -e "\n==============================================="
echo "# FORWARDING.TC.ADD [7/${STEPS}] : CHECK:"
echo -e "\n### ping '${PROXY}' -> ${SERVICE_IP}"
docker exec -it ${PROXY} bash -c "ping -c3 ${SERVICE_IP}"

if [ "${CLIENT}" ] ; then
    CHECK=`docker ps | awk '{print $NF}' | grep "${CLIENT}"`
    if [ "${CHECK}" ] ; then
        echo "'${CLIENT}' : running"
    else
        echo "'${CLIENT}' : NOT running"
        exit 1
    fi

    echo -e "\n==============================================="
    echo -e "\n### PING '${CLIENT}' -> ${PROXY_IP}"
    
    docker exec -it ${CLIENT} bash -c "ping -c3 ${PROXY_IP}"

    echo -e "\n==============================================="
    echo -e "\n### CURL from '${CLIENT}' to ${PROXY_IP}:${PROXY_PORT}"
    # syntax: $0     <docker>  <ip>        <port>        <service-id>
    ./http_check.sh ${CLIENT} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_ID}
fi

echo -e "\n==============================================="
echo "# FORWARDING.TC.ADD : DONE"
