#!/bin/bash
# syntax: $0 <node> <ip> <port> <service-id> <service-type>
# 1) deploy service on $NODE
# 2) add $SERVICE_IP to loopback of $NODE
# 3) start http server on $NODE listening on $SERVICE_IP:$SERVICE_PORT (tcp)

NODE=$1
IP=$2
PORT=$3
SERVICE_ID=$4
TYPE=$5

#VERBOSE="1"

if [ "${VERBOSE}" ]; then
    echo -e "\nSERVICE(${SERVICE_ID}).START : NODE='${NODE}' IP='${IP}' PORT='${PORT}' SERVICE_ID='${SERVICE_ID}' TYPE='${TYPE}'"
fi

STEPS=5

. common.cfg

SERVICE_DIR="/tmp"

echo -e "\n==============================================="
echo "# SERVICE(${SERVICE_ID}).START[1/${STEPS}] : Check input"

CHECK=`docker ps | awk '{print $NF}' | grep "${NODE}"`
if [ ! "${CHECK}" ] ; then
    echo "Docker '${NODE}' : NOT running!"
    exit 1
else
    echo "Docker '${NODE}' : OK"
fi

if [ ! -x "./${TYPE}_start.sh" ] ; then
    echo "./${TYPE}_start.sh : NOT available."
    exit 1
else
    echo "./${TYPE}_start.sh : OK"
fi

echo -e "\n==============================================="
echo "# SERVICE(${SERVICE_ID}).START [2/${STEPS}] : Create NS 'service-${SERVICE_ID}'"

./ns_add.sh ${NODE} "service-${SERVICE_ID}" ${IP} ${PORT} br0

echo -e "\n==============================================="
echo "# SERVICE(${SERVICE_ID}).START [4/${STEPS}] : Start service on '${NODE}'"

#                      <node>  <ip>  <port>  <service-id>  <home-dir>
./${TYPE}_start.1.sh ${NODE} "service-${SERVICE_ID}" ${IP} ${PORT} ${SERVICE_ID} ${SERVICE_DIR}/${SERVICE_ID}

if [ -x "./${TYPE}_check.sh" ] ; then
    echo -e "\n==============================================="
    echo "# SERVICE(${SERVICE_ID}).START [5/${STEPS}] : Check service is running"

    #echo -e "\n==============================================="
    #echo -e "\n### CURL from '${NODE}' to ${IP}:${PORT}"
    # syntax: $0     <docker>  <ip>        <port>
    ./${TYPE}_check.sh ${NODE} ${IP} ${PORT} ${SERVICE_ID}
    #./test_curl.sh ${IP} ${PORT} ${NODE}
else
    echo "./${TYPE}_check.sh not awailable for check."
fi

echo -e "\n==============================================="
echo "# SERVICE(${SERVICE_ID}).START : DONE"
