#!/bin/bash
# syntax: $0 <node> <ip> <port> <service-id> <home-dir>
# 1) deploy service on $NODE
# 2) add $SERVICE_IP to loopback of $NODE
# 3) start http server on $NODE listening on $SERVICE_IP:$SERVICE_PORT (tcp)

NODE=$1
IP=$2
PORT=$3
SERVICE_ID=$4
HOME=$5

#VERBOSE="1"

if [ "${VERBOSE}" ]; then
    echo -e "\nUDP.START: NODE='${NODE}' IP='${IP}' PORT='${PORT}' SERVICE_ID='${SERVICE_ID}' HOME='${HOME}'"
fi

STEPS=4
DELAY=1

echo -e "\n==============================================="
echo "# UDP.START [1/${STEPS}] : Create service record in ${HOME}"

docker exec -it ${NODE} bash -c "echo -e \"ID=${SERVICE_ID}\nPROTO=udp\nIP=${IP}\nPORT=${PORT}\nLOG=${HOME}/log\" > ${HOME}/info"

echo -e "\n==============================================="
echo "# UDP.START [2/${STEPS}] : Create files in ${HOME}"

docker exec -it ${NODE} bash -c "echo -e \"HELLO '${SERVICE_ID}' from '${NODE}' listening on ${IP}:${PORT}\" > ${HOME}/hello"

docker exec -it ${NODE} bash -c "dd if=/dev/zero of=${HOME}/data_10M.bin count=10 bs=1048576" > /dev/null 2>&1
docker exec -it ${NODE} bash -c "dd if=/dev/zero of=${HOME}/data_5M.bin count=5 bs=1048576" > /dev/null 2>&1
docker exec -it ${NODE} bash -c "dd if=/dev/zero of=${HOME}/data_2M.bin count=2 bs=1048576" > /dev/null 2>&1
docker exec -it ${NODE} bash -c "dd if=/dev/zero of=${HOME}/data_1M.bin count=1 bs=1048576" > /dev/null 2>&1

echo -e "\n==============================================="
echo "# UDP.START [3/${STEPS}] : Starting HTTP server ID ${SERVICE_ID} on ${IP}:${PORT}"
# TODO: append PID=... to info file
docker exec -itd ${NODE} bash -c "python3 udp_server.py ${IP} ${PORT} ${HOME} 4096 &> ${HOME}/log"

echo -e "\n==============================================="
echo "# UDP.START [4/${STEPS}] : Wait about ${DELAY} seconds for server going up"
sleep ${DELAY}

echo -e "\n==============================================="
echo "# HTTP.START : DONE"
