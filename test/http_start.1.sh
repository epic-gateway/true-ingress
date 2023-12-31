#!/bin/bash
# syntax: $0 <node> <ip> <port> <service-id> <home-dir>
# 1) deploy service on $NODE
# 2) add $SERVICE_IP to loopback of $NODE
# 3) start http server on $NODE listening on $SERVICE_IP:$SERVICE_PORT (tcp)

NODE=$1
NS=$2
IP=$3
PORT=$4
SERVICE_ID=$5
HOME=$5

#VERBOSE="1"

if [ "${VERBOSE}" ]; then
    echo -e "\nHTTP.START: NODE='${NODE}' NETNS='${NS}' IP='${IP}' PORT='${PORT}' SERVICE_ID='${SERVICE_ID}' HOME='${HOME}'"
fi

STEPS=4
DELAY=10

echo -e "\n==============================================="
echo "# HTTP.START [1/${STEPS}] : Create service record in ${HOME}"

docker exec -it ${NODE} bash -c "ip netns exec ${NS} mkdir -p ${HOME}"
docker exec -it ${NODE} bash -c "ip netns exec ${NS} echo -e \"ID=${SERVICE_ID}\nPROTO=tcp\nIP=${IP}\nPORT=${PORT}\nLOG=${HOME}/log\" > ${HOME}/info"
docker exec -it ${NODE} bash -c "ip netns exec ${NS} cat ${HOME}/info"

echo -e "\n==============================================="
echo "# HTTP.START [2/${STEPS}] : Create files in ${HOME}"

docker exec -it ${NODE} bash -c "ip netns exec ${NS} echo -e \"HELLO '${SERVICE_ID}' from '${NODE}' listening on ${IP}:${PORT}\" > ${HOME}/hello"

docker exec -it ${NODE} bash -c "ip netns exec ${NS} dd if=/dev/zero of=${HOME}/data_100M.bin count=100 bs=1048576" > /dev/null 2>&1
docker exec -it ${NODE} bash -c "ip netns exec ${NS} dd if=/dev/zero of=${HOME}/data_50M.bin count=50 bs=1048576" > /dev/null 2>&1
docker exec -it ${NODE} bash -c "ip netns exec ${NS} dd if=/dev/zero of=${HOME}/data_20M.bin count=20 bs=1048576" > /dev/null 2>&1
docker exec -it ${NODE} bash -c "ip netns exec ${NS} dd if=/dev/zero of=${HOME}/data_10M.bin count=10 bs=1048576" > /dev/null 2>&1
docker exec -it ${NODE} bash -c "ip netns exec ${NS} dd if=/dev/zero of=${HOME}/data_5M.bin count=5 bs=1048576" > /dev/null 2>&1
docker exec -it ${NODE} bash -c "ip netns exec ${NS} dd if=/dev/zero of=${HOME}/data_2M.bin count=2 bs=1048576" > /dev/null 2>&1
docker exec -it ${NODE} bash -c "ip netns exec ${NS} dd if=/dev/zero of=${HOME}/data_1M.bin count=1 bs=1048576" > /dev/null 2>&1

echo -e "\n==============================================="
echo "# HTTP.START [3/${STEPS}] : Starting HTTP server ID ${SERVICE_ID} on ${IP}:${PORT}"
# TODO: append PID=... to info file
docker exec -itd ${NODE} bash -c "ip netns exec ${NS} python3 server.py ${IP} ${PORT} ${HOME} &> ${HOME}/log"
docker exec -it ${NODE} bash -c "ip netns exec ${NS} ls ${HOME}"
docker exec -it ${NODE} bash -c "ip netns exec ${NS} ps aux | grep server"

echo -e "\n==============================================="
echo "# HTTP.START [4/${STEPS}] : Wait about ${DELAY} seconds for server going up"
sleep ${DELAY}

echo -e "\n==============================================="
echo "# HTTP.START : DONE"
