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
    echo -e "\nHTTP.START: NODE='${NODE}' IP='${IP}' PORT='${PORT}' SERVICE_ID='${SERVICE_ID}' HOME='${HOME}'"
fi

STEPS=4
DELAY=10

echo -e "\n==============================================="
echo "# HTTP.START [1/${STEPS}] : Create service record in ${HOME}"

docker exec -it ${NODE} bash -c "echo -e \"ID=${SERVICE_ID}\nPROTO=tcp\nIP=${IP}\nPORT=${PORT}\nLOG=${HOME}/log\" > ${HOME}/info"

echo -e "\n==============================================="
echo "# HTTP.START [2/${STEPS}] : Create files in ${HOME}"

docker exec -it ${NODE} bash -c "echo -e \"HELLO '${SERVICE_ID}' from '${NODE}' listening on ${IP}:${PORT}\" > ${HOME}/hello"

docker exec -it ${NODE} bash -c "dd if=/dev/zero of=${HOME}/data_10M.bin count=10 bs=1048576" > /dev/null 2>&1
docker exec -it ${NODE} bash -c "dd if=/dev/zero of=${HOME}/data_5M.bin count=5 bs=1048576" > /dev/null 2>&1
docker exec -it ${NODE} bash -c "dd if=/dev/zero of=${HOME}/data_2M.bin count=2 bs=1048576" > /dev/null 2>&1
docker exec -it ${NODE} bash -c "dd if=/dev/zero of=${HOME}/data_1M.bin count=1 bs=1048576" > /dev/null 2>&1

echo -e "\n==============================================="
echo "# HTTP.START [3/${STEPS}] : Starting HTTP server ID ${SERVICE_ID} on ${IP}:${PORT}"
# TODO: append PID=... to info file
#docker exec -itd ${NODE} bash -c "python3 /tmp/server.py ${IP} ${PORT} ${HOME} > ${HOME}/log 2>&1"
docker exec -itd ${NODE} bash -c "python3 /tmp/.acnodal/bin/server.py ${IP} ${PORT} ${HOME} &> ${HOME}/log"
#docker exec -it ${NODE} bash -c "nohup python3 /tmp/server.py ${IP} ${PORT} ${HOME} &> ${HOME}/log & echo $!"
#docker exec -it ${NODE} bash -c "nohup python3 /tmp/server.py ${IP} ${PORT} ${HOME} & echo $!"
#docker exec -it ${NODE} bash -c "python /tmp/server.py ${IP} ${PORT} ${HOME}"

echo -e "\n==============================================="
echo "# HTTP.START [4/${STEPS}] : Wait about ${DELAY} seconds for HTTP server going up"
sleep ${DELAY}

echo -e "\n==============================================="
echo "# HTTP.START : DONE"
