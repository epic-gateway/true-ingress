#!/bin/bash
# syntax: $0 <node> <ip> <port> <service-id>
# 1) deploy service on $NODE
# 2) add $SERVICE_IP to loopback of $NODE
# 3) start http server on $NODE listening on $SERVICE_IP:$SERVICE_PORT (tcp)

NODE=$1
IP=$2
PORT=$3
SERVICE_ID=$4

LOCATION="/tmp/${SERVICE_ID}"
STEPS=5
DELAY=10

echo -e "\n==============================================="
echo "# HTTP.START: [1/${STEPS}] Docker check"

CHECK=`sudo docker ps | awk '{print $NF}' | grep "${NODE}"`
if [ "${CHECK}" ] ; then
    echo "'${NODE}' : running"
else
    echo "'${NODE}' : NOT running"
    exit 1
fi

echo -e "\n==============================================="
echo "# HTTP.START: [2/${STEPS}] Setup service IP ${IP} on '${NODE}'"
docker exec -it ${NODE} bash -c "ip addr add ${IP} dev lo"
docker exec -it ${NODE} bash -c "ip addr"

echo -e "\n==============================================="
echo "# HTTP.START: [3/${STEPS}] Starting HTTP server ID ${SERVICE_ID} on ${IP}:${PORT}) on '${NODE}'"

docker exec -it ${NODE} bash -c "echo -e \"HELLO\nNODE: ${NODE}\nID: ${SERVICE_ID}\nSERVICE: HTTP server listening on ${IP}:${PORT}\nLOG: ${LOCATION}.log\" > /tmp/hello"

docker exec -it ${NODE} bash -c "dd if=/dev/zero of=/tmp/data_10M.bin count=10 bs=1048576" >/dev/null 2>&1
docker exec -it ${NODE} bash -c "dd if=/dev/zero of=/tmp/data_5M.bin count=5 bs=1048576" >/dev/null 2>&1
docker exec -it ${NODE} bash -c "dd if=/dev/zero of=/tmp/data_2M.bin count=2 bs=1048576" >/dev/null 2>&1
docker exec -it ${NODE} bash -c "dd if=/dev/zero of=/tmp/data_1M.bin count=1 bs=1048576" >/dev/null 2>&1

docker exec -itd ${NODE} bash -c "python /tmp/server.py ${IP} ${PORT} > ${LOCATION}.log 2>&1"

echo -e "\n==============================================="
echo "# HTTP.START: [4/${STEPS}] Wait about ${DELAY} seconds for HTTP server going up"
sleep ${DELAY}

echo -e "\n==============================================="
echo "# HTTP.START: [5/${STEPS}] Check service identity"

echo -e "\n==============================================="
echo -e "\n### CURL from '${NODE}' to ${IP}:${PORT}"
# syntax: $0     <docker>  <ip>        <port>
./http_check.sh ${NODE} ${IP} ${PORT} ${SERVICE_ID}
#./test_curl.sh ${IP} ${PORT} ${NODE}

echo -e "\n==============================================="
echo "# HTTP.START: DONE"
