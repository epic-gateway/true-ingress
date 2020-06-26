#!/bin/bash
# syntax: $0 <docker> <ip> <port>
# eg: $0 <tcp|udp> <proxy-ip> <proxy-port> <service-ip> <service-port> <service-id>

NODE=$1
IP=$2
PORT=$3
SERVICE_ID=$4

#echo "CURL: NODE='${NODE}' IP='${IP}' PORT='${PORT}'"

#CMD="docker exec -it ${NODE} bash -c \"curl ${IP}:${PORT}/tmp/hello\""
echo "#####################################################"
#echo "docker exec -it ${NODE} bash -c curl --connect-timeout 3 ${IP}:${PORT}/tmp/hello"
docker exec -it ${NODE} bash -c "curl --connect-timeout 3 ${IP}:${PORT}/tmp/hello"
echo "#####################################################"
#echo "LOG (/tmp/${SERVICE_ID}.log):"
#docker exec -it ${NODE} bash -c "curl --connect-timeout 3 ${IP}:${PORT}/tmp/${SERVICE_ID}.log"
#echo "#####################################################"
