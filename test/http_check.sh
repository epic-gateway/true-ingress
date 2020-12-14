#!/bin/bash
# syntax: $0 <docker> <ip> <port>
# eg: $0 <tcp|udp> <proxy-ip> <proxy-port> <service-ip> <service-port> [<src-port>]

NODE=$1
IP=$2
PORT=$3
SERVICE_ID=$4
if [ $5 ] ; then
    SRC_PORT="--local-port $5"
fi

echo ""
echo "#####################################################"
echo "From '${NODE}' exec 'curl http://${IP}:${PORT}/hello':"
echo ""
docker exec -it ${NODE} bash -c "curl ${SRC_PORT} --connect-timeout 3 ${IP}:${PORT}/hello"
echo "#####################################################"
