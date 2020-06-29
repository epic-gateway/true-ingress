#!/bin/bash
# Setup HTTP service on NODE on same network as EGW, expose it on EGW and send request from CLIENT.
# usage: $0

cd ..

# setup topology
./topo_setup.sh basic.cfg

NODE="node1"
PROXY="egw"
SERVICE="http"
SERVICE_ID="100"
SERVICE_ID2="101"
SERVICE_IP="1.1.1.1"
SERVICE_IP2="1.1.1.2"
SERVICE_PORT="4000"
SERVICE_PORT2="4002"
PROXY_IP="5.5.5.5"
PROXY_PORT="3100"

echo "#######################################################"
echo "# Topology up'n'runnin. Hit <ENTER> to setup service. #"
echo "#######################################################"

read

# setup HTTP service
#                   <node>  <ip>          <port>          <service-id>  <service>
./service_start.sh ${NODE} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_ID} ${SERVICE}
./service_start.sh ${NODE} ${SERVICE_IP2} ${SERVICE_PORT2} ${SERVICE_ID} ${SERVICE}

echo "###########################################################"
echo "# Service up'n'runnin. Hit <ENTER> to check reachability. #"
echo "###########################################################"

read

echo -e "\n### CURL from '${NODE}' to ${SERVICE_IP}:${SERVICE_PORT}"
# syntax: $0     <docker>  <ip>        <port>        <service-id>
./http_check.sh ${NODE} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_ID}

echo -e "\n### CURL from '${NODE}' to ${SERVICE_IP2}:${SERVICE_PORT2}"
./http_check.sh ${NODE} ${SERVICE_IP2} ${SERVICE_PORT2} ${SERVICE_ID}

echo "######################################"
echo "# Test done. Hit <ENTER> to cleanup. #"
echo "######################################"

read

# cleanup topology
./topo_cleanup.sh basic.cfg
