#!/bin/bash
# Setup HTTP service on NODE on same network as EGW, expose it on EGW and send request from CLIENT.
# usage: $0

# setup topology
./topo_setup.sh basic.cfg

NODE="node1"
PROXY="egw"
SERVICE_ID="100"
SERVICE_IP="1.1.1.1"
SERVICE_PORT="4000"
PROXY_IP="5.5.5.5"
PROXY_PORT="3100"

echo "#######################################################"
echo "# Topology up'n'runnin. Hit <ENTER> to setup service. #"
echo "#######################################################"

read

# setup HTTP service
#                <node>  <ip>          <port>          <service-id>
./http_start.sh ${NODE} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_ID}

echo "#########################################################"
echo "# Service up'n'runnin. Hit <ENTER> to setup forwarding. #"
echo "#########################################################"

read

# setup forwarding
./forwarding_setup.sh ${SERVICE_ID} ${NODE} ${PROXY} tcp ${SERVICE_IP} ${SERVICE_PORT} ${PROXY_IP} ${PROXY_PORT} client

echo "######################################"
echo "# Test done. Hit <ENTER> to cleanup. #"
echo "######################################"

read

# cleanup topology
./topo_cleanup.sh basic.cfg
