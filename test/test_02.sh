#!/bin/bash
# Setup HTTP service on NODE behind NAT, expose it on EGW and send request from CLIENT.
# usage: $0

# setup topology
./topo_setup.sh basic.cfg

NODE="node2"
PROXY="egw"
SERVICE="http"
SERVICE_ID="200"
SERVICE_IP="2.2.2.2"
SERVICE_PORT="4000"
PROXY_IP="5.5.5.5"
PROXY_PORT="3200"

echo "#######################################################"
echo "# Topology up'n'runnin. Hit <ENTER> to setup service. #"
echo "#######################################################"

read

# setup HTTP service
#                <node>  <ip>          <port>          <service-id>    <service>
./service_start.sh ${NODE} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_ID} ${SERVICE}

echo "#########################################################"
echo "# Service up'n'runnin. Hit <ENTER> to setup forwarding. #"
echo "#########################################################"

read

# setup forwarding
#                      <service-id>  <node>  <proxy> <proto> <service-ip>  <service-port>  <proxy-ip>  <proxy-port> [<client>]
./forwarding_setup.sh ${SERVICE_ID} ${NODE} ${PROXY} tcp ${SERVICE_IP} ${SERVICE_PORT} ${PROXY_IP} ${PROXY_PORT} client

echo "######################################"
echo "# Test done. Hit <ENTER> to cleanup. #"
echo "######################################"

read

# cleanup topology
./topo_cleanup.sh basic.cfg
