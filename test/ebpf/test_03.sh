#!/bin/bash
# Setup HTTP service on NODE on same network as EGW, expose it on EGW and send request from CLIENT.
# Load eBPF on NODE and EGW and check tracefile.
# usage: $0

cd ..

# setup topology
./topo_setup.sh basic.cfg

CLIENT="client"
NODE="node1"
PROXY="egw"
SERVICE="http"
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
#                <node>  <ip>          <port>          <service-id>    <service>
./service_start.sh ${NODE} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_ID} ${SERVICE}

echo "#########################################################"
echo "# Service up'n'runnin. Hit <ENTER> to setup forwarding. #"
echo "#########################################################"

read

# setup TC forwarding
#                         <service-id>  <node>  <proxy> <proto>  <service-ip>  <service-port>  <proxy-ip>  <proxy-port> [<client>]
./forwarding_tc_setup.sh ${SERVICE_ID} ${NODE} ${PROXY} tcp     ${SERVICE_IP} ${SERVICE_PORT} ${PROXY_IP} ${PROXY_PORT} ${CLIENT}

echo "#################################################"
echo "# Service up'n'runnin. Hit <ENTER> to run test. #"
echo "#################################################"

read

# check traces before
tail -n60 /sys/kernel/debug/tracing/trace

# generate ICMP ECHO REQUEST + RESPONSE packets
# syntax: $0     <docker>  <ip>        <port>
./${SERVICE}_check.sh ${CLIENT} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_ID}

# check traces after
tail -n60 /sys/kernel/debug/tracing/trace

#echo "########################################"
#echo "# Test done. Hit <ENTER> to detach TC. #"
#echo "########################################"

#read

#docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin ; ./detach_tc.sh eth1"
#docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin ; ./detach_tc.sh eth1"

echo "#################################################"
echo "# TC detached. Hit <ENTER> to cleanup topology. #"
echo "#################################################"

read
# cleanup topology
./topo_cleanup.sh basic.cfg
