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

#read

# setup HTTP service
#                <node>  <ip>          <port>          <service-id>    <service>
./service_start.sh ${NODE} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_ID} ${SERVICE}

echo "#########################################################"
echo "# Service up'n'runnin. Hit <ENTER> to setup forwarding. #"
echo "#########################################################"

#read

# setup TC forwarding
#                         <service-id>  <node>  <proxy> <proto>  <service-ip>  <service-port>  <proxy-ip>  <proxy-port> [<client>]
./forwarding_tc_setup.sh ${SERVICE_ID} ${NODE} ${PROXY} tcp     ${SERVICE_IP} ${SERVICE_PORT} ${PROXY_IP} ${PROXY_PORT} ${CLIENT}

echo "######################################################"
echo "# Service up'n'runnin. Hit <ENTER> to configure PFC. #"
echo "######################################################"

#read

# create config
# set <idx> <id> <flags> <name>
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set 0 1 9 'NODE1' && ./cli_cfg set 1 1 8 'NODE1' && ./cli_cfg get all"
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set 0 5 11 'EGW' && ./cli_cfg set 1 5 11 'EGW' && ./cli_cfg get all"

# setup tunnel
# set <id> <ip-local> <port-local> <ip-remote> <port-remote>
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin && ./cli_tunnel set ${SERVICE_ID} 172.1.0.4 6080 172.1.0.3 6080 && ./cli_tunnel get all"
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_tunnel set ${SERVICE_ID} 172.1.0.3 6080 0 0 && ./cli_tunnel get all"

# setup service
# set <service-id> <group-id> <proto> <ip-proxy> <port-proxy> <ip-ep> <port-ep> <tunnel-id> <key>
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin && ./cli_service set 2 2 tcp ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_ID} 'Pa55w0rd1234567' && ./cli_service get all"
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_service set 2 2 tcp ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_ID} 'Pa55w0rd1234567' && ./cli_service get all"

echo "############################################"
echo "# PFC configured. Hit <ENTER> to run test. #"
echo "############################################"

#read

# check TABLE_TUNNEL
for i in {1..2}
do
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get all"
#    tail -n20 /sys/kernel/debug/tracing/trace
    echo -e "\n\n"
    sleep 5
done

#echo "########################################"
#echo "# Test done. Hit <ENTER> to detach TC. #"
#echo "########################################"

#read

#docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin ; ./detach_tc.sh eth1"
#docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin ; ./detach_tc.sh eth1"

echo "#################################################"
echo "# TC detached. Hit <ENTER> to cleanup topology. #"
echo "#################################################"

#read

# cleanup topology
./topo_cleanup.sh basic.cfg