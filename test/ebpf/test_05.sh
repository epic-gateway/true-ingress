#!/bin/bash
# Setup HTTP service on NODE on same network as EGW, expose it on EGW and send request from CLIENT.
# Attach and configure PFC on NODE and EGW.
# Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
# usage: $0

cd ..

CLIENT="client"
NODE="node1"
PROXY="egw"
SERVICE_TYPE="http"
SERVICE_ID="100"
SERVICE_IP="1.1.1.1"
SERVICE_PORT="4000"
PROXY_IP="5.5.5.5"
PROXY_PORT="3100"
PASSWD='5erv1ceP@55w0rd!'

#export VERBOSE="1"

# setup topology
./topo_setup.sh basic.cfg

echo "#######################################################"
echo "# Topology up'n'runnin. Hit <ENTER> to setup service. #"
echo "#######################################################"

#read

# setup HTTP service on ${NODE}
#                  <node>  <ip>          <port>          <service-id>  <service>
./service_start.sh ${NODE} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_ID} ${SERVICE_TYPE}

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

# configure PFC instances operation mode
# cli_cfg set <idx> <id> <flags> <name>
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set eth1 0 1 9 'NODE1 RX' && ./cli_cfg set eth1 1 1 8 'NODE1 TX' && ./cli_cfg get all"
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set eth1 0 5 9 'EGW RX' && ./cli_cfg set eth1 1 5 9 'EGW TX' && ./cli_cfg get all"

# configure GUE tunnel from ${NODE} to ${PROXY}
# cli_tunnel set <id> <ip-local> <port-local> <ip-remote> <port-remote>
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin && ./cli_tunnel set ${SERVICE_ID} 172.1.0.4 6080 172.1.0.3 6080 && ./cli_tunnel get all"
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_tunnel set ${SERVICE_ID} 172.1.0.3 6080 0 0 && ./cli_tunnel get all"

# configure service forwarding
# cli_service set <service-id> <group-id> <proto> <ip-proxy> <port-proxy> <ip-ep> <port-ep> <tunnel-id> <key>
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin && ./cli_service set 2 2 tcp ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_ID} ${PASSWD} && ./cli_service get all"
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_service set 2 2 tcp ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_ID} ${PASSWD} && ./cli_service get all"

echo "############################################"
echo "# PFC configured. Hit <ENTER> to run test. #"
echo "############################################"

#read

# check TABLE_TUNNEL
docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get all"
echo -e "\n\n"

for i in {1..1}
do
    sleep 10
    docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get all"
#    tail -n20 /sys/kernel/debug/tracing/trace
    echo -e "\n\n"
done

#echo "########################################"
#echo "# Test done. Hit <ENTER> to detach TC. #"
#echo "########################################"

#read

docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin ; ./detach_tc.sh eth1"
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin ; ./detach_tc.sh eth1"

echo "#################################################"
echo "# TC detached. Hit <ENTER> to cleanup topology. #"
echo "#################################################"

#read

# cleanup topology
./topo_cleanup.sh basic.cfg
