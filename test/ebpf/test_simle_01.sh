#!/bin/bash
# Setup HTTP service on NODE on same network as EGW, expose it on EGW and send request from CLIENT.
# Attach and configure PFC on NODE and EGW.
# Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
# Setup HTTP service and forwarding.
# Send HTTP request from client to *proxy ip:port*.
# usage: $0

cd ..

#export VERBOSE="1"

# setup topology
./topo_setup.sh basic.cfg

echo "#######################################################"
echo "# Topology up'n'runnin. Hit <ENTER> to setup service. #"
echo "#######################################################"

#read

CLIENT="client"
PROXY="egw"
PROXY_IP="5.5.5.5"

NODE="node1"
SERVICE_TYPE="http"
SERVICE_ID="100"
SERVICE_NAME=${SERVICE_ID}
SERVICE_IP="1.1.1.1"
SERVICE_PORT="4000"
PROXY_PORT="3100"
PASSWD='5erv1ceP@55w0rd!'

# setup HTTP service on ${NODE}
#                  <node>  <ip>          <port>          <service-id>  <service>
./service_start.sh ${NODE} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_NAME} ${SERVICE_TYPE}

echo "######################################################"
echo "# Service up'n'runnin. Hit <ENTER> to configure PFC. #"
echo "######################################################"

#read

DELAY="10"
PROXY_TUN_IP="172.1.0.3"

TUNNEL_ID=${SERVICE_ID}
PROXY_TUN_PORT="6080"
NODE_TUN_PORT="6080"
NODE_TUN_IP="172.1.0.4"
EXPEXTED_IP="172.1.0.4"

######## CONFIGURE PROXY ########
### Install & configure PFC (<node> <iface> <role> <mode> ...) ... using $name, ignoring $id
NIC="eth1"

#echo "# EGW.TC.ADD [4/${STEPS}] : Set DNAT (PROXY ${PROXY_IP}:${PROXY_PORT} -> SERVICE ${SERVICE_IP}:${SERVICE_PORT})"
# add real entry (do we care about interfaces??? whitelist/blacklist)
PROTO="tcp"
docker exec -it ${PROXY} bash -c "iptables -t nat -A PREROUTING -p ${PROTO} -i ${NIC} --destination ${PROXY_IP} --dport ${PROXY_PORT} -j DNAT --to-destination ${SERVICE_IP}:${SERVICE_PORT}"
docker exec -it ${PROXY} bash -c "iptables -t nat -A POSTROUTING -p ${PROTO} -o ${NIC} -s ${SERVICE_IP} --sport ${SERVICE_PORT} -j SNAT --to-source ${PROXY_IP}:${PROXY_PORT}"
# check
#docker exec -it ${PROXY} bash -c "iptables -t nat -L PREROUTING -vn --line-numbers"
#docker exec -it ${PROXY} bash -c "iptables -t nat -L POSTROUTING -vn --line-numbers"


docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin ; ./attach_tc.sh ${NIC}"
# cli_cfg set <idx> <id> <flags> <name>
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set ${NIC} 0 5 9 '${PROXY} RX' && ./cli_cfg set ${NIC} 1 5 9 '${PROXY} TX' && ./cli_cfg get all"

### Setup GUE tunnel from ${NODE} to ${PROXY} (separate (shared tunnel) or combo (one tunnel per service))
# cli_tunnel set <id> <ip-local> <port-local> <ip-remote> <port-remote>
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_tunnel set ${TUNNEL_ID} ${PROXY_TUN_IP} ${PROXY_TUN_PORT} 0 0 && ./cli_tunnel get all"

### Setup service forwarding (separate (shared tunnel) or combo (one tunnel per service))
# cli_service set <service-id> <group-id> <proto> <ip-proxy> <port-proxy> <ip-ep> <port-ep> <tunnel-id> <key>
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_service set 0 ${SERVICE_ID} tcp ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT} ${TUNNEL_ID} ${PASSWD} && ./cli_service get all"

######## CONFIGURE NODE ########
### Install & configure PFC (<node> <iface> <role> <mode> ...)
NIC="eth1"
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin ; ./attach_tc.sh ${NIC}"
# cli_cfg set <idx> <id> <flags> <name>
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set ${NIC} 0 1 9 '${NODE} RX' && ./cli_cfg set ${NIC} 1 1 8 '${NODE} TX' && ./cli_cfg get all"

### Setup GUE tunnel from ${NODE} to ${PROXY} (separate (shared tunnel) or combo (one tunnel per service))
# cli_tunnel set <id> <ip-local> <port-local> <ip-remote> <port-remote>
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin && ./cli_tunnel set ${TUNNEL_ID} ${NODE_TUN_IP} ${NODE_TUN_PORT} ${PROXY_TUN_IP} ${PROXY_TUN_PORT} && ./cli_tunnel get all"

### Setup service forwarding (separate (shared tunnel) or combo (one tunnel per service))
# cli_service set <service-id> <group-id> <proto> <ip-proxy> <port-proxy> <ip-ep> <port-ep> <tunnel-id> <key>
docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin && ./cli_service set 0 ${SERVICE_ID} tcp ${PROXY_IP} ${PROXY_PORT} ${SERVICE_IP} ${SERVICE_PORT} ${TUNNEL_ID} ${PASSWD} && ./cli_service get all"

docker exec -itd ${NODE} bash -c "python3 /tmp/.acnodal/bin/gue_ping_svc.py ${NIC} ${DELAY} ${PROXY_TUN_IP} ${NODE_TUN_PORT} ${PROXY_TUN_PORT} ${SERVICE_ID} ${PASSWD}"

#echo "############################################"
#echo "# PFC configured. Hit <ENTER> to run test. #"
#echo "############################################"

#read

# wait for GUE ping resolved
for (( i=1; i<4; i++ ))
do
    TMP=$(docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get ${SERVICE_ID}" | grep ${EXPEXTED_IP})
    if [ "${TMP}" ] ; then
        break
    fi
    sleep 1
done

TMP=$(docker exec -it ${PROXY} bash -c "/tmp/.acnodal/bin/cli_tunnel get ${SERVICE_ID}" | grep ${EXPEXTED_IP})
if [ "${TMP}" ] ; then
    # check traces before
#    tail -n60 /sys/kernel/debug/tracing/trace

    # generate ICMP ECHO REQUEST + RESPONSE packets
    # syntax: $0     <docker>  <ip>        <port>
    ./${SERVICE_TYPE}_check.sh ${CLIENT} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_ID}

    # check traces after
#    tail -n60 /sys/kernel/debug/tracing/trace
fi

#echo "########################################"
#echo "# Test done. Hit <ENTER> to detach TC. #"
#echo "########################################"

#read

#docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin ; ./detach_tc.sh eth1"
#docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin ; ./detach_tc.sh eth1"

#echo "#################################################"
#echo "# TC detached. Hit <ENTER> to cleanup topology. #"
#echo "#################################################"

#read

# cleanup topology
./topo_cleanup.sh basic.cfg
