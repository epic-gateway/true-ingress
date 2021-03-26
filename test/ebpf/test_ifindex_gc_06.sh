#!/bin/bash
# Setup HTTP service on NODE on same network as EPIC, expose it on EPIC and send request from CLIENT.
# Attach and configure PFC on NODE and EPIC.
# Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
# Setup HTTP service and forwarding.
# Send HTTP request from client to *proxy ip:port*.
# usage: $0 [-v|-V]

#set -Eeo pipefail

# parse args
while getopts "vV" opt; do
    case "$opt" in
    v)  VERBOSE=1
        shift
        ;;
    V)  export VERBOSE=1
        shift
        ;;
    esac
done

cd ..

RETURN=0
TOPO=basic.cfg

# INFRA >>>> setup topology
./topo_setup.sh ${TOPO}
# <<<<

# TEST CONFIG >>>>
CLIENT="client"
GROUP_ID=1

PROXY="epic"
PROXY_NS="proxy1"
PROXY_IP="5.5.5.5"

NODE="node1"
SERVICE_TYPE="http"
SERVICE_PROTO="tcp"
SERVICE_ID="100"
SERVICE_NAME="foo"
SERVICE_IP="1.1.1.1"
SERVICE_PORT="4000"
PROXY_PORT="3100"
PASSWD='5erv1ceP@55w0rd!'

PROXY_PORT_MIN=5000
PROXY_PORT_MAX=5010
NODE_PORT_MIN=6000
NODE_PORT_MAX=6010

PROXY_NIC="eth1"
NODE_NIC="eth1"
DELAY=100
SWEEP_DELAY=2
SWEEP_COUNT=5
# <<<<

#set -x


# PFC >>>> Attach PFC to eth on EPIC
if [ ! "$(docker exec -it ${PROXY} bash -c \"tc qdisc show dev ${PROXY_NIC} | grep clsact\")" ]; then
    docker exec -it ${PROXY} bash -c "sudo tc qdisc add dev ${PROXY_NIC} clsact"
fi
docker exec -it ${PROXY} bash -c "tc filter add dev ${PROXY_NIC} ingress bpf direct-action object-file pfc_decap_tc.o sec .text"

docker exec -it ${PROXY} bash -c "cli_cfg set ${PROXY_NIC} 0 0 9 \"${PROXY}-ETH RX\""

docker exec -it ${PROXY} bash -c "port_init.sh ${PROXY_PORT_MIN} ${PROXY_PORT_MAX}"
# <<<<


# PFC >>>> Attach PFC to br on EPIC
DEFAULT_IFINDEX=$(docker exec -it ${PROXY} bash -c "ip link show ${PROXY_NIC}" | grep mtu | awk '{print $1}' | sed 's/://')
echo "[${DEFAULT_IFINDEX}]"

if [ ! "$(docker exec -it ${PROXY} bash -c \"tc qdisc show dev br0 | grep clsact\")" ]; then
    docker exec -it ${PROXY} bash -c "sudo tc qdisc add dev br0 clsact"
fi
docker exec -it ${PROXY} bash -c "tc filter add dev br0 ingress bpf direct-action object-file pfc_encap_tc.o sec .text"

docker exec -it ${PROXY} bash -c "cli_cfg set br0 1 ${DEFAULT_IFINDEX} 9 'EPIC-BR-R RX'"
# <<<<

# DEBUG >>>>
docker exec -it ${PROXY} bash -c "show_tc.sh ; cli_cfg get all"
# <<<<


# PFC >>>> Attach PFC to eth on NODE
docker exec -itd ${NODE} bash -c "gue_ping_svc_auto ${DELAY} ${SWEEP_DELAY} ${SWEEP_COUNT} &> /tmp/gue_ping.log"

if [ ! "$(docker exec -it ${NODE} bash -c \"tc qdisc show dev ${NODE_NIC} | grep clsact\")" ]; then
    docker exec -it ${NODE} bash -c "sudo tc qdisc add dev ${NODE_NIC} clsact"
fi
docker exec -it ${NODE} bash -c "tc filter add dev ${NODE_NIC} ingress bpf direct-action object-file pfc_decap_tc.o sec .text"
docker exec -it ${NODE} bash -c "tc filter add dev ${NODE_NIC} egress bpf direct-action object-file pfc_encap_tc.o sec .text"

docker exec -it ${NODE} bash -c "cli_cfg set ${NODE_NIC} 0 0 9 \"${NODE} RX\""
docker exec -it ${NODE} bash -c "cli_cfg set ${NODE_NIC} 1 0 8 \"${NODE} TX\""

docker exec -it ${NODE} bash -c "port_init.sh ${NODE_PORT_MIN} ${NODE_PORT_MAX}"
# <<<<

# DEBUG >>>>
docker exec -it ${PROXY} bash -c "show_tc.sh ; cli_cfg get all"
# <<<<

# INFRA >>>> Setup HTTP service on ${NODE}
if [ "${VERBOSE}" ]; then
    # service_start.sh  <node>  <ip>          <port>          <service-id>   <service>
    ./service_start.sh ${NODE} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_NAME} ${SERVICE_TYPE}
else
    echo "Starting service(s)..."
    echo "  ${SERVICE_NAME}"
    echo "    Location '${NODE}', Type '${SERVICE_TYPE}', Endpoint '${SERVICE_PROTO}:${SERVICE_IP}:${SERVICE_PORT}'"
    ./service_start.sh ${NODE} ${SERVICE_IP} ${SERVICE_PORT} ${SERVICE_NAME} ${SERVICE_TYPE} > /dev/null
fi
# <<<<

# get epic interface IP
PROXY_TUN_IP=$(docker exec -it ${PROXY} bash -c "ip addr show dev ${PROXY_NIC}" | grep inet | awk '{print $2}' | sed 's/\// /g' | awk '{print $1}')
# get epic interface IP
NODE_TUN_IP=$(docker exec -it ${NODE} bash -c "ip addr show dev ${NODE_NIC}" | grep inet | awk '{print $2}' | sed 's/\// /g' | awk '{print $1}')
# compute tunnel-id as group-id "+" servie-id
TUNNEL_ID=${GROUP_ID}
((TUNNEL_ID <<= 16))
((TUNNEL_ID += ${SERVICE_ID}))

PROXY_TUN_PORT=$(docker exec -it ${PROXY} bash -c "port_alloc.sh")
NODE_TUN_PORT=$(docker exec -it ${NODE} bash -c "port_alloc.sh")

echo "[${TUNNEL_ID}]"
echo "[${PROXY_TUN_IP}]"
echo "[${PROXY_TUN_PORT}]"
echo "[${NODE_TUN_IP}]"
echo "[${NODE_TUN_PORT}]"

# INFRA >>>> Setup PROXY NS1 -> create namespace, attach veth1, add it to bridge, assign public ip 5.5.5.5
./ns_add.sh ${PROXY} "proxy1" ${PROXY_IP} 1 br0
# <<<<

# PFC >>>> attach TAGging BPF to veth ingress
docker exec -it ${PROXY} bash -c "sudo tc qdisc add dev veth1 clsact"
docker exec -it ${PROXY} bash -c "tc filter add dev veth1 ingress bpf direct-action object-file pfc_tag_rx_tc.o sec .text"
# <<<<

# Configure forwarding
PROXY_IFINDEX=$(docker exec -it ${PROXY} bash -c "ip link show veth1" | grep mtu | awk '{print $1}' | sed 's/://')

echo "Setup forwarding..."
echo "  ${SERVICE_NAME}"
echo "    Proxy   : ${PROXY}  ${SERVICE_PROTO}:${PROXY_IP}:${PROXY_PORT} (proxy container ifindex ${PROXY_IFINDEX}) -> ${NODE}  ${SERVICE_PROTO}:${SERVICE_IP}:${SERVICE_PORT}"
echo "    Service : (${GROUP_ID},${SERVICE_ID}) -> '${PASSWD}'"
echo "    Tunnel  : ${TUNNEL_ID} (${PROXY_TUN_IP}:${PROXY_TUN_PORT} -> ${NODE_TUN_IP}:${NODE_TUN_PORT})"

# DEBUG: >>>>
docker exec -it ${PROXY} bash -c "ip netns list"
docker exec -it ${PROXY} bash -c "brctl show"
docker exec -it ${PROXY} bash -c "show_tc.sh"

docker exec -it ${PROXY} bash -c "ip route"
docker exec -it ${PROXY} bash -c "ip netns exec ${PROXY_NS} ip route"
docker exec -it ${PROXY} bash -c "ip netns exec ${PROXY_NS} ping -c1 172.1.0.3"
docker exec -it ${PROXY} bash -c "ip netns exec ${PROXY_NS} ping -c1 172.1.0.4"
docker exec -it ${PROXY} bash -c "ip netns exec ${PROXY_NS} ping -c1 1.1.1.1"
# <<<<

# INFRA >>>> Configure NAT in proxy namespace
docker exec -it ${PROXY} bash -c "ip netns exec ${PROXY_NS} iptables -t nat -A PREROUTING -p ${SERVICE_PROTO} -i vethns1 --destination ${PROXY_IP} --dport ${PROXY_PORT} -j DNAT --to-destination ${SERVICE_IP}:${SERVICE_PORT}"
docker exec -it ${PROXY} bash -c "ip netns exec ${PROXY_NS} iptables -t nat -A POSTROUTING -p ${SERVICE_PROTO} -o vethns1 -s ${SERVICE_IP} --sport ${SERVICE_PORT} -j SNAT --to-source ${PROXY_IP}:${PROXY_PORT}"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${PROXY} bash -c "ip netns exec ${PROXY_NS} iptables -t nat -L PREROUTING -vn --line-numbers"
fi
# <<<<

# pfc_add.sh     <nic> <group-id> <service-id> <passwd> <remote-tunnel-ip> <remote-tunnel-port> <proto> <proxy-ip> <proxy-port> <backend-ip> <backend-port>
docker exec -it ${PROXY} bash -c "cli_tunnel set ${TUNNEL_ID} ${PROXY_TUN_IP} ${PROXY_TUN_PORT} 0 0"
docker exec -it ${PROXY} bash -c "cli_service set-gw ${GROUP_ID} ${SERVICE_ID} ${PASSWD} ${TUNNEL_ID} ${SERVICE_PROTO} ${SERVICE_IP} ${SERVICE_PORT} ${PROXY_IFINDEX}"

docker exec -it ${NODE} bash -c "cli_tunnel set ${TUNNEL_ID} ${NODE_TUN_IP} ${NODE_TUN_PORT} ${PROXY_TUN_IP} ${PROXY_TUN_PORT}"
docker exec -it ${NODE} bash -c "cli_service set-node ${GROUP_ID} ${SERVICE_ID} ${PASSWD} ${TUNNEL_ID}"
# <<<<


# DEBUG >>>>
docker exec -it ${PROXY} bash -c "cli_tunnel get all ; cli_service get all"
docker exec -it ${NODE} bash -c "cli_tunnel get all ; cli_service get all"
# <<<<


# TEST >>>> verify result
echo "Waiting for GUE ping..."
for (( i=1; i<10; i++ ))
do
    if [ "$(docker exec -it ${PROXY} bash -c "cli_tunnel get ${TUNNEL_ID}" | grep "TUN" | grep ${TUNNEL_ID} | grep -v "0.0.0.0:0")" ] ; then
        break
    fi
    echo "."
    sleep 1
done

docker exec -it ${NODE} bash -c "cli_gc get all" | grep 'ENCAP (' | wc -l

if [ ! "$(docker exec -it ${PROXY} bash -c "cli_tunnel get ${TUNNEL_ID}" | grep "TUN" | grep ${TUNNEL_ID} | grep -v "0.0.0.0:0")" ] ; then
    echo -e "\nGUE Ping for '${SERVICE_NAME}' \e[31mFAILED\e[0m\n"
    RETURN=1
else
    for (( j=1; j<11; j++ ))
    do
        for (( i=5000; i<6000; i++ ))
        do
            echo "Request: [$j/$i]"
            ./${SERVICE_TYPE}_check.sh ${CLIENT} ${PROXY_IP} ${PROXY_PORT} ${SERVICE_ID} $i > /dev/null
        done
    done

    echo "Waiting ~20s for final cleanup..."
    for (( i=1; i<9; i++ ))
    do
        echo "[$i/8] Sessions:"
        docker exec -it ${NODE} bash -c "cli_gc get all" | grep 'ENCAP (' | wc -l
        sleep 3
    done
    docker exec -it ${NODE} bash -c "cli_gc get all"
fi
# <<<<


# INFRA & PFC >>>> cleanup topology
if [ "${VERBOSE}" ]; then
    docker exec -it ${PROXY} bash -c "pfc_delete.sh ${GROUP_ID} ${SERVICE_ID}"
    docker exec -it ${NODE} bash -c "pfc_delete.sh ${GROUP_ID} ${SERVICE_ID}"

    docker exec -it ${PROXY} bash -c "pfc_list.sh"
    docker exec -it ${NODE} bash -c "pfc_list.sh"

    # Stop PFC
    docker exec -it ${PROXY} bash -c "pfc_stop.sh ${PROXY_NIC}"
    docker exec -it ${NODE} bash -c "pfc_stop.sh ${NODE_NIC}"

    ./topo_cleanup.sh ${TOPO}
else
    echo "Shutdown '${TOPO}' topology..."
    docker exec -it ${PROXY} bash -c "pfc_delete.sh ${GROUP_ID} ${SERVICE_ID}" > /dev/null
    docker exec -it ${NODE} bash -c "pfc_delete.sh ${GROUP_ID} ${SERVICE_ID}" > /dev/null

    # Stop PFC
    docker exec -it ${PROXY} bash -c "pfc_stop.sh ${PROXY_NIC}" > /dev/null
    docker exec -it ${NODE} bash -c "pfc_stop.sh ${NODE_NIC}" > /dev/null

    ./topo_cleanup.sh ${TOPO} > /dev/null
fi
# <<<<

exit ${RETURN}
