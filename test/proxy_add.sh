#!/bin/bash
# Setup topology defined in config file
# Usage: $0 <egw-docker> <namespace-name> <public-ip> <bridge-if-name> <veth-id>"

PROXY=$1
PROXY_ID=$2
PROXY_IP=$3
IF_BR=$4
VETH_ID=$5


# parse args
while getopts "vV" opt; do
    case "$opt" in
    v)  VERBOSE=1
        ;;
    V)  export VERBOSE=1
        ;;
    esac
done
shift $((OPTIND-1))

# --- Setup NS1 ---
docker exec -it ${PROXY} bash -c "ip netns add proxy${PROXY_ID}"

# create veth pair for namespace
docker exec -it ${PROXY} bash -c "ip link add veth${VETH_ID} type veth peer name vethns${VETH_ID}"

# attach veth to namespace
docker exec -it ${PROXY} bash -c "ip link set vethns${VETH_ID} netns proxy${PROXY_ID}"

# EXIST
# add veth to bridge
docker exec -it ${PROXY} bash -c "brctl addif ${IF_BR} veth${VETH_ID}"
# veth up
docker exec -it ${PROXY} bash -c "ip link set veth${VETH_ID} up"

##brctl show

# configure veth in namespace + add deault route to ${IF_BR}
docker exec -it ${PROXY} bash -c "ip netns exec proxy${PROXY_ID} ip addr add ${PROXY_IP}/32 dev vethns${VETH_ID}"
docker exec -it ${PROXY} bash -c "ip netns exec proxy${PROXY_ID} ip link set vethns${VETH_ID} up"
docker exec -it ${PROXY} bash -c "ip netns exec proxy${PROXY_ID} ip route add default dev vethns${VETH_ID}"

# set route on host to steer PROXY-IP into ${IF_BR}
docker exec -it ${PROXY} bash -c "ip route add ${PROXY_IP}/32 dev ${IF_BR}"
