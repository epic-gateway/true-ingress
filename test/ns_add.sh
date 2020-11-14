#!/bin/bash
# Setup topology defined in config file
# Usage: $0 <egw-docker> <namespace-name> <public-ip> <veth-id> [<bridge-if-name>]"

HOST=$1
NAME=$2
IP=$3
VETH_ID=$4
IF_BR=$5


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
docker exec -it ${HOST} bash -c "ip netns add ${NAME}"

# create veth pair for namespace
docker exec -it ${HOST} bash -c "ip link add veth${VETH_ID} type veth peer name vethns${VETH_ID}"

# attach veth to namespace
docker exec -it ${HOST} bash -c "ip link set vethns${VETH_ID} netns ${NAME}"

# configure veth in namespace + add deault route to ${IF_BR}
docker exec -it ${HOST} bash -c "ip netns exec ${NAME} ip addr add ${IP}/32 dev vethns${VETH_ID}"
docker exec -it ${HOST} bash -c "ip netns exec ${NAME} ip link set vethns${VETH_ID} up"
docker exec -it ${HOST} bash -c "ip netns exec ${NAME} ip route add default dev vethns${VETH_ID}"

# EXIST
# add veth to bridge
if [ "${IF_BR}" ] ; then
    docker exec -it ${HOST} bash -c "brctl addif ${IF_BR} veth${VETH_ID}"

    # set route on host to steer PROXY-IP into ${IF_BR}
    docker exec -it ${HOST} bash -c "ip route add ${IP}/32 dev ${IF_BR}"
else
    docker exec -it ${HOST} bash -c "ip route add ${IP}/32 dev veth${VETH_ID}"
fi

# veth up
docker exec -it ${HOST} bash -c "ip link set veth${VETH_ID} up"
