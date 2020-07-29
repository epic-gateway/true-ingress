#!/bin/bash
# syntax: $0 <node> <service-id> <proto> <service-ip> <service-port> <real-ip> <real-port> <proxy-ip> <proxy-port> <foo-ip>

# 1) setup GUE tunnel
# 2) add routing to the tunnel
# 3) add neccessary NAT

STEPS=7
#TUNNEL_PREFIX="10.1.1."

NODE=$1
SERVICE_ID=$2
PROTO=$3
SERVICE_IP=$4
SERVICE_PORT=$5
# following information should be retrieved later from GUE ping
TUNNEL_REMOTE_IP=$6
TUNNEL_REMOTE_PORT=$7
PROXY_IP=$8
PROXY_PORT=$9
FOO_IP=${10}
NAT=${11}

#VERBOSE="1"

if [ "${VERBOSE}" ]; then
    echo -e "\nEGW.TC.ADD : NODE='${NODE}' SERVICE_ID='${SERVICE_ID}' PROTO='${PROTO}' SERVICE_IP='${SERVICE_IP}' SERVICE_PORT='${SERVICE_PORT}' TUNNEL_REMOTE_IP='${TUNNEL_REMOTE_IP}' TUNNEL_REMOTE_PORT='${TUNNEL_REMOTE_PORT}' PROXY_IP='${PROXY_IP}' PROXY_PORT='${PROXY_PORT}' FOO_IP='${FOO_IP}'"
fi

TUNNEL_PORT=6080

IFNAME="gue${SERVICE_ID}"
CHECK=`docker exec -it ${NODE} bash -c "ip addr" | grep ${IFNAME}`
if [ "${CHECK}" ] ; then
    echo "Service ID ${SERVICE_ID} already exist"
    exit 1
fi

# careful! works only with small numbers
TUNNEL_LOCAL_IP=${FOO_IP}

echo -e "\n==============================================="
echo "# EGW.TC.ADD [1/${STEPS}] : Create GUE tunnel (${IFNAME}) to ${TUNNEL_REMOTE_IP}:${TUNNEL_REMOTE_PORT})"

docker exec -it ${NODE} bash -c "ip fou add port ${TUNNEL_PORT} gue"
docker exec -it ${NODE} bash -c "ip link add name ${IFNAME} type ipip remote ${TUNNEL_REMOTE_IP} encap gue encap-sport ${TUNNEL_PORT} encap-dport ${TUNNEL_REMOTE_PORT}"

CHECK=`docker exec -it ${NODE} bash -c "ip link" | grep ${IFNAME}`
if [ ! "${CHECK}" ] ; then
    echo "FAILED to create tunnel"
    exit 1
fi

echo -e "\n==============================================="
echo "# EGW.TC.ADD [2/${STEPS}] : Assign IP ${TUNNEL_LOCAL_IP} to ${IFNAME} and bring it up"

docker exec -it ${NODE} bash -c "ip addr add ${TUNNEL_LOCAL_IP}/24 dev ${IFNAME}"
docker exec -it ${NODE} bash -c "ip link set ${IFNAME} up"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${NODE} bash -c "ip addr"
fi

echo -e "\n==============================================="
echo "# EGW.TC.ADD [3/${STEPS}] : Set Route for service ${SERVICE_IP}/32 via ${IFNAME}"

docker exec -it ${NODE} bash -c "ip route add ${SERVICE_IP}/32 dev ${IFNAME}"
# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${NODE} bash -c "ip route"
fi

if [ ! "${NAT}" ] ; then
    echo -e "\n==============================================="
    echo "# EGW.TC.ADD [4/${STEPS}] : Set DNAT (PROXY ${PROXY_IP}:${PROXY_PORT} -> SERVICE ${SERVICE_IP}:${SERVICE_PORT})"

    # add icmp entry for ping check (remove later)
    docker exec -it ${NODE} bash -c "iptables -t nat -A PREROUTING -p icmp -i eth1 --destination ${PROXY_IP} -j DNAT --to-destination ${SERVICE_IP}"
    # add real entry (do we care about interfaces??? whitelist/blacklist)
    docker exec -it ${NODE} bash -c "iptables -t nat -A PREROUTING -p ${PROTO} -i eth1 --destination ${PROXY_IP} --dport ${PROXY_PORT} -j DNAT --to-destination ${SERVICE_IP}:${SERVICE_PORT}"
    # check
    docker exec -it ${NODE} bash -c "iptables -t nat -L PREROUTING -n --line-numbers"

    echo -e "\n==============================================="
    echo "# EGW.TC.ADD [5/${STEPS}] : Set SNAT (SERVICE ${SERVICE_IP}:${SERVICE_PORT} -> PROXY ${PROXY_IP}:${PROXY_PORT})"

    # add icmp entry for ping check (remove later)
    docker exec -it ${NODE} bash -c "iptables -t nat -A POSTROUTING -p icmp -o eth1 -s ${SERVICE_IP} -j SNAT --to-source ${PROXY_IP}"
    # add real entry (do we care about interfaces??? whitelist/blacklist)
    docker exec -it ${NODE} bash -c "iptables -t nat -A POSTROUTING -p ${PROTO} -o eth1 -s ${SERVICE_IP} --sport ${SERVICE_PORT} -j SNAT --to-source ${PROXY_IP}:${PROXY_PORT}"
fi

echo -e "\n==============================================="
echo "# EGW.TC.ADD [6/${STEPS}] : (FAKE) Set MASQUERADE on tunnel entry (required for routing on NODE side)"

# set SNAT client ip -> tunnel ip translation
docker exec -it ${NODE} bash -c "iptables -t nat -A POSTROUTING -o ${IFNAME} -j MASQUERADE"
# (do we care about interfaces??? whitelist/blacklist)
docker exec -it ${NODE} bash -c "iptables -A FORWARD -i ${IFNAME} -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT"
docker exec -it ${NODE} bash -c "iptables -A FORWARD -i eth1 -o ${IFNAME} -j ACCEPT"

# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${NODE} bash -c "iptables -t nat -L POSTROUTING -n --line-numbers"
fi

echo -e "\n==============================================="
echo "# EGW.TC.ADD [7/${STEPS}] : Attach TC to ${IFNAME}"

docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin && ./attach_tc.sh eth1"

# check
#if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${NODE} bash -c "ls -R /sys/fs/bpf/"
#fi

echo -e "\n==============================================="
echo "# EGW.TC.ADD : DONE"
