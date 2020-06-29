#!/bin/bash
# Setup topology defined in config file
# usage: $0 <config> [<docker-image>]
#           <config>        - file with topology description
#           <docker-image>  - (OPTIONAL) docker image to use for containers. If not specified, default image will be used.

STEPS=8
#VERBOSE="1"
KERNEL_MODULES="fou"

# check config file
echo "==========================================="
echo "# TOPO($1).START [1/${STEPS}] : Checking input"
echo "==========================================="
# config
CHECK=`ls "$1"`
if [ ! "${CHECK}" ] ; then
    echo "Topology config '$1' : Not found!"
    echo "Usage: $0 <config-file> [<docker-image>]"
    echo "          <config-file>   - file with topology description"
    echo "          <docker-image>  - (OPTIONAL) docker image to use for containers. If not specified, default image will be used."
    exit 1
else
    echo "Topology config '$1' : OK"
fi

. $1

if [ "$2" ] ; then
    LINUX_IMG="$2"
fi

# docker image
CHECK=`sudo docker images | awk '{print $1":"$2}' | grep ${LINUX_IMG}`
if [ ! "${CHECK}" ]; then
    echo "Docker image '${LINUX_IMG}' : Not found! You need to build it first."
    exit 1
else
    echo "Docker image '${LINUX_IMG}' : OK"
fi

echo -e "\n==========================================="
echo "# TOPO($1).START [2/${STEPS}] : Inserting kernel modules"
echo "==========================================="
for MODULE in ${KERNEL_MODULES}
do
    CHECK=`lsmod | grep ${MODULE}`
    if [ ! "${CHECK}" ]; then
        echo "Module '${MODULE}' : Inserting..."
        sudo modprobe ${MODULE}
    else
        echo "Module '${MODULE}' : OK"
    fi
done

echo -e "\n==========================================="
echo "# TOPO($1).START [3/${STEPS}] : Starting nodes"
echo "==========================================="
for NODE in ${NODES}
do
    echo "### Starting '${NODE}' container ###"
    sudo docker run --rm -itd --cap-add=NET_ADMIN --name ${NODE} -e MICROSERVICE_LABEL=${NODE} ${LINUX_IMG}
done

if [ "${VERBOSE}" ]; then
    echo ""
    docker ps
fi

echo -e "\n==========================================="
echo "# TOPO($1).START [4/${STEPS}] : Creating Docker Networks"
echo "==========================================="
for (( i=1; i<${#NETWORK_NAME[@]}; i++ ))
do
    echo "### Creating (bridge) network '${NETWORK_NAME[$i]}' subnet '${NETWORK_SUBNET[$i]}' ###"
    sudo docker network create --driver bridge --opt com.docker.network.bridge.name=br_$i --subnet "${NETWORK_SUBNET[$i]}" "${NETWORK_NAME[$i]}"
done

if [ "${VERBOSE}" ]; then
    echo ""
    docker network ls
fi

echo -e "\n==========================================="
echo "# TOPO($1).START [5/${STEPS}] : Cleaning IPTABLES"
echo "==========================================="
if [ "${VERBOSE}" ]; then
    iptables -L POSTROUTING -n -t nat --line-numbers
fi

if [ "${VERBOSE}" ]; then
    # list all rules,                                 skip headers, skip expected enties,     get rule numbers   reverse order     and delete one by one(-n1) (-t verbose) 
    iptables -L POSTROUTING -n -t nat --line-numbers | tail -n +3 | grep -v "172.17.0.0/16" | awk '{print $1}' | sed '1!G;h;$!d' | xargs -t -n1 iptables -t nat -D POSTROUTING
else
    iptables -L POSTROUTING -n -t nat --line-numbers | tail -n +3 | grep -v "172.17.0.0/16" | awk '{print $1}' | sed '1!G;h;$!d' | xargs -n1 iptables -t nat -D POSTROUTING
fi

if [ "${VERBOSE}" ]; then
    echo ""
    iptables -L POSTROUTING -n -t nat --line-numbers
fi

echo -e "\n==========================================="
echo "# TOPO($1).START [6/${STEPS}] : Connecting Docker Networks"
echo "==========================================="

for (( i=1; i<${#NETWORK_NAME[@]}; i++ ))
do
    for NODE in ${NET_MAPPING[i]}
    do
        echo "Connecting '${NODE}' to '${NETWORK_NAME[i]}'"
        docker network connect ${NETWORK_NAME[i]} ${NODE}
    done
done

#if [ "${VERBOSE}" ]; then
#    for NODE in $NODES
#    do
#        echo -e "\nInterfaces on ${NODE}:"
#        echo "docker exec -it ${NODE} bash -c ip addr"
#        docker exec -it ${NODE} bash -c "ip addr"
#    done

echo -e "\n==========================================="
echo "# TOPO($1).START [7/${STEPS}] : Configuring nodes"
echo "==========================================="
DEFAULT_ROUTE=`docker exec -it egw bash -c "ip addr" | grep "eth1" | grep inet | awk '{print $2}' | sed 's/\/16//g'`
DEFAULT_NAT_ROUTE=`docker exec -it nat bash -c "ip addr" | grep "eth2" | grep inet | awk '{print $2}' | sed 's/\/16//g'`
echo "DEFAULT_ROUTE: [${DEFAULT_ROUTE}]"
echo "DEFAULT_NAT_ROUTE: [${DEFAULT_NAT_ROUTE}]"

for NODE in ${PROXIES}
do
    echo -e "\n### Configuring '${NODE}' ###\n"
    # enable packet forwarding
    docker exec -it ${NODE} bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

    docker exec -it ${NODE} bash -c "ip addr add ${PROXY_IP} dev lo"        # need different ip per proxy

    if [ "${VERBOSE}" ]; then
        echo ""
        docker exec -it ${NODE} bash -c "ip addr"
    fi
done

for NODE in ${CLIENTS}
do
    echo -e "\n### Configuring '${NODE}' ###\n"
    # set routing
    docker exec -it ${NODE} bash -c "ip route add ${PROXY_IP}/32 via ${DEFAULT_ROUTE} dev eth1"     # need one route per proxy

    if [ "${VERBOSE}" ]; then
        echo ""
        docker exec -it ${NODE} bash -c "ip addr"
        docker exec -it ${NODE} bash -c "ip route"
    fi
done


for NODE in ${SERVERS}
do
    echo -e "\n### Configuring '${NODE}' ###\n"
    # enable packet forwarding
    docker exec -it ${NODE} bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

    # set routing
    CHECK=`docker exec -it ${NODE} bash -c "ip route" | grep "172.1.0.0/16"`
    if [ "${CHECK}" ] ; then
        docker exec -it ${NODE} bash -c "ip route add ${PROXY_IP}/32 via ${DEFAULT_ROUTE} dev eth1"     # need one route per proxy
    else
        docker exec -it ${NODE} bash -c "ip route add ${PROXY_IP}/32 via ${DEFAULT_NAT_ROUTE} dev eth1"     # need one route per proxy/with own NAT box IP
        docker exec -it ${NODE} bash -c "ip route add ${NETWORK_SUBNET[1]} via ${DEFAULT_NAT_ROUTE} dev eth1"     # required when sitting behind nat
    fi

    if [ "${VERBOSE}" ]; then
        echo ""
        docker exec -it ${NODE} bash -c "ip addr"
        docker exec -it ${NODE} bash -c "ip route"
    fi
done

for NODE in ${NATS}
do
    echo -e "\n### Configuring '${NODE}' ###\n"
    # enable packet forwarding
    docker exec -it ${NODE} bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

    docker exec -it ${NODE} bash -c "ip route add ${PROXY_IP}/32 via ${DEFAULT_ROUTE} dev eth1"     # need one route per proxy

    # NAT eth2 (private) -> eth1 (public)
    docker exec -it ${NODE} bash -c "iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE"          # assuming eth1 facing to public and eth2 to private network
    docker exec -it ${NODE} bash -c "iptables -A FORWARD -i eth1 -o eth2 -m state --state RELATED,ESTABLISHED -j ACCEPT"
    docker exec -it ${NODE} bash -c "iptables -A FORWARD -i eth2 -o eth1 -j ACCEPT"

    if [ "${VERBOSE}" ]; then
        echo ""
        docker exec -it ${NODE} bash -c "ip route"
    fi
done

echo -e "\n==========================================="
echo "# TOPO($1).START [8/${STEPS}] : Reachability Check"
echo "==========================================="

./test_icmp.sh ${PROXY_IP} "${CLIENTS} ${SERVERS} ${NATS}"

echo -e "\n==========================================="
echo "# TOPO($1).START : DONE"
echo "# Status : TBD"
echo "==========================================="
