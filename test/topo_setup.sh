#!/bin/bash
# Setup topology defined in config file
# usage: $0 <config> [<docker-image>]
#           <config>        - file with topology description
#           <docker-image>  - (OPTIONAL) docker image to use for containers. If not specified, default image will be used.


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

STEPS=8
KERNEL_MODULES="fou"

#set -x

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
    PRODUCTION_IMG="$2"
fi

# docker image
CHECK=`docker images | awk '{print $1":"$2}' | grep ${PRODUCTION_IMG}`
if [ ! "${CHECK}" ]; then
    echo "Docker image '${PRODUCTION_IMG}' : Not found! You need to build it first."
    exit 1
else
    echo "Docker image '${PRODUCTION_IMG}' : OK"
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

# enable ip tables logging inside docker
sudo bash -c "echo 1 > /proc/sys/net/netfilter/nf_log_all_netns"

echo -e "\n==========================================="
echo "# TOPO($1).START [3/${STEPS}] : Starting nodes"
echo "==========================================="
for NODE in ${NODES}
do
    echo "### Starting '${NODE}' container ###"
#    docker run --rm -itd --cap-add=NET_ADMIN --name ${NODE} -e MICROSERVICE_LABEL=${NODE} ${PRODUCTION_IMG}
    docker run --rm -itd  --privileged --name ${NODE} -e MICROSERVICE_LABEL=${NODE} ${PRODUCTION_IMG}
done

if [ "${VERBOSE}" ]; then
    echo ""
    docker ps
fi

echo -e "\n==========================================="
echo "# TOPO($1).START [4/${STEPS}] : Creating Docker Networks"
echo "==========================================="
for (( i=0; i<${#NETWORK_NAME[@]}; i++ ))
do
    echo "### Creating (bridge) network '${NETWORK_NAME[$i]}' subnet '${NETWORK_SUBNET[$i]}' ###"
    docker network create --driver bridge --opt com.docker.network.bridge.name=br_$i --subnet "${NETWORK_SUBNET[$i]}" "${NETWORK_NAME[$i]}"
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

for (( i=0; i<${#NETWORK_NAME[@]}; i++ ))
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

function lookup()
{
    if [ -f "./$1" ] ; then
        FILE="./$1"
    elif [ -f "$1" ] ; then
        FILE="$1"
    elif [ -f $(which $1) ] ; then
        FILE=$(which $1)
#    else
#        echo "Cannot find '${BINARY}_${DIRECTION}_tc.o'"
#        exit 1
    fi
    echo "${FILE}"
}

echo -e "\n==========================================="
echo "# TOPO($1).START [7/${STEPS}] : Configuring nodes"
echo "==========================================="
prxs=(${PROXIES})
#echo "[${prxs}]"
for (( i=0; i<${#prxs[@]}; i++ ))
do
    echo -e "\n### Configuring '${prxs[i]}' ###\n"
    # enable packet forwarding
    docker exec -it ${prxs[i]} bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

    echo "Disabling ICMP redirects..."
    docker exec -it ${prxs[i]} bash -c "echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects"
    docker exec -it ${prxs[i]} bash -c "echo 0 > /proc/sys/net/ipv4/conf/default/send_redirects"
    docker exec -it ${prxs[i]} bash -c "echo 0 > /proc/sys/net/ipv4/conf/eth0/send_redirects"

    echo "Enabling Proxy ARP..."
    docker exec -it ${prxs[i]} bash -c "echo 1 > /proc/sys/net/ipv4/conf/all/proxy_arp"

    # >>>>>>
    #docker exec -it ${prxs[i]} bash -c "ip addr add ${PROXY_IP[i]} dev lo"        # need different ip per proxy
    # ======
    # create bridge
    docker exec -it ${prxs[i]} bash -c "brctl addbr br0"

    # bridge up
    docker exec -it ${prxs[i]} bash -c "ip link set br0 up"

    # add default route
    docker exec -it ${prxs[i]} bash -c "ip route"
    #docker exec -it ${prxs[i]} bash -c "ip route add default via 172.1.0.1"

    if [ "${VERBOSE}" ]; then
        echo ""
        docker exec -it ${prxs[i]} bash -c "ip addr"
    fi

done

for NODE in ${CLIENTS}
do
    echo -e "\n### Configuring '${NODE}' ###\n"
    # set routing
    for (( i=0; i<${#PROXY_IP[@]}; i++ ))
    do
        DEFAULT_ROUTE=$(docker exec -it ${prxs[i]} bash -c "ip addr" | grep "eth1" | grep inet | awk '{print $2}' | sed 's/\/16//g')
        docker exec -it ${NODE} bash -c "ip route add ${PROXY_IP[i]}/32 via ${DEFAULT_ROUTE} dev eth1"     # need one route per proxy
    done

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

    # set routing if on main network (if behind nat, it will be configured together with nat box)
    CHECK=$(docker exec -it ${NODE} bash -c "ip route" | grep ${NETWORK_SUBNET[0]})
    if [ "${CHECK}" ] ; then
        for (( i=0; i<${#PROXY_IP[@]}; i++ ))
        do
            DEFAULT_ROUTE=$(docker exec -it ${prxs[i]} bash -c "ip addr" | grep "eth1" | grep inet | awk '{print $2}' | sed 's/\/16//g')
            #echo "docker exec -it ${NODE} bash -c 'ip route add ${PROXY_IP[i]}/32 via ${DEFAULT_ROUTE} dev eth1'"
            docker exec -it ${NODE} bash -c "ip route add ${PROXY_IP[i]}/32 via ${DEFAULT_ROUTE} dev eth1"     # need one route per proxy
        done
    fi

    if [ "${VERBOSE}" ]; then
        echo ""
        docker exec -it ${NODE} bash -c "ip addr"
        docker exec -it ${NODE} bash -c "ip route"
    fi
done

nats=(${NATS})
#echo "[${#nats[@]}]"
for (( i=0; i<${#nats[@]}; i++ ))
do
    echo -e "\n### Configuring '${nats[i]}' ###\n"
    # enable packet forwarding
    docker exec -it ${nats[i]} bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

    for (( j=0; j<${#PROXY_IP[@]}; j++ ))      # need one route per proxy/with own NAT box IP
    do
        DEFAULT_ROUTE=$(docker exec -it ${prxs[j]} bash -c "ip addr" | grep "eth1" | grep inet | awk '{print $2}' | sed 's/\/16//g')
        #echo "[${DEFAULT_ROUTE}]=docker exec -it ${prxs[j]} bash -c 'ip addr' | grep 'eth1' | grep inet | awk '{print $2}' | sed 's/\/16//g'"
        #echo "docker exec -it ${nats[i]} bash -c 'ip route add ${PROXY_IP[j]}/32 via ${DEFAULT_ROUTE} dev eth1'"
        docker exec -it ${nats[i]} bash -c "ip route add ${PROXY_IP[j]}/32 via ${DEFAULT_ROUTE} dev eth1"     # need one route per proxy
    done

    # NAT eth2 (private) -> eth1 (public)
    docker exec -it ${nats[i]} bash -c "iptables -t raw -A PREROUTING -j TRACE"
    docker exec -it ${nats[i]} bash -c "iptables -t raw -A OUTPUT -j TRACE"

    docker exec -it ${nats[i]} bash -c "iptables -t nat -A POSTROUTING -j LOG --log-prefix='FWD:ALL '"
    docker exec -it ${nats[i]} bash -c "iptables -t nat -A POSTROUTING -o eth1 -j LOG --log-prefix='MASQUERADE '"
    docker exec -it ${nats[i]} bash -c "iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE"          # assuming eth1 facing to public and eth2 to private network
    docker exec -it ${nats[i]} bash -c "iptables -A FORWARD -j LOG --log-prefix='FWD:ALL '"
    docker exec -it ${nats[i]} bash -c "iptables -A FORWARD -i eth1 -o eth2 -m state --state RELATED,ESTABLISHED -j ACCEPT"
    docker exec -it ${nats[i]} bash -c "iptables -A FORWARD -i eth2 -o eth1 -j ACCEPT"
    docker exec -it ${nats[i]} bash -c "iptables-translate -A INPUT -j CHECKSUM --checksum-fill"

    if [ "${VERBOSE}" ]; then
        echo ""
        docker exec -it ${nats[i]} bash -c "ip route"
    fi

    # configure default GW on nodes sitting behind thin NAT box
    DEFAULT_NAT_ROUTE=$(docker exec -it ${nats[i]} bash -c "ip addr" | grep "eth2" | grep inet | awk '{print $2}' | sed 's/\/16//g')
    for NODE in ${NAT_GW[i]}
    do
        echo -e "\n### Adding routing of '${NODE}' via '${DEFAULT_NAT_ROUTE}' ###\n"
        for (( i=0; i<${#PROXY_IP[@]}; i++ ))      # need one route per proxy/with own NAT box IP
        do
            #echo "docker exec -it ${NODE} bash -c 'ip route add ${PROXY_IP[i]}/32 via ${DEFAULT_NAT_ROUTE} dev eth1'"
            docker exec -it ${NODE} bash -c "ip route add ${PROXY_IP[i]}/32 via ${DEFAULT_NAT_ROUTE} dev eth1"     # need one route per proxy
        done
        #echo "docker exec -it ${NODE} bash -c 'ip route add ${NETWORK_SUBNET[0]} via ${DEFAULT_NAT_ROUTE} dev eth1'"
        docker exec -it ${NODE} bash -c "ip route add ${NETWORK_SUBNET[0]} via ${DEFAULT_NAT_ROUTE} dev eth1"     # required when sitting behind nat

        if [ "${VERBOSE}" ]; then
            echo ""
            docker exec -it ${NODE} bash -c "ip route"
        fi
    done
done

#echo -e "\n==========================================="
#echo "# TOPO($1).START [8/${STEPS}] : Reachability Check"
#echo "==========================================="

#for (( i=0; i<${#PROXY_IP[@]}; i++ ))      # need one route per proxy/with own NAT box IP
#do
#    ./test_icmp.sh ${PROXY_IP[i]} "${CLIENTS} ${SERVERS} ${NATS}"
#    echo "=========="
#done

echo -e "\n==========================================="
echo "# TOPO($1).START : DONE"
echo "# Status : TBD"
echo "==========================================="
