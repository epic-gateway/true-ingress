#!/bin/bash
# Load eBPF on EGW, run ping 5.5.5.5 from Client and check tracefile.
# usage: $0

cd ..

# setup topology
./topo_setup.sh basic.cfg

CLIENT="client"
NODE="node1"
PROXY="egw"
PROXY_IP="5.5.5.5"

echo "########################################################"
echo "# Topology up'n'runnin. Hit <ENTER> to attach TC on EGW. #"
echo "########################################################"

read

docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin ; ./attach_tc.sh eth1 pfc"

echo "#########################################"
echo "# TC attached. Hit <ENTER> to run test. #"
echo "#########################################"

read

# check traces before
tail -n60 /sys/kernel/debug/tracing/trace

# generate ICMP ECHO REQUEST + RESPONSE packets
./test_icmp.sh ${PROXY_IP} "${NODE}"

# check traces after
tail -n60 /sys/kernel/debug/tracing/trace

echo "#################################################"
echo "# Test done. Hit <ENTER> to detach TC from EGW. #"
echo "#################################################"

read

docker exec -it ${NODE} bash -c "cd /tmp/.acnodal/bin ; ./detach_tc.sh eth1"

echo "#################################################"
echo "# TC detached. Hit <ENTER> to cleanup topology. #"
echo "#################################################"

read
# cleanup topology
./topo_cleanup.sh basic.cfg
