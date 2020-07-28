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

#read

#docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin ; ./attach_tc.sh eth0"
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin ; ./attach_tc.sh eth1"

echo "###############################################"
echo "# Test done. Hit <ENTER> to run test on eth0 (no config). #"
echo "###############################################"

read

# check traces before
tail -n60 /sys/kernel/debug/tracing/trace

# generate ICMP ECHO REQUEST + RESPONSE packets
./test_icmp.sh 172.17.0.3

# check traces after
tail -n60 /sys/kernel/debug/tracing/trace

read

# check traces before
tail -n60 /sys/kernel/debug/tracing/trace

# generate ICMP ECHO REQUEST + RESPONSE packets
./test_icmp.sh ${PROXY_IP} "${NODE}"

# check traces after
tail -n60 /sys/kernel/debug/tracing/trace

# create config
# set <idx> <id> <flags> <name>
#docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin ; ./attach_tc.sh eth0"
#docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin ; ./attach_tc.sh eth1"
#docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set eth0 0 1 8 'ETH0' && ./cli_cfg set eth0 1 1 8 'ETH0' && ./cli_cfg get all"
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set eth1 0 1 8 'ETH1' && ./cli_cfg set eth1 1 1 8 'ETH1' && ./cli_cfg get all"

echo "###############################################"
echo "# Test done. Hit <ENTER> to run test on eth0 (config). #"
echo "###############################################"

read

# check traces before
tail -n60 /sys/kernel/debug/tracing/trace

# generate ICMP ECHO REQUEST + RESPONSE packets
./test_icmp.sh 172.17.0.3

# check traces after
tail -n60 /sys/kernel/debug/tracing/trace

read

# check traces before
tail -n60 /sys/kernel/debug/tracing/trace

# generate ICMP ECHO REQUEST + RESPONSE packets
./test_icmp.sh ${PROXY_IP} "${NODE}"

# check traces after
tail -n60 /sys/kernel/debug/tracing/trace

echo "########################################################"
echo "# Topology up'n'runnin. Hit <ENTER> to attach TC on EGW. #"
echo "########################################################"

#read

docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin ; ./attach_tc.sh eth0"
#docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin ; ./attach_tc.sh eth1"
#docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set eth0 0 1 8 'ETH0' && ./cli_cfg set eth0 1 1 8 'ETH0' && ./cli_cfg get all"
#docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set eth1 0 1 8 'ETH1' && ./cli_cfg set eth1 1 1 8 'ETH1' && ./cli_cfg get all"

echo "###############################################"
echo "# Test done. Hit <ENTER> to run test on eth0 (no config). #"
echo "###############################################"

read

# check traces before
tail -n60 /sys/kernel/debug/tracing/trace

# generate ICMP ECHO REQUEST + RESPONSE packets
./test_icmp.sh 172.17.0.3

# check traces after
tail -n60 /sys/kernel/debug/tracing/trace

read

# check traces before
tail -n60 /sys/kernel/debug/tracing/trace

# generate ICMP ECHO REQUEST + RESPONSE packets
./test_icmp.sh ${PROXY_IP} "${NODE}"

# check traces after
tail -n60 /sys/kernel/debug/tracing/trace

# create config
# set <idx> <id> <flags> <name>
docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set eth0 0 1 8 'ETH0' && ./cli_cfg set eth0 1 1 8 'ETH0' && ./cli_cfg get all"
#docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin && ./cli_cfg set eth1 0 1 8 'ETH1' && ./cli_cfg set eth1 1 1 8 'ETH1' && ./cli_cfg get all"

echo "###############################################"
echo "# Test done. Hit <ENTER> to run test on eth0 (config). #"
echo "###############################################"

read

# check traces before
tail -n60 /sys/kernel/debug/tracing/trace

# generate ICMP ECHO REQUEST + RESPONSE packets
./test_icmp.sh 172.17.0.3

# check traces after
tail -n60 /sys/kernel/debug/tracing/trace

read

# check traces before
tail -n60 /sys/kernel/debug/tracing/trace

# generate ICMP ECHO REQUEST + RESPONSE packets
./test_icmp.sh ${PROXY_IP} "${NODE}"

# check traces after
tail -n60 /sys/kernel/debug/tracing/trace

#echo "#################################################"
#echo "# TC attached. Hit <ENTER> to run test on eth1. #"
#echo "#################################################"

#read

## check traces before
#tail -n60 /sys/kernel/debug/tracing/trace

## generate ICMP ECHO REQUEST + RESPONSE packets
#./test_icmp.sh ${PROXY_IP} "${NODE}"

## check traces after
#tail -n60 /sys/kernel/debug/tracing/trace

echo "#################################################"
echo "# Test done. Hit <ENTER> to detach TC from EGW. #"
echo "#################################################"

read

docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin ; ./detach_tc.sh eth0"
#docker exec -it ${PROXY} bash -c "cd /tmp/.acnodal/bin ; ./detach_tc.sh eth1"

echo "#################################################"
echo "# TC detached. Hit <ENTER> to cleanup topology. #"
echo "#################################################"

#read

# cleanup topology
./topo_cleanup.sh basic.cfg
