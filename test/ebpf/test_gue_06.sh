#!/bin/bash
# Setup HTTP service on NODE on same network as EGW, expose it on EGW and send request from CLIENT.
# Attach and configure PFC on NODE and EGW.
# Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
# usage: $0 [-v|-V]

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

# setup topology
if [ "${VERBOSE}" ]; then
    ./topo_setup.sh basic.cfg
else
    echo "Starting topology..."
    ./topo_setup.sh basic.cfg > /dev/null
fi

NODE="node1"
NODE_PORT_MIN=6000
NODE_PORT_MAX=6010
NODE_NIC="eth1"
DELAY=10
FAIL=0
PASS=0

for (( i=1; i<=100; i++ ))
do
    if [ "${VERBOSE}" ]; then
        docker exec -it ${NODE} bash -c "pfc_start.sh ${NODE_NIC} "${NODE}" 9 8 ${NODE_PORT_MIN} ${NODE_PORT_MAX} ${DELAY}"

        #docker exec -it ${NODE} bash -c "ps aux" | grep "gue_ping" | grep -v "grep"
        #echo "---"
        ps aux | grep "gue_ping" | grep -v "grep"
    else
        docker exec -it ${NODE} bash -c "pfc_start.sh ${NODE_NIC} "${NODE}" 9 8 ${NODE_PORT_MIN} ${NODE_PORT_MAX} ${DELAY}" > /dev/null
    fi

    PID=$(ps aux | grep "gue_ping" | grep -v "grep")
    #echo "[${PID}]"
    if [ ! "${PID}" ] ; then
        ((FAIL += 1))
        echo " [${i}/100] : FAIL"
    else
        ((PASS++))
        echo " [${i}/100] : OK"
    fi

    if [ "${VERBOSE}" ]; then
        docker exec -it ${NODE} bash -c "pfc_stop.sh ${NODE_NIC}"
    else
        docker exec -it ${NODE} bash -c "pfc_stop.sh ${NODE_NIC}" > /dev/null
    fi
done

echo "PASSED : ${PASS}, FAILED : ${FAIL}"

# cleanup topology
if [ "${VERBOSE}" ]; then
    ./topo_cleanup.sh basic.cfg
else
    echo "Topology cleanup..."
    ./topo_cleanup.sh basic.cfg > /dev/null
fi

exit ${RETURN}
