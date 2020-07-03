#!/bin/bash
# Cleanup topology defined in config file
# usage: $0 <config> [<docker-image>]
#           <config>        - file with topology description
#           <docker-image>  - (OPTIONAL) docker image used for containers. If not specified, default image will be used.

STEPS=3
#VERBOSE="1"

# check config file
echo "==========================================="
echo "# TOPO($1).CHECK [1/${STEPS}] : Checking input"
echo "==========================================="
# config
CHECK=`ls "$1"`
if [ ! "${CHECK}" ] ; then
    echo "Topology config '$1' : Not found!"
    echo "Usage: $0 <config-file> [<docker-image>]"
    echo "          <config-file>   - file with topology description"
    echo "          <docker-image>  - (OPTIONAL) docker image used for containers. If not specified, default image will be used."
    exit 1
else
    echo "Topology config '$1' : OK"
fi

. $1

if [ "$2" ] ; then
    PRODUCTION_IMG="$2"
fi

echo -e "\n==========================================="
echo "# TOPO($1).CHECK [2/${STEPS}] : Running containers for '${PRODUCTION_IMG}'"
echo "==========================================="

docker ps | grep ${PRODUCTION_IMG} | awk '{print $NF}'

echo -e "\n==========================================="
echo "# TOPO($1).CHECK [3/${STEPS}] : Running networks"
echo "==========================================="
docker network ls | grep ${NAME_PREFIX} | awk '{print $2}'

echo -e "\n==========================================="
echo "# TOPO($1).CHECK : DONE"
echo "==========================================="
