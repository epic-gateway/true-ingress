#!/bin/bash
# Cleanup topology defined in config file
# usage: $0 <config> [<docker-image>]
#           <config>        - file with topology description
#           <docker-image>  - (OPTIONAL) docker image used for containers. If not specified, default image will be used.

STEPS=3
VERIFY="1"

# check config file
echo "==========================================="
echo "# [1/${STEPS}] Checking topology configuration '$1'"
echo "==========================================="
CHECK=`ls "$1"`
if [ ! "${CHECK}" ] ; then
    echo "ERROR: Unknown <config-file> specified '$1'"
    echo "Usage: $0 <config-file> [<docker-image>]"
    echo "          <config-file>   - file with topology description"
    echo "          <docker-image>  - (OPTIONAL) docker image used for containers. If not specified, default image will be used."
    exit 1
fi

echo -e "### Done ###\n"

. $1

if [ "$2" ] ; then
    LINUX_IMG="$2"
fi

echo "==========================================="
echo "# [2/${STEPS}] Stoping instances of '${LINUX_IMG}'"
echo "==========================================="

CONTAINERS=`docker ps | grep ${LINUX_IMG} | awk '{print $NF}'`
#echo "CONTAINERS to delete:[$CONTAINERS]"
for CONTAINER in $CONTAINERS
do
    docker stop ${CONTAINER}
done

#for NODE in $NODES
#do
#    docker stop ${NODE} # >/dev/null 2>&1
#done

echo -e "### Done ###\n"

if [ "${VERIFY}" ]; then
    docker ps
fi

echo "==========================================="
echo "# [3/${STEPS}] Removing networks named '${NAME_PREFIX}*'"
echo "==========================================="
NETWORKS=`docker network ls | grep ${NAME_PREFIX} | awk '{print $2}'`
#echo "NETWORKS to delete:[$NETWORKS]"
if [ "${NETWORKS}" ]; then
    docker network rm ${NETWORKS}
fi

#for (( i=1; i<${#NETWORK_NAME[@]}; i++ ))
#do
#    docker network rm ${NETWORK_NAME[$i]} # >/dev/null 2>&1
#done

echo -e "### Done ###\n"

if [ "${VERIFY}" ]; then
    docker network ls
fi
