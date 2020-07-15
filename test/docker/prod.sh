#!/bin/bash
# Rebuild (remove existing image first) node docker image
# usage: $0 [<docker-image>]
#           <docker-image>  - (OPTIONAL) docker image name to use. If not specified, default image name will be used.

. ../common.cfg

if [ "$1" ] ; then
    PRODUCTION_IMG="$1"
fi

TMP_FOLDER="/tmp/docker"
FILES="prod.Dockerfile server.py gue_ping_tun.py ../../src/egw_egress_tc.o ../../src/egw_ingress_tc.o ../../src/pfc_egress_tc.o ../../src/pfc_ingress_tc.o ../../src/attach_tc.sh ../../src/detach_tc.sh ../../src/reattach_tc.sh ../../src/show_tc.sh ../../src/cli_cfg ../../src/cli_tunnel ../../src/cli_service"

# chack no containers are running
CONTAINERS=`sudo docker ps | grep ${PRODUCTION_IMG}`
if [ "${CONTAINERS}" ] ; then
    echo "# Docker image '${PRODUCTION_IMG}' is in use. Stop following containers first:"
    echo "${CONTAINERS}"
    exit 1
fi

# check system image exists
CHECK=`sudo docker images | awk '{print $1":"$2}' | grep ${SYSTEM_IMG}`
if [ ! "${CHECK}" ]; then
    echo "# System image missing. Need to build it first..."
    ./system.sh
fi

# create temporary folder and copy files
rm -rf ${TMP_FOLDER} &> /dev/null
mkdir -p ${TMP_FOLDER}

for FILE in ${FILES}
do
    if [ -f "${FILE}" ] ; then
        cp ${FILE} ${TMP_FOLDER}
        echo "# Copy '${FILE}' : OK"
    else
        echo "# Copy '${FILE}' : does not exist"
        exit 1
    fi
done

ls ${TMP_FOLDER}

cp ./* ${TMP_FOLDER}
cd ${TMP_FOLDER}

ls

# remove old production image if exists
CHECK=`sudo docker images | awk '{print $1":"$2}' | grep ${PRODUCTION_IMG}`
if [ "${CHECK}" ]; then
    echo "# Removing old docker image..."
    sudo docker rmi ${PRODUCTION_IMG}
    sudo docker images
fi

# build new production image
echo "### Building '${PRODUCTION_IMG}'..."
sudo docker build --tag ${PRODUCTION_IMG} -f prod.Dockerfile .

#check
sudo docker images

echo "### Done ###"
