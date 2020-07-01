#!/bin/bash
# Rebuild (remove existing image first) node docker image
# usage: $0

. ../common.cfg

TMP_FOLDER="/tmp/docker"
FILES="node.Dockerfile  server.py ../../src/egw_egress_tc.o ../../src/egw_ingress_tc.o ../../src/pfc_egress_tc.o ../../src/pfc_ingress_tc.o ../../src/attach_tc.sh ../../src/detach_tc.sh ../../src/reattach_tc.sh ../../src/show_tc.sh"

CONTAINERS=`docker ps | grep ${LINUX_IMG}`
if [ "${CONTAINERS}" ] ; then
    echo "# Docker image is in use. Stop following containers first:"
    echo "${CONTAINERS}"
    exit 1
fi

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

CHECK=`sudo docker images | awk '{print $1":"$2}' | grep ${LINUX_IMG}`
if [ "${CHECK}" ]; then
    echo "# Removing old docker image..."
    sudo docker rmi ${LINUX_IMG}
    sudo docker images
fi

echo "### Building '${LINUX_IMG}'..."
sudo docker build --tag ${LINUX_IMG} -f node.Dockerfile .

#check
docker images

echo "### Done ###"
