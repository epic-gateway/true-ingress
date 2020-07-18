#!/bin/bash
# Rebuild (remove existing image first) system node docker image
# usage: $0

. ../common.cfg

CHECK=`docker images | awk '{print $1":"$2}' | grep ${SYSTEM_IMG}`
if [ "${CHECK}" ]; then
    echo "# Removing old docker image..."
    docker rmi ${SYSTEM_IMG}
    if [ ! "$?"=="0" ] ; then
        exit 1
    fi
    docker images
fi

echo "### Building '${SYSTEM_IMG}'..."
docker build --tag ${SYSTEM_IMG} -f system.Dockerfile .

#check
docker images

echo "### Done ###"
