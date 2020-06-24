#!/bin/bash
# Rebuild (remove existing image first) node docker image
# usage: $0

. ../common.cfg

CONTAINERS=`docker ps | grep ${LINUX_IMG}`
if [ "${CONTAINERS}" ] ; then
    echo "# Docker image is in use. Stop following containers first:"
    echo "${CONTAINERS}"
    exit 1
fi

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
