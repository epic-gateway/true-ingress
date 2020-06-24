#!/bin/bash
# Rebuild (remove existing image first) node docker image
# usage: $0

. ../common.sh

echo "==========================================="
echo "# (Re)building NODE docker image (${LINUX_IMG})"
echo "==========================================="
CHECK=`sudo docker images | awk '{print $1":"$2}' | grep ${LINUX_IMG}`
if [ "${CHECK}" ]; then
    echo "# Removing old image..."
    sudo docker rmi ${LINUX_IMG}
fi

echo "### Building new image..."
sudo docker build --tag ${LINUX_IMG} -f node.Dockerfile .

#check
docker images

echo "### Done ###"
