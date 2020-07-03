#!/bin/bash
# Rebuild (remove existing image first) system node docker image
# usage: $0

. ../common.cfg

CHECK=`sudo docker images | awk '{print $1":"$2}' | grep ${SYSTEM_IMG}`
if [ "${CHECK}" ]; then
    echo "# Removing old docker image..."
    sudo docker rmi ${SYSTEM_IMG}
    if [ ! "$?"=="0" ] ; then
        exit 1
    fi
    sudo docker images
fi

echo "### Building '${SYSTEM_IMG}'..."
sudo docker build --tag ${SYSTEM_IMG} -f system.Dockerfile .

#check
sudo docker images

echo "### Done ###"
