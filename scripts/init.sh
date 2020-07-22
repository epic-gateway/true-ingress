#!/bin/bash
# usage $0 [<project-name>]
#       <project-name> - folder name, where to clone sources. If not specified, repository name will be used.

PROJECT="packet-forwarding-component"

if [ "$1" ] ; then
    PROJECT_DIR=$1              # Project name
else
    PROJECT_DIR=${PROJECT}   	# Project name
fi
WORKDIR=~/workspace             # Where to create project

# minimal dependencies to allow "git clone ..." and "make init"
PACKAGES="git build-essential"

#set -e


echo "============================="
echo "# Install minimal dependencies"
echo "============================="
sudo apt -y update
sudo apt install -y ${PACKAGES}

if [ ! -d "${WORKDIR}" ]; then
    echo "Creating ${WORKDIR}"
    mkdir -p ${WORKDIR}
fi

cd ${WORKDIR}


CHECK=`ls ${PROJECT_DIR}`
if [ ! "${CHECK}" ]; then
#if [ ! -d ${PROJECT} ]; then
    echo "============================="
    echo "# Cloning ${PROJECT}"
    echo "============================="
    git clone "ssh://git@gitlab.com/acnodal/${PROJECT}.git" ${PROJECT_DIR}
else
    echo "${PROJECT_DIR} already exists"
fi

echo "# DONE"
