#!/bin/bash
# usage $0 [<project-name>]
#       <project-name> - folder name, where to clone sources. If not specified, repository name will be used.

WORKDIR=./                # Where to create project
if [ "$1" ] ; then
    WORKDIR=$1              # Project name
fi

PROJECT="egw"
if [ "$2" ] ; then
    PROJECT=$2              # Project name
fi

if [ "$(egrep -c '(svm|vmx)' /proc/cpuinfo)" == "0" ] ; then
    echo "CPU doesn't support virtualzation"
    exit 1
fi

if [ ! "$(locate kvm-ok)" ] ; then
    sudo apt install cpu-checker
fi

if [ ! "$(kvm-ok | grep 'KVM acceleration can be used')" ] ; then
    echo "KVM acceleration not supported"
    exit 1
fi


# minimal dependencies to allow "git clone ..." and "make init"
PACKAGES="\
    git \
    vagrant \
    qemu-kvm \
    libvirt-daemon-system \
    libvirt-clients \
    bridge-utils \
    virtinst 
    virt-manager \
    ansible"

#set -e

#echo "============================="
#echo "# Update system"
#echo "============================="
sudo apt update -y
sudo apt install software-properties-common
sudo apt-add-repository --yes --update ppa:ansible/ansible


echo "============================="
echo "# Install dependencies"
echo "============================="
sudo apt install -y ${PACKAGES}


sudo adduser ${USER} libvirt

if [ ! -d "${WORKDIR}" ]; then
    echo "### Creating ${WORKDIR}"
    mkdir -p ${WORKDIR}
fi

cd ${WORKDIR}

if [ ! -d ${PROJECT} ]; then
    echo "============================="
    echo "# Cloning sources"
    echo "============================="
    git clone "ssh://git@gitlab.com/acnodal/egw.git" ${PROJECT}
else
    echo "'${PROJECT}' already exists"
fi

echo "# DONE"
