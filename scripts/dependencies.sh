#!/bin/bash
# usage $0 [<project-name>]
#       <project-name> - folder name, where to clone sources. If not specified, repository name will be used.

PACKAGES="clang \
    llvm \
    gcc-multilib \
    build-essential \
    python3 \
    python3-pip \
    linux-headers-$(uname -r) \
    libelf-dev \
    zlib1g-dev \
    vagrant"

#set -e

echo "============================="
echo "# Install minimal dependencies"
echo "============================="
sudo apt -y update
sudo apt install -y ${PACKAGES}
sudo snap install go --classic

echo "# DONE"
