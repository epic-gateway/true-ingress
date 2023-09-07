#!/bin/bash

PACKAGES="clang \
    llvm \
    gcc-multilib \
    golang-go \
    build-essential \
    linux-headers-virtual \
    libssl-dev \
    libelf-dev \
    zlib1g-dev"

apt -y update
DEBIAN_FRONTEND=noninteractive apt install --yes ${PACKAGES}
