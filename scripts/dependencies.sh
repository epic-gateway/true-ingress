#!/bin/bash

PACKAGES="clang \
    llvm \
    gcc-multilib \
    golang-go \
    build-essential \
    python3 \
    python3-pip \
    linux-headers-virtual \
    libssl-dev \
    libelf-dev \
    zlib1g-dev \
    vagrant"

apt -y update
DEBIAN_FRONTEND=noninteractive apt install --yes ${PACKAGES}
