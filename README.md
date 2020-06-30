# Packet Forwarding Component

The Packet Forwarding Component (PFC) is the eBPF program and associated infrastructure used to create Service based GUE tunnels between the customer k8s cluster running EGO and the EGW.  The PFC runs on both.

## Description

    TBD

### Limitations

- IPv4 only


## Repository structure

| Directory name         | Description                                                       |
| ---------------------- | ----------------------------------------------------------------- |
|      docs              | Additional documentation and pictures                             |
|      common            | Common files (from https://github.com/xdp-project/xdp-tutorial)   |
|      header            | Linux heades (from https://github.com/xdp-project/xdp-tutorial)   |
|      libbpf            | Libbpf submdule. It is required for linking BFP programs          |
|      src               | Sources of eBPF and helpers                                       |
|      test              | Tests and scripts to setup test topology                          |

## Prerequisites

PFC was developed and tested on Ubuntu 18.04 LST.

Building and testing require following packages:

    git llvm clang build-essential docker.io python3 python3-pip libelf-dev libpcap-dev gcc-multilib linux-headers-$(uname -r)

> Note: Only mandatory packages are mentioned. Tools for improving quality of life (like favorite IDE) are not listed.

Kernel version required at least 5.1

    TBD: verify dependencies on clean installation

Python scripts have following dependencies (pip3 install ...):

    TBD: verify dependencies on clean installation

## Build

Follow instructions in [[file:src/README.org][src]] folder in order to build eBPF programs and helpers.

## Run

Follow instructions in [[file:test/README.org][test]] folder in order to setup a demo topology and run some tests. 
