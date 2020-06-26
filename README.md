# Packet Forwarding Component

The Packet Forwarding Component (PFC) is the eBPF program and associated infrastructure used to create Service based GUE tunnels between the customer k8s cluster running EGO and the EGW.  The PFC runs on both.

## Description

    TBD

### Limitations

- IPv4 only


## Repository structure

| Directory name         | Description                                                  |
| ---------------------- | ------------------------------------------------------------ |
|      docs              | Additional documentation and pictures                        |
|      src               | Sources of eBPF and helpers                                  |
|      test              | Tests and scripts to setup test topology                     |

## Prerequisites

PFC was developed and tested on Ubuntu 18.04 LST.

Building and testing require following packages:

    git build-essential llvm clang docker.io python python-pip

> Note: Only mandatory packages are listed. Tools for improving quality of life (like favorite IDE) are not listed.

Python scripts have following dependencies (pip install ...):

    TBD

## Build

    TBD

## Run

Check instructions in 'test' folder to setup a demo topology and run some tests. 
