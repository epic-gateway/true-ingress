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

For starting you need only:

    git make

Once you clone project locally, issue:

    make init
    
And it will get all dependencies for you.

## Build

Follow instructions in ![src](src/README.org) folder in order to build eBPF programs and helpers.

## Run

Follow instructions in ![test](test/README.org) folder in order to setup a demo topology and run some tests. 
