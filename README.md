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

## Geting started

### Prerequisites

PFC was developed and tested on Ubuntu 18.04 LTS.

For starting you need only:

    git make

### Clone repository

Once you clone project locally, run following command from main folder:

    make init
    
And it will get all dependencies for you. Now you are ready to procees with building sources.

### Build

Let's compile TC programs into *.o* files and make userspace binaries like *cli*. 
Simple version is:

    make build

For detailed instructions go to [src](src/).

When binaries and docker image are ready, you can run some tests.

### Run

First let's put compiled binaries into docker image:

    make prod-img

And then you can build testing topology and run basic test:

    make test

For detailed information about testing topology and additional test cases proceed to [test](test/) folder. 
