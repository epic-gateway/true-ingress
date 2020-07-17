# Packet Forwarding Component

The Packet Forwarding Component (PFC) is the eBPF program and associated infrastructure used to create Service based GUE tunnels between the customer k8s cluster running EGO and the EGW.  The PFC runs on both.

## Description

PFC consists of 2 binaries, one attached to ingress queue and one attached to egress queue of network interface.
Both can be configured to perform certain tasks.
They use shared maps to allow configuration from control plane.
There is set if userspace CLIs to read and write data into maps. 

### Limitations

- IPv4 only


## Repository structure

| Directory name         | Description                                                       |
| ---------------------- | ----------------------------------------------------------------- |
|      docs              | Additional documentation and pictures                             |
|      common            | Common files (from [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial))   |
|      header            | Linux headers (from [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial))  |
|      libbpf            | Libbpf submdule. It is required for linking BFP programs          |
|      src               | Sources of eBPF and helpers                                       |
|      test              | Tests and scripts to setup test topology                          |

## Geting started

### Prerequisites

PFC was developed and tested on Ubuntu 18.04 LTS.

For starting you need only `git` and `make`.

### Clone repository

If you have setup [ssh access](https://gitlab.com/help/ssh/README#locating-an-existing-ssh-key-pair) to gitlab:

    git clone git@gitlab.com:acnodal/packet-forwarding-component.git

otherwise:

    git clone https://gitlab.com/acnodal/packet-forwarding-component.git

### First run

Once you clone project locally, run following command from main folder:

    make init
    
And it will downoad and install all dependencies for you. Once initialized, your system should be ready (unless new dependency is added).
Now you are ready to proceed with building sources.

> Note: `make init` creates also [system docker image](test/docker/README.md#system-image)

### Build

Let's compile TC programs into *.o* files and make userspace binaries like *cli*. 
Simple version is:

    make build

For detailed instructions go to [src](src/).

When binaries and docker image are ready, you can run some tests.

### Run

First let's put compiled binaries into docker image:

    make prod-img

> Note: `make [all]` will build sources including update of prod-image in single step.

And then you can build testing topology and run basic test:

    make test

For detailed information about testing topology and additional test cases proceed to [test](test/) folder. 

> Note: type `make help` to get list of allowed operations.
