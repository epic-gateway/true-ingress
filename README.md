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
|      common            | Common files (from [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial))   |
|      docs              | Additional documentation and pictures                             |
|      header            | Linux headers (from [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial))  |
|      libbpf            | Libbpf submdule. It is required for linking BFP programs          |
|      scripts           | Handful of sripts to help setup dev/test VM                       |
|      src               | Sources of eBPF and helpers                                       |
|      test              | Tests and scripts to setup test topology                          |

## Geting started

### Prerequisites

PFC was developed and tested on Ubuntu 18.04 LTS (requires kernel version bump to at least 5.2) and 20.04 LTS (which uses kernel 5.4).

If you are running on fresh system (like VM), you may want to update it first.

> Hint: look at [update.sh](scripts/update.sh)

You need only `docker`, `git` and `make`.  We recommend the docker-ce distribution (i.e., docker.com's distro) instead of the version packaged by Ubuntu as that's what Kubernetes recommends.

https://docs.docker.com/get-docker/

Ensure that you can run docker commands without using `sudo`. You might need to add your login to the `docker` group and log out and back in.

### Clone repository

You may want to setup ssh access first [ssh access](https://gitlab.com/help/ssh/README#locating-an-existing-ssh-key-pair).

> Hint: some steps are already automated in [ssh_init.sh](scripts/ssh_init.sh), but you need to generate key-pair first and register public key on gitlab manually first.

If you have setup to gitlab:

    git clone git@gitlab.com:acnodal/packet-forwarding-component.git

otherwise:

    git clone https://gitlab.com/acnodal/packet-forwarding-component.git

> Hint: cloning with installing of some basic dependencies is already automated in [clone_pfc.sh](scripts/clone_pfc.sh).

### First time build

Once you clone project locally, run following command from main folder:

    make init

And it will downoad and install all dependencies for you. Once initialized, your system should be ready (unless new dependency is added). It may take few minutes.

> Note: After installing docker among other dependencies you may need to reboot your system.

Now you are ready to proceed with building sources.

> Note: `make init` creates also [system docker image](test/docker/README.md#system-image)

### Regular build

Let's compile TC programs into *.o* files and make userspace binaries like *cli*. 
Simple version is:

    make build

When cource compilation is done, you can check whether kernel can load created BFP binaries by executing:

    make check

In case of success, you should see binaries were attached to both ingress and egress of an interface:

    ens33 (2)
        ingress : filter protocol all pref 49152 bpf chain 0 handle 0x1 pfc_ingress_tc.o:[.text] direct-action not_in_hw id 427 tag 4ba81b9389320c66 
        egress  : filter protocol all pref 49152 bpf chain 0 handle 0x1 pfc_egress_tc.o:[.text] direct-action not_in_hw id 428 tag fb8fc0a7fe9de7ea

For detailed instructions go to [src](src/).

When binaries and docker image are ready, you can run some tests.

### Test

First let's put compiled binaries into docker image:

    make prod-img

> Note: first execution will build the docker image and will take several minutes, subsequent executions take only few seconds.
> Note: `make [all]` will build sources including update of prod-image in single step.

And then you can build testing topology and run basic test:

    make test

For detailed information about testing topology and additional test cases proceed to [test](test/) folder. 

> Note: type `make help` to get list of allowed operations.
