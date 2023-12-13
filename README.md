TrueIngress is the eBPF program and associated infrastructure used to create tunnels between Epic and client k8s clusters running PureGW.

## Description

TrueIngress consists of a set of eBPF programs and a set of command-line programs. The eBPF programs encapsulate and decapsulate packets, and the command-line programs configure the shared maps.

### Limitations

- IPv4 only

## Repository structure

| Directory name         | Description                                                       |
| ---------------------- | ----------------------------------------------------------------- |
|      common            | Common files (from [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial))   |
|      docs              | Additional documentation and pictures                             |
|      headers           | Linux headers (from [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial))  |
|      headers/bpf       | libbpf headers (installed from libbpf submodule)                  |
|      libbpf            | Libbpf submdule. It is required for linking BFP programs          |
|      scripts           | Handful of sripts to help setup dev/test VM                       |
|      src               | Sources of eBPF and helpers                                       |
|      test              | Tests and scripts to setup test topology                          |

## Geting started

### Prerequisites

TrueIngress was developed and tested on Ubuntu 20.04 LTS (which uses kernel 5.4).

If you are running on fresh system (like a VM), you may want to update it first.

You need only `docker`, `git` and `make`. Ensure that you can run docker commands without using `sudo`. You might need to add your login to the `docker` group and log out and back in.

> Note: After installing docker among other dependencies you may need to reboot your system.

### First time build

> Note: type `make help` to get list of allowed operations.

Now you are ready to proceed with building sources.

### Regular build

Let's compile TC programs into *.o* files and make userspace binaries like *cli*.
Simple version is:

    make all

When cource compilation is done, you can check whether kernel can load created BFP binaries by executing:

    make check

In case of success, you should see binaries were attached to both ingress and egress of an interface:

    ens33 (2)
        ingress : filter protocol all pref 49152 bpf chain 0 handle 0x1 pfc_decap_tc.o:[.text] direct-action not_in_hw id 427 tag 4ba81b9389320c66
        egress  : filter protocol all pref 49152 bpf chain 0 handle 0x1 pfc_encap_tc.o:[.text] direct-action not_in_hw id 428 tag fb8fc0a7fe9de7ea

For detailed instructions go to [src](src/).

When binaries and docker image are ready, you can run some tests.

### Test

    make test

> Note: first execution will build the docker image and will take several minutes, subsequent executions will take only a few seconds.

For detailed information about testing topology and additional test cases proceed to [test](test/) folder.

### Install

In order to run on your local setup create true-ingress.tar.bz2:

    make tar

Copy this archive to the target machine and unpack to desired location e.g.:

    tar -jvxf true-ingress.tar.bz2 -C /opt/pfc/

Don't forget to add new location to your PATH:

    export PATH="/opt/pfc/bin:${PATH}"

#### Attach to eth0

Now that TrueIngress is installed, you can attach it to interface eth0:

    sudo pfc_start.sh eth0 TEST 9 9 5000 6000 10 2 3

> Note: Ingress and Egress configuration flags are described [here](src/README.md)

If root doesn't share your PATH update yet, use:

    sudo env "PATH=$PATH" pfc_start.sh eth0 TEST 9 9 5000 6000 10 2 3

#### Detach from eth0

    sudo pfc_stop.sh eth0

or

    sudo env "PATH=$PATH" pfc_stop.sh eth0
