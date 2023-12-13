TrueIngress is the eBPF program and associated infrastructure used to create tunnels between Epic and the customer k8s cluster running PureGW.

## Description

TrueIngress consists of 2 binaries: one that encapsulates packets, and one that decapsulates.
They use shared maps to allow configuration from control plane.

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

TrueIngress was developed and tested on Ubuntu 18.04 LTS (requires kernel version bump to at least 5.2) and 20.04 LTS (which uses kernel 5.4).

If you are running on fresh system (like VM), you may want to update it first.

> Hint: look at [update.sh](scripts/update.sh)

You need only `docker`, `git` and `make`.  We recommend the docker-ce distribution (i.e., docker.com's distro) instead of the version packaged by Ubuntu as that's what Kubernetes recommends.

https://docs.docker.com/get-docker/

Ensure that you can run docker commands without using `sudo`. You might need to add your login to the `docker` group and log out and back in.

### Clone repository

You may want to setup ssh access first [ssh access](https://gitlab.com/help/ssh/README#locating-an-existing-ssh-key-pair).

> Hint: some steps are already automated in [ssh_init.sh](scripts/ssh_init.sh), but you need to generate key-pair first and register public key on gitlab manually first.

    git clone git@gitlab.com:acnodal/epic/true-ingress.git

> Hint: cloning with installing of some basic dependencies is already automated in [clone_pfc.sh](scripts/clone_pfc.sh).

### First time build

Once you clone project locally, run following command from main folder:

    make init

And it will downoad and install all dependencies for you. Once initialized, your system should be ready (unless new dependency is added). It may take few minutes.

> Note: After installing docker among other dependencies you may need to reboot your system.
> Note: type `make help` to get list of allowed operations.
> Note: `make init` creates also [system docker image](test/docker/README.md#system-image)

Now you are ready to proceed with building sources.

### Regular build

Let's compile TC programs into *.o* files and make userspace binaries like *cli*.
Simple version is:

    make build

When cource compilation is done, you can check whether kernel can load created BFP binaries by executing:

    make check

In case of success, you should see binaries were attached to both ingress and egress of an interface:

    ens33 (2)
        ingress : filter protocol all pref 49152 bpf chain 0 handle 0x1 pfc_decap_tc.o:[.text] direct-action not_in_hw id 427 tag 4ba81b9389320c66
        egress  : filter protocol all pref 49152 bpf chain 0 handle 0x1 pfc_encap_tc.o:[.text] direct-action not_in_hw id 428 tag fb8fc0a7fe9de7ea

For detailed instructions go to [src](src/).

When binaries and docker image are ready, you can run some tests.

### Test

First let's put all compiled binaries and helper scripts into docker image:

    make docker

> Note: first execution will build the docker image and will take several minutes, subsequent executions will take only few seconds.

And then you can build testing topology and run basic test:

    make test

> Note: `make test` executed `make docker` on your behalf.

There are alot more tests.
For detailed information about testing topology and additional test cases proceed to [test](test/) folder.

### Install

On order to run on your local setup create true-ingress.tar.bz2:

    make tar

Copy this archive to machine where you want to execute it and unpack to desired location e.g.:

    tar -jvxf true-ingress.tar.bz2 -C /opt/pfc/

Don't forget to add new location to your PATH:

    export PATH="/opt/pfc/bin:${PATH}"

#### Attach to eth0

Now that TrueIngress is installed, you can attach it to interface eth0:

    sudo pfc_start.sh eth0 TEST 9 9 5000 6000 10 2 3

Where:

    syntax: $0 <nic> <name> <conf-rx> <conf-tx> <port-min> <port-max>
        <nic>             - Interface to bind TrueIngress to
        <name>            - Instance name
        <conf-rx>         - Inress configuration flags
        <conf-tx>         - Egress configuration flags
        <port-min>        - Gue tunnel port range lower bound
        <port-max>        - Gue tunnel port range upper bound
        <gue-delay>       - (Optional) Interval of sending GUE pings (in seconds)

> Note: Ingress and Egress configuration flags are described [here](src/README.md)

If root doesn't share your PATH update yet, use:

    sudo env "PATH=$PATH" pfc_start.sh eth0 TEST 9 9 5000 6000 10 2 3

#### Detach from eth0

    sudo pfc_stop.sh eth0

or

    sudo env "PATH=$PATH" pfc_stop.sh eth0



# Go API

Provides Go bindings to setup/delete/list service forwarding.

### pfc/pfc.go

API itself. Provides set of functions to add, delete, get list of services.

#### func Version() string

Return version infomation (string).

> Note: There is no official versioning yet.

#### func Check() (bool, string)

Return whether TrueIngress is ready to be used (bool) and reason (string) in case it is not.

#### func ForwardingAdd(nic string, group_id int, service_id int, passwd string, proto string, proxy_ip net.IP, proxy_port int, service_ip net.IP, service_port int, gue_remote_ip net.IP, gue_remote_port int) (net.IP, int, error)

Configure forwarding.
Returns allocated IP and port for GUE tunnel.

ForwardingAdd should be called firts on EGW side with GUE remote ip:port set as "0.0.0.0:0".
EGW allocates some ip:port and retuns it to the caller. Caller should use that ip:port as GUE remote ip:port next when configure forwarding on Node.
Node based on that information will send GUE ping (control packet) to the EGW, based on which EGW resolves Node's GUE ip:port.

#### func ForwardingRemove(group_id int, service_id int) error

Delete forwarding for group-id, service-id pair.
Returns nil or error.

#### func GetServiceKey(gid int, sid int) int

Compute 32bit number from group-id, service-id pair.

#### func ForwardingGetAll() (map[int]Tunnel, map[int]Service, error)

Return list of all configured tunnels and services or error.
Tunnels are accessible by tunnel-id, services are accessible by key computed from group-id, service-id pair (using `GetServiceKey()`).

> Note: There is 1:1 mapping betweet services and tunnels, combination of group-id and service-id is used as key to identify both service and related tunnel.

#### func ForwardingGetService(gid int, sid int) (Service, bool)

In case bool=true: returns service identified by group-id, service-id pair. Uses `ForwardingGetAll()` in background.
In case bool=false: service does not exist. 

#### func ForwardingGetTunnel(tid int) (Tunnel, bool)

In case bool=true: returns tunnel identified by tunnel-id (group-id, service-id pair computed by `GetServiceKey()`). Uses `ForwardingGetAll()` in background.
In case bool=false: tunnel does not exist. 

### gue_ping_svc_auto.go

Go daemon which periodically sends GUE ping for all configured tunnels.
