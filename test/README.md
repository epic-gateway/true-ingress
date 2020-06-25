# Packet Forwarding Component


## Demo topology

Simple topology used to validate PFC capabilities.

### Description

Simple IPv4 setup looks like this:

![context](docs/imgs/test_topology.png "Setup with Client, EGW, and Nodes for service proxying using PFC")

Green boxes are docker containers.
Blue "service" is publicly available.
Red "service" are running on local IPs.

eBPF is PCF programm attached to network interface doing packet processing/forwarding/GUE encapsulation and decapsulation in order to achive service proxying seamless.

Network interfaces are listed in case you want to trace flowing packets. 
Each docker container has default network attached to eth0 and connected to internet. That one can be used for updating/downloading/browsing, but is not relevant for purpose of demo topology and is intentionally left out from the picture.
Usually each node is connected to demo network using one network interface (eth1).
Only exception is NAT which translate IP addresses from local network (eth2) to public network (eth1)

#### Client

Send requests to proxy IP and PORT.
Simple linux box with few tools to send/craft packets and collecting metrics.

#### EGW

Exposes local **Services** running on **Nodes** to public network.
Create GUE tunnel (per Service/per Node) to **NodeX** and forward all requests for **ServiceX** into that tunnel.

#### Node1

Running **Services** which are not directly accessible to **Clients**.
Connected to same network as **EGW**.

#### Node2

Running **Services** which are not directly accessible to **Clients**.
Sitting behind **NAT**.
Nodes sitting behing the **NAT** have to send "GUE ping" (periodical GUE control packet) to punch hole into the **NAT** to make them accessible from public network.

#### NAT

Translates IPv4 addresses from local network to the public network.
Simple IPv4 NAT/Firewall box realized using iptables. 

> Note: iptables ... -j MASQUERADE preserves PORT value.


### Run

#### Docker image

Default docker image is based on Ubunutu 18.04 LTS with few tools for crafting, sending packets and collecting metrics.
Also contains web server as testing service.
In the future it will contain eBPF binaries to be loaded on network interfaces.

Docker image related files are locaten in _docker_ subfolder.

Docker image can be (re)built by issuing following command:

    ./docker.sh

This script sources _common.cfg_ which contains default docker image name:

    LINUX_IMG="acnodal-test:latest"

You need to build docker image first to be able to proceed with following steps.

> Note: sudo may be required
#### Topology

First step is to mimic final solution using existing linux infrastructure like _ip route_, _iptables_ and generic GUE tunnel.
This solution requires few workarounds:

1) Linux GUE tunnel doesn't support GUE header fields
2) Address translation is done on **EGW** instead of **NODE**
3) there is one more address translation layer, when packet enter GUE tunnel on **EGW** side
4) GUE control packets are not supported, so GUE ping is replaces by **NODE** address recognition and then this address is supplied to service setup

##### Definition

Plan is that topology _setup/cleanup_ scripts will be topology agnostic anf topology itsels will be defined in _*.cfg_ file.
But at the moment _setup_ still handles some topology specific stuff (like node configuration)

Topology depicted above is defined in:

    basic.cfg

Config file should contain following information (from _basic.cfg_):

List of names of containers with different roles:

    CLIENTS="client"
    PROXIES="egw"
    SERVERS="node1 node2"
    NATS="nat"

List of all containers in topology:

    NODES="${CLIENTS} ${PROXIES} ${SERVERS} ${NATS}"

Network name prefix used for easier identification (for _topo_cleanup_):

    NAME_PREFIX="basic"

Array of docker network names:

    NETWORK_NAME=("foo" "${NAME_PREFIX}-public" "${NAME_PREFIX}-nat")

Array of docker network names:

    NETWORK_SUBNET=("foo" "172.1.0.0/16" "172.2.0.0/16")

> Note: Order of items in NETWORK_NAME and NETWORK_SUBNET must match, because they are used together.

Public IP address of EGW, reachable by all nodes:

    PROXY_IP="5.5.5.5"

Array of list of nodes belonging to each docker network:

    NET_MAPPING=("foo"  "client egw node1 nat" )

> Note: Order of lists must fit NETWORK_NAME array. So mapping is as follows:

    NETWORK_NAME[0]="foo"                    -> NET_MAPPING[0]="foo"
    NETWORK_NAME[1]="${NAME_PREFIX}-public"  -> NET_MAPPING[1]="client egw node1 nat"
    NETWORK_NAME[2]="${NAME_PREFIX}-nat"     -> NET_MAPPING[2]="nat node2"

> Note: Arrays use "foo" as first value to workaround indexing starting from 0.

##### Setup

When you want to bring demo topology up, use following script:

    ./topo_setup.sh <config> [<docker-image>]

where

    <config>        - file with topology description
    <docker-image>  - (OPTIONAL) docker image to use for containers. If not specified, default image will be used.

e.g.:

    ./topo_setup.sh basic.cfg

Script will perform following operations:

1) Check input args
2) Load kernel modules (fou) for GUE tunnel
3) Start docker containers
4) Create docker networks and attach them to containers
5) Configure containers to allow them to perform their roles
6) Check node connectivity

After that topology should be up and running and ready to create some servive and connect to it.

> Note: sudo may be required

##### Teardown

When testing is done you can bring topology down and free resources by using of following command:

    ./topo_cleanup.sh <config> [<docker-image>]

where

    <config>        - file with topology description
    <docker-image>  - (OPTIONAL) docker image used for containers. If not specified, default image will be used.

e.g.:

    ./topo_cleanup.sh basic.cfg

Script will perform following operations:

1) Check input args
2) Stop docker containers
3) Delete docker networks

> Note: sudo may be required

#### Service

    TBD: What is service...

##### Setup

    TBD: How to start Service, configure Node and EGW

##### Teardown

    TBD: How to stop and cleanup

#### Helpers

There is bunch of other scripts to help you with testing and debugging. They will be described here.

##### cli.sh

    TBD: What id does and how to run it

##### pktdump.sh

    TBD: What id does and how to run it

##### test_icmp.sh

    TBD: What id does and how to run it

##### test_tcp.sh

    TBD: What id does and how to run it

##### test_udp.sh

    TBD: What id does and how to run it

## Tests

> Note: All tests are manual no automated framework for result evaluation planned yet.

    TBD: list of test cases
