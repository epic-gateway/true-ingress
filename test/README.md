# True Ingress
## Demo topology

Simple topology used to validate True Ingress.

### Description

Simple IPv4 setup looks like this:

![context](docs/imgs/test_topology.png "Setup with Client, Epic, and Nodes for service proxying")

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

#### Epic

Exposes local **Services** running on **Nodes** to public network.
Create GUE tunnel (per Service/per Node) to **NodeX** and forward all requests for **ServiceX** into that tunnel.

#### Node1

Running **Services** which are not directly accessible to **Clients**.
Connected to same network as **Epic**.

#### Node2

Running **Services** which are not directly accessible to **Clients**.
Sitting behind **NAT**.
Nodes sitting behing the **NAT** have to send "GUE ping" (periodical GUE control packet) to punch hole into the **NAT** to make them accessible from public network.

#### NAT

Translates IPv4 addresses from local network to the public network.
Simple IPv4 NAT/Firewall box realized using iptables. 

> Note: iptables ... -j MASQUERADE preserves PORT value.


### Run

In order to successfully perform some tests you need to go through following steps:

1) Build docker image
2) Bring up topology consistg of at least one of each: **Client**, **Epic**, **Node**. **Epic** is running public ip address accessible from all other nodes.
3) Create a service on a **Node**. Service is not accessible from network.
4) Setup forwarding, this create GUE tunnel, forwarding rules and neccessary IP address translation
5) Now client can access service throug **Epic's** pulic IP address and PORT

#### Docker image

Docker related files are located in *docker* subfolder.
Check inside about details.

#### Topology

First step is to mimic final solution using existing linux infrastructure like _ip route_, _iptables_ and generic GUE tunnel.
This solution requires few workarounds:

1) Linux GUE tunnel doesn't support GUE header fields.
2) Address translation is done on **Epic** instead of **NODE**.
3) There is one more address translation layer, when packet enter GUE tunnel on **Epic** side. This could be avoided by source based routing on **NODE**.
4) Linux GUE implementation doesn't allow to fill and parse GUE header.
5) GUE control packets are not supported, so GUE ping is replaced by **NODE** address recognition and then this address is supplied to service setup.
6) There can be only one service active at a time with one GUE tunnel using 6080 as source and destination port. Servive namespace need to be separated, to allow them to run in parallel. GUE source and destination ports are configurable, but for lack of time it was not testied with different values yes.

#####  Definition

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

Public IP address of Epic, reachable by all nodes:

    PROXY_IP="5.5.5.5"

Array of list of nodes belonging to each docker network:

    NET_MAPPING=("foo" "client egw node1 nat" "nat node2")

> Note: Order of lists must fit NETWORK_NAME array. So mapping is as follows:

    NETWORK_NAME[0]="foo"                    -> NET_MAPPING[0]="foo"
    NETWORK_NAME[1]="${NAME_PREFIX}-public"  -> NET_MAPPING[1]="client egw node1 nat"
    NETWORK_NAME[2]="${NAME_PREFIX}-nat"     -> NET_MAPPING[2]="nat node2"

> Note: Arrays use "foo" as first value to workaround indexing starting from 0.

##### Setup

When you want to bring demo topology up, use following script:

    ./topo_setup.sh <config> [<docker-image>]

Where

    <config>        - file with topology description
    <docker-image>  - (OPTIONAL) docker image to use for containers. If not specified, default image will be used.

Example:

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

Where

    <config>        - file with topology description
    <docker-image>  - (OPTIONAL) docker image used for containers. If not specified, default image will be used.

Example:

    ./topo_cleanup.sh basic.cfg

Script will perform following operations:

1) Check input args
2) Stop docker containers
3) Delete docker networks

> Note: sudo may be required

##### Check

For the sake of completeness there is a script that enlists all topology related docker containers and networks running:

    ./topo_check.sh basic.cfg


#### Service

For purpose of this demo topology by service we mean HTTP server. Different kind of services can be added later.

HTTP server can run on given **NODE** listening on give IP address and PORT.
HTTP server can serve content of file specified in URL.
Once service is started there are few files created.

1) hello - contains service identification, by displaying thi file user should easily see which service is connected to
2) data_10M.bin, data_5M.bin, data_2M.bin, data_1M.bin - binary file od specific size for longer download.

##### Setup

To start demo HTTP service run following command:

    ./http_start.sh <node> <ip> <port> <service-id>
    
Example:

    ./http_start.sh node1 1.1.1.1 4000 100

It will:

1) Attach to docker named _< node >_.
2) Configure _< ip >_ on local _lo_ intreface.
3) Start HTTP server listening on _< ip >_:_< port >_.
4) Create hello file including _< service-id >_ and other files for download.

##### Teardown

    TBD: How to stop and cleanup

#### Forwarding

Service is running locally. To make it publicly available, create proxy setting on **Epic**. **Epic** will forward incomming requests to the backend.

Once service and TrueIngress is running and configured, you can configure service forwarding by using `pfc_add.sh` script described below.


##### Teardown

    TBD: How to stop and cleanup

#### Testing

Now you are able to run HTTP requests against **Epic** and it will forward it to the backend.
To see what operation can be done, proceed to followig section.


## Tests

> Note: All tests are manual no automated framework for result evaluation planned yet.
> Note: At the moment service and forwarding cleanup desn't work properly therefore topology has to be created and discarded for each test separately.

### basic

Set of tests for topology setup/cleanup, services create/delete, service forwarding create/delete.

### multiservice

Set of tests for running multiple service instances on same node.

### ebpf

Set of tests for attaching and detaching TC programs to **Epic** and **NODE**.


## Interface scripts

Located on docker image under /opt/acnodal/bin/

### pfc_start.sh

Start and configure PCF.

- start GUE ping daemon
- attach eBPF binaries to interface
- configure
- initialize port pool

    ./pfc_start.sh <nic> <name> <conf-rx> <conf-tx> <port-min> <port-max> [<delay>]
       <nic>       - Interface to bind to
       <name>      - Instance name
       <conf-rx>   - Ingress configuration flags
       <conf-tx>   - Egress configuration flags
       <port-min>  - Gue tunnel port range lower bound
       <port-max>  - Gue tunnel port range upper bound
       <delay>     - (Optional) Interval of sending GUE pings in seconds

Example:

    ./pfc_start.sh eth1 node1 9 9 5000 6000 10
    
which will attach TrueIngress to eth1. Instance will identify itself in log as "node1". Ingress operation mode is 9, egress operation mode is 9 (for details check TABLE-CONFIG). GUE ports will be assigned from range <5000, 6000> and GUE ping daemon will be started with period of 10s.

### pfc_stop.sh

Stop and clean up.

- stop GUE ping daemon
- detach eBPF binaries from interface
- cleanup port pool

    ./pfc_stop.sh <nic>
       <nic>       - Interface to bind to

Example:

    ./pfc_stop.sh eth1

which will remove eBPF attached to eth1.

### pfc_add.sh

Configure GUE tunnel and service forwarding.

    ./pfc_add.sh [-p] <nic> <group-id> <service-id> <passwd> <remote-tunnel-ip> <remote-tunnel-port> <proto> <proxy-ip> <proxy-port> <backend-ip> <backend-port>
       <-p>                    - (Optional) Send one time GUE ping
       <nic>                   - Interface to sending one time GUE ping from
       <group-id>              - Group ID
       <service-id>            - Service ID
       <passwd>                - Security key
       <remote-tunnel-ip>      - Remote GUE tunnel IPv4 address
       <remote-tunnel-port>    - Remote GUE tunnel port
       <proto>                 - Service IP protocol
       <proxy-ip>              - Service proxy IPv4 address
       <proxy-port>            - Service proxy port
       <backend-ip>            - Service backend IPv4 address
       <backend-port>          - Service backend port

Example:

    ./pfc_add.sh eth1 1 100 "abcdefgh12345678" 172.1.0.3 5000 tcp 5.5.5.5 3100 1.1.1.1 4000

### pfc_delete.sh

Delete GUE tunnel and service forwarding.

    ./pfc_delete.sh <group-id> <service-id>
       <group-id>              - Group ID
       <service-id>            - Service ID

Example:

    ./pfc_delete.sh 1 100

### pfc_list.sh

Show content of lookup tables.

    ./pfc_list.sh


### port_init.sh

Initialize port pool from range specifiaec by <min> and <max> (including).

    ./port_init.sh <min> <max>

### port_alloc.sh

Get first port from pool.

    ./port_alloc.sh

### port_free.sh

Insert port at the end of the pool.

    ./port_free.sh <port>

### port_list.sh

Show content of GUE port pool.

    ./port_list.sh


## Helpers

There is bunch of other scripts to help you with testing and debugging. They will be described here.

### gue_ping.sh

This is workaroud for periodical GUE control packet. It does not contain _Service-id_ in GUE header, but it still punches hole into the NAT/Firewall:

    ./gue_ping.sh <node> <service-id> <remote-ip> <remote-port> <local-port> <delay>

Example:

    ./gue_ping.sh node2 200 172.1.0.4 6080 6080 30

It sends UDP packet from localhost:_< local-port >_ to _< remote-ip >_:_< remote-port >_ every _< delay >_ seconds.
a.k.a.
It sends UDP packet from localhost:6080 to 172.1.0.4:6080 every 30 seconds.

### egw_setup.sh

Configure GUE tunnel, forwarding and address translation on _< node >_:

    ./egw_setup.sh <node> <service-id> <proto> <service-ip> <service-port> <real-ip> <real-port> <proxy-ip> <proxy-port> <foo-ip>

Example:

    ./egw_setup.sh egw 100 tcp 1.1.1.1 4000 172.1.0.5 6080 5.5.5.5 3100 10.1.1.100

> Note: The _< foo-ip >_ address is a routing workaround. It is IP address assigned to _tun_ interface on **Epic** side. **Epic** is doing SNAT to this ip address, and **Node** uses it ad destination for routing packets into the tunnel. 

### pfc_setup.sh

Configure GUE tunnel and forwarding on _< node >_:

    ./pfc_setup.sh <node> <service-id> <proto> <service-ip> <service-port> <remote-tunnel-ip> <remote-tunnel-port> <foo-ip>

Example:

    ./pfc_setup.sh node1 100 tcp 1.1.1.1 4000 172.1.0.4 6080 10.1.1.100

> Note: The _< foo-ip >_ address is a routing workaround. It is IP address assigned to _tun_ interface on **Epic** side. **Epic** is doing SNAT to this ip address, and **Node** uses it ad destination for routing packets into the tunnel.    

### cli.sh

This is wrapper to help you to attach linux console of _< docker-name >_ container:

    ./cli.sh <docker-name>

Example:

    ./cli.sh client

### pktdump.sh

This is wrapper start tcpdump on _< interface >_ inside _< docker >_ container:

    ./pktdump.sh <docker-name> <interface> [<filter>]

Example:

    ./pktdump.sh egw eth1 "udp and port 6080"
    
Optionally you can specify filter, what kind of packets you are insterested in.

> Note: By default it executes with "-nvvvXXes 0", which means no name resolving, verbose, including Ethernet header, including hexdump of whole packet.

### test_icmp.sh

This is wrapper send ICMP ping to given _< ip >_ from all _< node-list >_:

    ./test_icmp.sh <ip> ["<node-list>"]

Where _< node-list >_ can be none or more docker containers.
In case no container specified, ping will be sent from host.

Example:

    ./test_icmp.sh 5.5.5.5 client

To send ping from _client_

    ./test_icmp.sh 5.5.5.5 "client node1 node2"

To send ping from multiple containers

    ./test_icmp.sh 5.5.5.5

To send ping from host
