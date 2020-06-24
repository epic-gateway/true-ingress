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


### Setup

#### Topology

    TBD

#### Service

    TBD


## Tests
