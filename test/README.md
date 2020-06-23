# Packet Forwarding Component


## Demo topology

Simple topology used to validate PFC capabilities.

### Description

![context](docs/imgs/test_topology.png "Setup with Client, EGW, and Nodes for service proxying using PFC")

Consists of multiple docker images in following roles:

#### Client

Send requests

#### EGW

    TBD

#### Node1

Running service.
Not directly accessible to clients.
Connected to same network as EGW.

#### Node2

Running service.
Not directly accessible to clients.
Sitting behind NAT.

#### NAT

Simple IPv4 address translation & Firewall


### Setup

#### Topology

    TBD

#### Service

    TBD


## Tests
