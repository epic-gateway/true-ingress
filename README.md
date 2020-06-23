# Packet Forwarding Component

The Packet Forwarding Component (PFC) is the eBPF program and associated infrastructure used to create Service based GUE tunnels between the customer k8s cluster running EGO and the EGW.  The PFC runs on both.

## Description

    TBD

### Limitations

- IPv4 only


## Repository structure

| Directory name         | Description                                                  |
| ---------------------- | ------------------------------------------------------------ |
|      docs              | Additional documentation and pictures                        |
|      src               | Sources of eBPF and helpers                                  |
|      test              | Tests and scripts to setup test topology                     |

## Prerequisites

    TBD

## Build

    TBD

## Run

Check instructions in 'test' folder to setup a demo topology and run some tests. 
