# Packet Forwarding Component

This folder contains TC files and scripts to attach and detach TC program to network interface.

## Source structure

| Directory name         | Description                                                       |
| ---------------------- | ----------------------------------------------------------------- |
|    pfc_ingress_tc.c    | PFC RX TC program                                                 |
|    pfc_egress_tc.c     | PFC TX TC program                                                 |
|    egw_ingress_tc.c    | EGW RX TC program                                                 |
|    egw_egress_tc.c     | EGW TX TC program                                                 |
|    attach_tc.sh        | Attach TC binary to network interface                             |
|    detach_tc.sh        | Detach TC binary from network interface                           |
|    reattach_tc.sh      | Reattach new TC binary to network interface                       |
|    show_tc.sh          | Show what is attached to network interface                        |


## Description

In current version There are are only dummy TC binaries which dump size of incomming or outgoing packets.

## Build

There is Makefile provided, so building binaries is as simple as:

    make

It will build also dependencied (e.g. libbpf)

## Attach

There is a script for attaching TC program to ingress or egress queue of network interface.

    ./attach_tc.sh <interface> <ebpf-program> [ingress|egress]

Example:

    ./attach_tc.sh eth0 pfc

To attach pfc program to both ingress and egress of eth0 or:

    ./attach_tc.sh eth0 egw ingress

To attach egw program to ingress of eth0.

Attached eBPF programm uses kernel trace to log information.
Logged messages can be found:

    less /sys/kernel/debug/tracing/trace

However this looks unreliable, some information seems to be missing occasionaly.

## Detach

Removes attached TC program from ingress or egress queue of network interface.

    ./detach_tc.sh <interface> [ingress|egress]

Example:

    ./detach_tc.sh eth0 pfc

Detaches TC program from both ingress and egress of eth0 or:

    ./detach_tc.sh eth0 ingress

To detach TC program from ingress of eth0.

## Show

Show what is attached to network interface.

    ./attach_tc.sh <interface> [ingress|egress]

Example:

    ./show_tc.sh eth0

or:

    ./show_tc.sh eth0 ingress

## Reattach

Reattach first detaches existing TC program and then attaches new to network interface.

    ./reattach_tc.sh <interface> <ebpf-program> [ingress|egress]

Example:

    ./reattach_tc.sh eth0 pfc

To remove current and attach pfc program to both ingress and egress of eth0 or:

    ./reattach_tc.sh eth0 egw ingress

To remove current and attach egw program to ingress of eth0.
