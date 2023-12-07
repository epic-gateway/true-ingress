# Packet Forwarding Component

## Source structure

| Directory name   | Description                                    |
| ---------------- | ---------------------------------------------- |
| go               | Go API                                         |
| cli              | Command-line programs                          |
| bpf              | BPF programs                                   |
| attach_tc.sh     | Attach TC binary to network interface          |
| detach_tc.sh     | Detach TC binary from network interface        |
| reattach_tc.sh   | Reattach new TC binary to network interface    |
| show_tc.sh       | Show what is attached to network interface     |

## Description

### Assumptions and Restrictions
- Have one RX and one TX TC applicable on both Epic and client node (behavior tweaked by configuration)
- Share lookup maps if possible (no conflicts)
- Keep it modular in case of future reorganization
- Actions cannot chain (one TC instance can perform single operation ... There may be list of actions, but first match wins). There is no hard limitation, why action should not chain, but it would complicate things.
- Adding `tunnel-id` in GUE ping header + in `TABLE-TUNNEL` and `TABLE-SERVICE`. It allows to use multiple `services` in one `GUE tunnel` or one `service` per `GUE tunnel`. In case NAT settings change over time, this allows that all affected `GUE tunnels` will remain updated.

### TrueIngress

Set of two eBPF programs for Traffic Control (TC). One attached to ingress and other to egress queue of network interface.

#### Packet Flows (single action)

- Epic, NODE, CLIENT, PureGW - Role
- RX, TX - ingress or egress TC

##### Standard Mode:
Returning traffic in **NODE** is encapsulated and sent back to **Epic**.
```
ROLE		ACTION
-----------------------------
CLIENT		SEND-REQUEST
Epic		ROUTE
Epic:TX		ACTION-ENCAP
NODE:RX		ACTION-DECAP
KUBERNETES	PROCESS
NODE:TX		ACTION-ENCAP
Epic:RX		ACTION-DECAP
Epic		ROUTE
CLIENT		RECEIVE-REPLY
```
##### DSO Mode
Returning traffic on **NODE** is not encapsulated, but sent directly to **CLIENT** instead.
```
ROLE		ACTION
-----------------------------
CLIENT		SEND-REQUEST
Epic		ROUTE
Epic:TX		ACTION-ENCAP
NODE:RX		ACTION-DECAP
KUBERNETES	PROCESS
CLIENT		RECEIVE-REPLY
```
##### GUE Ping
Parse GUE traffic and in case of Control packet update tunnel remote endoint.
```
ROLE		ACTION
-----------------------------
PureGW		SEND-GUE-PING
Epic:RX		ACTION-UPDATE
```

#### TC Actions (and required Tables)

##### Ingress
Will perform one of following actions on incoming packet:
```
ACTION		TABLES
-----------------------------
ACTION-DECAP    (TABLE-DECAP, TABLE-VERIFY)
ACTION-UPDATE   (TABLE-TUNNEL)
```
##### Egress
Will perform one of following actions on departing packet:
```
ACTION		TABLES
-----------------------------
ACTION-ENCAP    (TABLE-ENCAP, TABLE-TUNNEL)
```

> Note: Both Ingress and Egress use `TABLE-CONFIG`

#### Table structure

##### Tables
```
NAME		KEY -> VALUE
-----------------------------
TABLE-DECAP	EP -> <EMPTY>
TABLE-ENCAP	EP -> SERVICE
TABLE-VERIFY	SID -> key
TABLE-TUNNEL	tunnel-id -> TUNNEL
TABLE-CONFIG	RX|TX -> config
```
Where
```
EP	{ip, proto, port}				// Endpoint 3-tuple
TUNNEL	{local-ip, local-port, remote-ip, remote-port}	// Tunnel outer header ... remote-ip and remote-port are parsed from GUE ping packet
SID	{group-id, service-id}				// Service identifier
SERVICE	{tunnel-id, SID, key}				// GUE Header information
```

> Note: If table with same name is used by both Ingress and Egress, then it means table is shared (there should be no collisions).
> Note: Only `TABLE-TUNNEL` can be updated internally (by `GUE Ping` source ip and port), rest of the tables will be programmed by control plane.

### Attach/Detach scripts

Uses iproute2 suite to attach/detach eBPF in TC mode.

#### Done

- Attach TC to ingress/egress
- Expose shared maps

### CLIs

Set of userspace programs allowing control plain to program lookup tables.

#### Config CLI

Set instance identity, log level, behavior.
Manages following tables:
```
TABLE-CONFIG
```

#### Tunnel CLI

Defines GUE tunnel with local and remote endpoints (ip:port).
Manages following tables:
```
TABLE-DECAP
TABLE-TUNNEL
```

#### Service CLI

Defines service with proxy ip:port, real ip:port, service-id, group-id, security key and what tunnel it uses.
Manages following tables:
```
TABLE-NAT
TABLE-ENCAP
TABLE-VERIFY
```

#### Done

- PoC quality
- Read from /write into shared maps to configure TrueIngress.

#### Todo

- Statistics
- Extend configuration with other options if needed
- Error handling


## Operations

### Build

There is Makefile provided, simplest form is:

    make [all]

It will build also dependencies (e.g. libbpf)

#### Clean sources

    make clean

#### Build sources

    make build

#### Pack binaries into docker image

    make prod-img

#### Quick consistency check

    make check

Performs attach and detach on primary (where default GW is) network interface.

> Note: There are additional options, for more details check `make help`.

### Attach/Detach

#### Attach

There is a script for attaching TC program to ingress or egress queue of network interface. If interface is not specified, default interface (where gefault GW is) will be used.

    ./attach_tc.sh [<interface>] [ingress|egress]

Example:

    ./attach_tc.sh eth0

To attach bpf programs to both ingress and egress of eth0 or:

    ./attach_tc.sh eth0 ingress

To attach bpf program to ingress of eth0.

Attached eBPF programm uses kernel trace to log information.
Logged messages can be found:

    less /sys/kernel/debug/tracing/trace

However this looks unreliable, some information seems to be missing occasionaly.

> Note: To check BPF loading error after build try `make attach` and then  `make dettach`.

#### Detach

Removes attached TC program from ingress or egress queue of network interface. If interface is not specified, default interface (where gefault GW is) will be used.

    ./detach_tc.sh [<interface>] [ingress|egress]

Example:

    ./detach_tc.sh eth0

Detaches TC program from both ingress and egress of eth0 or:

    ./detach_tc.sh eth0 ingress

To detach TC program from ingress of eth0.

#### Show

Show what is attached to network interface. If interface is not specified, default interface (where gefault GW is) will be used.

    ./show_tc.sh [<interface>] [ingress|egress]

Example:

    ./show_tc.sh eth0

or:

    ./show_tc.sh eth0 ingress

#### Reattach

Reattach first detaches existing TC program and then attaches new to network interface. If interface is not specified, default interface (where gefault GW is) will be used.

    ./reattach_tc.sh [<interface>] [ingress|egress]

Example:

    ./reattach_tc.sh eth0

To remove current and re-attach program to both ingress and egress of eth0 or:

    ./reattach_tc.sh eth0 ingress

To remove current and attach program to ingress of eth0.

### Configuration

#### Config CLI

##### GET

    ./cli_cfg get <idx|all>

    <idx> is 0 for ingress or 1 for egress

Example for reading Ingress configuration:

    ./cli_cfg get 0

Example for reading Egress configuration:

    ./cli_cfg get 1

Example for reading Ingress and Egress configuration:

    ./cli_cfg get all

##### SET

    ./cli_cfg set <idx> <id> <flags> <name>

    <idx>   is 0 for ingress or 1 for egress
    <id>    is numeric identifier of instance
    <name>  is literal identifier of instance
    <flags> configure behavior of instance

###### Ingress flags
```
#define CFG_RX_DUMP     8       /* DUMP intercepted packet */
```
###### Egress flags
```
#define CFG_TX_PROXY    1       /* set in case of EGW (do not set for NODE) */
#define CFG_TX_DUMP     8       /* DUMP intercepted packet */
#define CFG_TX_FIB     16       /* FIB lookup after encap */
```
#### Tunnel CLI

##### GET

    ./cli_tunnel get <id>|all

Example to show all tunnels:

    ./cli_tunnel del all

Example to show tunnel id 100:

    ./cli_tunnel del 100

##### SET (create or owerwrite)

    ./cli_tunnel set <id> <ip-local> <port-local> <ip-remote> <port-remote>

Example to configure GUE tunnel id 100 with local endpoint 172.1.0.4:6080 and remote endpoint 0.0.0.0:0 (Will be filled by GUE Ping):

    ./cli_tunnel set 100 172.1.0.4 6080 0 0

##### DELETE

    ./cli_tunnel del <id>|all

Example to delete all tunnels:

    ./cli_tunnel del all

Example to delete tunnel id 100:

    ./cli_tunnel del 100

#### Service CLI

##### GET

    ./cli_service get all|<service-id> <group-id>

Example to show all services:

    ./cli_service get all

Example to show service with service-id 1 and group-id 2:

    ./cli_service get 1 2

##### SET (create or owerwrite)

    ./cli_service set <service-id> <group-id> <proto> <ip-proxy> <port-proxy> <ip-ep> <port-ep> <tunnel-id> <key>

Example to configure service with service-id 1 and group-id 2 to forward TCP packets from PROXY 5.5.5.5:3100 to backend 1.1.1.1:4000 via GUE tunnel with id 100 secured by password 'Pa55w0rd1234567':

    ./cli_service set 1 2 tcp 5.5.5.5 3100 1.1.1.1 4000 100 'Pa55w0rd1234567'

##### DELETE

    ./cli_service del all|<service-id> <group-id>

Example to delete all services:

    ./cli_service del all

Example to delete service with service-id 1 and group-id 2:

    ./cli_service del 1 2
