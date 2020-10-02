# PFC Go API

Provides Go bindings to setup/delete/list service forwarding in PFC.

Contain 2 files

### pfc/pfc.go

API itself. Provides set of functions to add, delete, get list of services.

#### func Version() string

Return PFC version infomation (string).

> Note: There is no official versioning yet.

#### func Check() (bool, string)

Return whether PFC is ready to be used (bool) and reason (string) in case it is not.

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


### pfc_cli_go.go

Binary which imports and uses Go API.
It is demo application of Go API and can be used as an alternative to `test/pfc_add.sh`, `test/pfc_delete.sh` and `test/pfc_list.sh` scripts.
There are `test/ebpf/test_go_0x.sh` tests which exactly do that.

#### pfc_cli_go version

Report PFC version.

> Note: There is no official versioning yet.

    pfc_cli_go version

#### pfc_cli_go check

Check whether PFC is present and running on the system.

    pfc_cli_go check

#### pfc_cli_go add

Configure forwarding

    pfc_cli_go add <interface> <group-id> <service-id> <pwd> <proto> <proxy-ip> <proxy-port> <service-ip> <service-port> <gue-ip> <gue-port>

#### pfc_cli_go del

Delete forwarding

    pfc_cli_go del <group-id> <service-id>

#### pfc_cli_go list

List all configured tunnels and services.

    pfc_cli_go list

#### pfc_cli_go help

Show help.

    pfc_cli_go help
