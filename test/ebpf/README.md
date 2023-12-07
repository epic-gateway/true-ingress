# eBPF tests

Tests to attach and detach TC programs to **EPIC** and/or **NODE**.
Check kernel trace */sys/kernel/debug/tracing/trace* for output.

## Dev tests

## Go tests

Simple tests using Go API (`cmd/pfc_cli_go`) to setup forwarding instead of bash sript (`pfc_add.sh`).

### test_go_01.sh

Variation to `test_simple_2gw_01.sh`.
Test creating single forwarding on **EPIC** for service running on **Node1**.

Run:

    ./test_go_01.sh [-v|-V]

    -v verbose output
    -V very verbose output
    
Expected: PASS
Status: PASS

### test_go_02.sh

Test creating 2 forwardings on **EPIC** for 2 services, both located on **Node1**.

Run:

    ./test_go_02.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

## GUE ping tests

Tests for GUE ping resolution.

### test_gue_01.sh

TC attached and configured on both **EPIC** and **Node1**.

- load TrueIngress
- Start GUE ping daemon on **Node1**
- Configure tunnel with empty *remote ip:port*.
- Check whether tunnel remote endpoint on **EPIC** was resolved properly

Run:

    ./test_gue_01.sh [-v|-V]

    -v verbose output
    -V very verbose output

> Note: Resolution may take several second based on period which GUE ping daemon uses to send packets.
    
Expected: PASS
Status: PASS

### test_gue_02.sh

TC attached and configured on both **EPIC** and **Node2**.

- load TrueIngress
- Start GUE ping daemon on **Node2**
- Configure tunnel with empty *remote ip:port*.
- Check whether tunnel remote endpoint on **EPIC** was resolved properly

Run:

    ./test_gue_02.sh [-v|-V]

    -v verbose output
    -V very verbose output

> Note: Resolution may take several second based on period which GUE ping daemon uses to send packets.

Expected: PASS
Status: PASS

## MTU tests

Encapsulation tests where packated can reach MTU size.

### test_mtu_tcp_2gw_01.sh

Check whether TrueIngress can encapsulate when server **Node1** replies with big packets.

- load TrueIngress
- Configure HTTP service and forwarding.
- Download big file and check the result.

Run:

    ./test_mtu_tcp_2gw_01.sh [-v|-V]

    -v verbose output
    -V very verbose output
    
Expected: PASS
Status: PASS

### test_mtu_tcp_2gw_02.sh

Check whether TrueIngress can encapsulate when server **Node2** replies with big packets.

- load TrueIngress
- Configure HTTP service and forwarding.
- Download big file and check the result.

Run:

    ./test_mtu_tcp_2gw_02.sh [-v|-V]

    -v verbose output
    -V very verbose output
    
Expected: PASS
Status: PASS

### test_mtu_tcp_2gw_03.sh

Check whether TrueIngress can encapsulate when client send big packets towards **Node1**.

- load TrueIngress
- Configure HTTP service and forwarding.
- Send MTU sized request and check the response.

Run:

    ./test_mtu_tcp_2gw_03.sh [-v|-V]

    -v verbose output
    -V very verbose output
    
Expected: PASS
Status: PASS

### test_mtu_tcp_2gw_04.sh

Check whether TrueIngress can encapsulate when client send big packets towards **Node1**.

- load TrueIngress
- Configure HTTP service and forwarding.
- Send MTU sized request and check the response.

Run:

    ./test_mtu_tcp_2gw_04.sh [-v|-V]

    -v verbose output
    -V very verbose output
    
Expected: PASS
Status: PASS

### test_mtu_udp_2gw_01.sh

Check whether TrueIngress can encapsulate when server **Node1** replies with big packets.

- load TrueIngress
- Configure UDP service and forwarding.
- Download big file and check the result.

Run:

    ./test_mtu_udp_2gw_01.sh [-v|-V]

    -v verbose output
    -V very verbose output
    
Expected: PASS
Status: FAIL (UDP server does not accomodate packet size when received ICMP "Fragmentation needed")

### test_mtu_udp_2gw_02.sh

Check whether TrueIngress can encapsulate when server **Node2** replies with big packets.

- load TrueIngress
- Configure UDP service and forwarding.
- Download big file and check the result.

Run:

    ./test_mtu_udp_2gw_02.sh [-v|-V]

    -v verbose output
    -V very verbose output
    
Expected: PASS
Status: FAIL (UDP server does not accomodate packet size when received ICMP "Fragmentation needed")

### test_mtu_udp_2gw_03.sh

Check whether TrueIngress can encapsulate when client send big packets towards **Node1**.

- load TrueIngress
- Configure UDP service and forwarding.
- Send MTU sized request and check the response.

Run:

    ./test_mtu_udp_2gw_03.sh [-v|-V]

    -v verbose output
    -V very verbose output
    
Expected: PASS
Status: PASS

### test_mtu_udp_2gw_04.sh

Check whether TrueIngress can encapsulate when client send big packets towards **Node1**.

- load TrueIngress
- Configure UDP service and forwarding.
- Send MTU sized request and check the response.

Run:

    ./test_mtu_udp_2gw_04.sh [-v|-V]

    -v verbose output
    -V very verbose output
    
Expected: PASS
Status: PASS

## GUE encap/decap tests (manual port assignment)

GUE encap decap performed by TrueIngress, NAT is performed by external tools e.g. IPTABLES.
Check different GUE tunnel source/destination port combinations.

### test_simple_2gw_01.sh

Setup service on *Node1* (same network) and configure forwarding on **EPIC1**.
Iptables does DNAT/SNAT on **EPIC1**, TC does GUE encap/decap.
Working in regular mode.
Check service reachability.

Run:

    ./test_simple_2gw_01.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_simple_2gw_02.sh

Setup service on *Node2* (behind NAT) and configure forwarding on **EPIC1**.
Iptables does DNAT/SNAT on **EPIC1**, TC does GUE encap/decap.
Working in regular mode.
Check service reachability.

Run:

    ./test_simple_2gw_02.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_simple_2gw_03.sh

Setup service on *Node1* (same network) and configure forwarding on **EPIC2**.
Iptables does DNAT/SNAT on **EPIC2**, TC does GUE encap/decap.
Working in regular mode.
Check service reachability.

Run:

    ./test_simple_2gw_03.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_simple_2gw_04.sh

Setup service on *Node2* (behind NAT) and configure forwarding on **EPIC2**.
Iptables does DNAT/SNAT on **EPIC2**, TC does GUE encap/decap.
Working in regular mode.
Check service reachability.

Run:

    ./test_simple_2gw_04.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_multi_2gw_01.sh

Setup 2 services on *Node1* (same network) and configure forwarding on **EPIC1**.
Iptables does DNAT/SNAT on **EPIC1**, TC does GUE encap/decap.
Working in regular mode.
Check both services reachability.

Run:

    ./test_multi_2gw_01.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_multi_2gw_02.sh

Setup 2 services on *Node2* (behind NAT) and configure forwarding on **EPIC1**.
Iptables does DNAT/SNAT on **EPIC1**, TC does GUE encap/decap.
Working in regular mode.
Check both services reachability.

Run:

    ./test_multi_2gw_02.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_multi_2gw_03.sh

Setup 2 services on *Node1* (same network) and configure forwarding on **EPIC2**.
Iptables does DNAT/SNAT on **EPIC2**, TC does GUE encap/decap.
Working in regular mode.
Check both services reachability.

Run:

    ./test_multi_2gw_03.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_multi_2gw_04.sh

Setup 2 services on *Node2* (behind NAT) and configure forwarding on **EPIC2**.
Iptables does DNAT/SNAT on **EPIC2**, TC does GUE encap/decap.
Working in regular mode.
Check both services reachability.

Run:

    ./test_multi_2gw_04.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_multi_2gw_05.sh

Setup 2 services, one on *Node1* (same network) via **EPIC1** and second on *Node2* (behind NAT) via **EPIC2**.
Iptables does DNAT/SNAT on **EPICx**, TC does GUE encap/decap.
Working in regular mode.
Check both services reachability.

Run:

    ./test_multi_2gw_05.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_multi_2gw_09.sh

Setup 2 services, one on *Node1* (same network) and second on *Node2*, configure forwarding for both via **EPIC1**.
Iptables does DNAT/SNAT on **EPIC1**, TC does GUE encap/decap.
Working in regular mode.
Check both services reachability.

Run:

    ./test_multi_2gw_09.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_multi_2gw_10.sh

Setup 2 services, one on *Node1* (same network) and second on *Node2*, configure forwarding for both via **EPIC2**.
Iptables does DNAT/SNAT on **EPIC2**, TC does GUE encap/decap.
Working in regular mode.
Check both services reachability.

Run:

    ./test_multi_2gw_10.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

## Session expiration tests

Check whether dynamic session are correctly removed after expiration.

### test_ses_2gw_01.sh

Send 2 requests with random source port in sucession (before expiration).
Check requests resulted in 2 dynamic sessions.
Check whether sessions will expire afrer predefined duration and will be deleted.

Run:

    ./test_ses_2gw_01.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_ses_2gw_02.sh

Send 2 requests with same source port in sucession (before expiration).
Check second request refreshed original session.
Check whether session will expire afrer predefined duration and will be deleted.

Run:

    ./test_ses_2gw_02.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_ses_2gw_03.sh

Send 1 request.
Check whether session will expire afrer predefined duration and will be deleted.
Send 2dn requests with same source port.
Check second request created new session (with same source port).
Check whether session will expire afrer predefined duration and will be deleted.

Run:

    ./test_ses_2gw_03.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

## Session tracking tests

Check whether dynamic sessions steer response toward proper EPIC.

### test_split_2gw_01.sh

Create service on **Node1** and create 2 forwardings via **EPIC1** and **EPIC2**.
Send 2 succesive requests from same client via **EPIC1** and then via **EPIC2** using random source port.
Check whether server could deliver responses via correct EPIC.

Run:

    ./test_split_2gw_01.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_split_2gw_02.sh

Create service on **Node2** and create 2 forwardings via **EPIC1** and **EPIC2**.
Send 2 succesive requests from same client via **EPIC1** and then via **EPIC2** using random source port.
Check whether server could deliver responses via correct EPIC.

Run:

    ./test_split_2gw_02.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_split_2gw_03.sh

Create service on **Node1** and create 2 forwardings via **EPIC1** and **EPIC2**.
Send 2 succesive requests from same client via **EPIC1** and then via **EPIC2** using same source port.
Check whether server could deliver responses via correct EPIC.

Run:

    ./test_split_2gw_03.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS

### test_split_2gw_04.sh

Create service on **Node2** and create 2 forwardings via **EPIC1** and **EPIC2**.
Send 2 succesive requests from same client via **EPIC1** and then via **EPIC2** using same source port.
Check whether server could deliver responses via correct EPIC.

Run:

    ./test_split_2gw_04.sh [-v|-V]

    -v verbose output
    -V very verbose output

Expected: PASS
Status: PASS
