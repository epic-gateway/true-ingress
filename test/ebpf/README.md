# eBPF tests

Tests to attach and detach TC programs to **EGW** and/or **NODE**.
Check kernel trace */sys/kernel/debug/tracing/trace* for output.

## Dev tests

Various tests used during transition from Linux infra to PFC functionality.

### test_01.sh

Simple attach PFC test

- Setup basic topology
- Attaches *pfc_ingress_tc.o* and *pfc_egress_tc.o* to **NODE** and run ping from **Client** to *PROXY IP* :

Run:

    ./test_01.sh

Expected: PASS
Status: PASS

### test_02.sh

Run PFC on multiple interfaces in parallel with different configuration.

- Setup basic topology.
- Attaches *pfc_ingress_tc.o* and *pfc_egress_tc.o* to **NODE's** eth0 and eth1
- Run ping from **Client** (via eth1) to *PROXY IP*
- Run ping from *host* (via eth0) to *eth0 ip*

Run:

    ./test_02.sh

Expected: PASS
Status: PASS

### test_03.sh

Variation of `basic/test_01.sh` which setup service on *Node1* (same network).
PFC attached on both **EGW** and **Node1**.
PFC not configured.

Run:

    ./test_03.sh

Expected: PASS
Status: PASS

### test_04.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached on both **EGW** and **Node2**.
TC not configured.

Run:

    ./test_04.sh

Expected: PASS
Status: PASS

### test_09.sh

Variation of `basic/test_01.sh` which setup service on *Node1* (same network).
TC attached and configured on both **EGW** and **Node1**.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
- Setup HTTP service and forwarding.
- Send HTTP request from client to *proxy ip:port*

Run:

    ./test_09.sh

Expected: PASS
Status: PASS

### test_10.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached and configured on both **EGW** and **Node2**.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
- Setup HTTP service and forwarding.
- Send HTTP request from client to *proxy ip:port*

Run:

    ./test_10.sh

Expected: PASS
Status: PASS

## PFC GUE ping tests

Tests for GUE ping resolution.

### test_gue_01.sh

TC attached and configured on both **EGW** and **Node1**.

- load PFC
- Start GUE ping daemon on **Node1**
- Configure tunnel with empty *remote ip:port*.
- Check whether tunnel remote endpoint on **EGW** was resolved properly

Run:

    ./test_gue_01.sh

> Note: Resolution may take several second based on period which GUE ping daemon uses to send packets.
    
Expected: PASS
Status: PASS

### test_gue_02.sh

TC attached and configured on both **EGW** and **Node2**.

- load PFC
- Start GUE ping daemon on **Node2**
- Configure tunnel with empty *remote ip:port*.
- Check whether tunnel remote endpoint on **EGW** was resolved properly

Run:

    ./test_gue_02.sh

> Note: Resolution may take several second based on period which GUE ping daemon uses to send packets.

Expected: PASS
Status: PASS

### test_gue_03.sh

TC attached and configured on both **EGW** and **Node1**.

- load PFC
- Start GUE ping daemon on **Node1**
- Configure tunnel with empty *remote ip:port* and send one time GUE ping.
- Check whether tunnel remote endpoint on **EGW** was resolved properly

Run:

    ./test_gue_03.sh

> Note: Resolution will be immediate.

Expected: PASS
Status: PASS

### test_gue_04.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached and configured on both **EGW** and **Node2**.

- load PFC
- Start GUE ping daemon on **Node2**
- Configure tunnel with empty *remote ip:port* and send one time GUE ping.
- Check whether tunnel remote endpoint on **EGW** was resolved properly

Run:

    ./test_gue_04.sh

> Note: Resolution will be immediate.

Expected: PASS
Status: PASS

### test_gue_05.sh

TC attached and configured on both **EGW** and **Node1**.

- Start GUE ping daemon on **Node1**
- load PFC
- Configure tunnel with empty *remote ip:port*.
- Check whether tunnel remote endpoint on **EGW** was resolved properly

Run:

    ./test_gue_05.sh

Expected: PASS
Status: PASS

### test_gue_06.sh

TC attached and configured on both **EGW** and **Node2**.

- Start GUE ping daemon on **Node2**
- load PFC
- Configure tunnel with empty *remote ip:port*.
- Check whether tunnel remote endpoint on **EGW** was resolved properly

Run:

    ./test_gue_05.sh

Expected: PASS
Status: PASS

## PFC GUE encap/decap tests (manual port assignment)

GUE encap decap performed by PFC, NAT is performed by external tools e.g. IPTABLES.
Check different GUE tunnel source/destination port combinations.

### test_simple_01.sh

Variation of `basic/test_01.sh` which setup service on *Node1* (same network).
TC attached and configured on both **EGW** and **Node1**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
- Setup HTTP service
- Configure PFC on EGW and NODE.
- Send HTTP request from client to *proxy ip:port*

Run:

    ./test_simple_01.sh

Expected: PASS
Status: PASS

### test_simple_02.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached and configured on both **EGW** and **Node2**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
- Setup HTTP service
- Configure PFC on EGW and NODE.
- Send HTTP request from client to *proxy ip:port*

Run:

    ./test_simple_02.sh

Expected: PASS
Status: PASS

### test_multi_01.sh

Variation of `basic/test_01.sh` which setup service on *Node1* (same network).
TC attached and configured on both **EGW** and **Node1**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*
- Setup 2 HTTP services on **Node1**
- Configure PFC forwarding on EGW and NODE
- Send HTTP request from client to both *proxy ip:port*
- First GUE tunnel is runing from 172.1.0.3:6080 to 172.1.0.4:6080
- Second GUE tunnel is runing from 172.1.0.3:6081 to 172.1.0.4:6081

Run:

    ./test_multi_01.sh

Expected: PASS
Status: PASS

### test_multi_02.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached and configured on both **EGW** and **Node2**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*
- Setup 2 HTTP services on **Node1**
- Configure PFC forwarding on EGW and NODE
- Send HTTP request from client to both *proxy ip:port*
- First GUE tunnel is runing from 172.1.0.3:6080 to 172.1.0.4:6080
- Second GUE tunnel is runing from 172.1.0.3:6081 to 172.1.0.4:6081

Run:

    ./test_multi_02.sh

Expected: PASS
Status: PASS

### test_multi_03.sh

Variation of `basic/test_01.sh` which setup service on *Node1* (same network).
TC attached and configured on both **EGW** and **Node1**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*
- Setup 2 HTTP services on **Node1**
- Configure PFC forwarding on EGW and NODE
- Send HTTP request from client to both *proxy ip:port*
- First GUE tunnel is runing from 172.1.0.3:6080 to 172.2.0.3:6080
- Second GUE tunnel is runing from 172.1.0.3:6080 to 172.2.0.3:6081

Run:

    ./test_multi_03.sh

Expected: PASS
Status: PASS

### test_multi_04.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached and configured on both **EGW** and **Node2**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*
- Setup 2 HTTP services on **Node1**
- Configure PFC forwarding on EGW and NODE
- Send HTTP request from client to both *proxy ip:port*
- First GUE tunnel is runing from 172.1.0.3:6080 to 172.2.0.3:6080
- Second GUE tunnel is runing from 172.1.0.3:6080 to 172.2.0.3:6081

Run:

    ./test_multi_04.sh

Expected: PASS
Status: PASS

### test_multi_05.sh

Variation of `basic/test_01.sh` which setup service on *Node1* (same network).
TC attached and configured on both **EGW** and **Node1**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*
- Setup 2 HTTP services on **Node1**
- Configure PFC forwarding on EGW and NODE
- Send HTTP request from client to both *proxy ip:port*
- First GUE tunnel is runing from 172.1.0.3:6080 to 172.1.0.4:6080
- Second GUE tunnel is runing from 172.1.0.3:6081 to 172.1.0.4:6080

Run:

    ./test_multi_05.sh

Expected: PASS
Status: PASS

### test_multi_06.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached and configured on both **EGW** and **Node2**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*
- Setup 2 HTTP services on **Node1**
- Configure PFC forwarding on EGW and NODE
- Send HTTP request from client to both *proxy ip:port*
- First GUE tunnel is runing from 172.1.0.3:6080 to 172.2.0.3:6080
- Second GUE tunnel is runing from 172.1.0.3:6081 to 172.2.0.3:6080

Run:

    ./test_multi_06.sh

Expected: PASS
Status: PASS

### test_multi_07.sh

Variation of `basic/test_01.sh` which setup service on *Node1* (same network).
TC attached and configured on both **EGW** and **Node1**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*
- Setup 2 HTTP services on **Node1**
- Configure PFC forwarding on EGW and NODE
- Send HTTP request from client to both *proxy ip:port*
- First GUE tunnel is runing from 172.1.0.3:6080 to 172.1.0.4:6080
- Second GUE tunnel is runing from 172.1.0.3:6080 to 172.1.0.4:6080

Run:

    ./test_multi_07.sh

Expected: PASS
Status: PASS

### test_multi_08.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached and configured on both **EGW** and **Node2**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*
- Setup 2 HTTP services on **Node1**
- Configure PFC forwarding on EGW and NODE
- Send HTTP request from client to both *proxy ip:port*
- First GUE tunnel is runing from 172.1.0.3:6080 to 172.2.0.3:6080
- Second GUE tunnel is runing from 172.1.0.3:6080 to 172.2.0.3:6080

Run:

    ./test_multi_08.sh

Expected: PASS
Status: PASS

### test_multi_09.sh

TC attached and configured on **EGW**, **Node1** and **Node2**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*
- Setup 2 HTTP services, one on **Node1** and other on **Node2**
- Configure PFC forwarding on each node
- Send HTTP request from client to both *proxy ip:port*
- First GUE tunnel is runing from 172.1.0.3:6080 to 172.1.0.4:6080
- Second GUE tunnel is runing from 172.1.0.3:6080 to 172.2.0.3:6080

Run:

    ./test_multi_09.sh

Expected: PASS
Status: PASS

## PFC GUE encap/decap tests (automatic port assignment)

GUE encap decap performed by PFC, NAT is performed by external tools e.g. IPTABLES.
Port pool is created when PFC is loaded and GUE tunnel ports are assigned from that pool when created.
Uses wraper pcf_start/pfc_stop to load/unload PFC.
Uses wrapper pfc_add/pfc_delete to create/remove tunnel and service forwarding.

### test_simple_pfc_01.sh

Variation of `basic/test_01.sh` which setup service on *Node1* (same network).
TC attached and configured on both **EGW** and **Node1**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
- Setup HTTP service
- Configure PFC on EGW and NODE.
- Send HTTP request from client to *proxy ip:port*

Run:

    ./test_simple_pfc_01.sh [-v]
    
    -v for verbose output

Expected: PASS
Status: PASS

### test_simple_pfc_02.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached and configured on both **EGW** and **Node2**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
- Setup HTTP service
- Configure PFC on EGW and NODE.
- Send HTTP request from client to *proxy ip:port*

Run:

    ./test_simple_pfc_02.sh [-v]
    
    -v for verbose output

Expected: PASS
Status: PASS

### test_multi_pfc_01.sh

Variation of `basic/test_01.sh` which setup 2 services on *Node1* (same network).
TC attached and configured on both **EGW** and **Node1**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*
- Setup 2 HTTP services on **Node1**
- Configure PFC forwarding on EGW and NODE
- Send HTTP request from client to both *proxy ip:port*

Run:

    ./test_multi_pfc_01.sh [-v]
    
    -v for verbose output

Expected: PASS
Status: PASS

### test_multi_pfc_02.sh

Variation of `basic/test_02.sh` which setup 2 service on *Node2* (behind NAT).
TC attached and configured on both **EGW** and **Node2**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*
- Setup 2 HTTP services on **Node1**
- Configure PFC forwarding on EGW and NODE
- Send HTTP request from client to both *proxy ip:port*

Run:

    ./test_multi_pfc_02.sh [-v]
    
    -v for verbose output

Expected: PASS
Status: PASS

### test_multi_pfc_09.sh

TC attached and configured on **EGW**, **Node1** and **Node2**.
Iptables does DNAT/SNAT on EGW, TC does GUE encap/decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*
- Setup 2 HTTP services, one on **Node1** and other on **Node2**
- Configure PFC forwarding on each node
- Send HTTP request from client to both *proxy ip:port*

Run:

    ./test_multi_pfc_09.sh [-v]
    
    -v for verbose output

Expected: PASS
Status: PASS
