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

### test_05.sh

Variation of `basic/test_01.sh` which setup service on *Node1* (same network).
TC attached and configured on both **EGW** and **Node1**.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
- Uses GUE ping with tunnel-id

Run:

    ./test_05.sh

Expected: PASS
Status: PASS

### test_06.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached and configured on both **EGW** and **Node2**.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
- Uses GUE ping with tunnel-id

Run:

    ./test_06.sh

Expected: PASS
Status: PASS

### test_07.sh

Variation of `basic/test_01.sh` which setup service on *Node1* (same network).
TC attached and configured on both **EGW** and **Node1**.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
- Uses GUE ping with service-id + group-id + security key

Run:

    ./test_07.sh

Expected: PASS
Status: PASS

### test_08.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached and configured on both **EGW** and **Node2**.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
- Uses GUE ping with service-id + group-id + security key

Run:

    ./test_08.sh

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

## PFC GUE encap/decap tests

GUE encap decap performed by PFC, NAT is performed by external tools e.g. IPTABLES.

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

## PFC NAT tests

Both GUE encap/decap and NAT are performed by PFC.

### test_nat_01.sh

Variation of `basic/test_01.sh` which setup service on *Node1* (same network).
TC attached and configured on both **EGW** and **Node1**.
PFC configured to perform DNAT/SNAT and GUE Encap/Decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
- Setup HTTP service
- Configure PFC on EGW and NODE.
- Send HTTP request from client to *proxy ip:port*

Run:

    ./test_nat_01.sh

Expected: PASS
Status: PASS

### test_nat_02.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached and configured on both **EGW** and **Node2**.
PFC configured to perform DNAT/SNAT and GUE Encap/Decap.
Working in regular mode.

- Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
- Setup HTTP service
- Configure PFC on EGW and NODE.
- Send HTTP request from client to *proxy ip:port*

Run:

    ./test_nat_02.sh

Expected: PASS
Status: PASS
