# eBPF tests

Tests to attach and detach TC programs to **EGW** and/or **NODE**.
Check kernel trace */sys/kernel/debug/tracing/trace* for output.

## test_01.sh

Setup basic topology.
Attaches *pfc_ingress_tc.o* and *pfc_egress_tc.o* to **NODE** and run ping from **Client** to *PROXY IP* :

    ./test_01.sh

Expected: PASS
Status: PASS

## test_02.sh

    **OBSOLETE -> REMOVED**

## test_03.sh

Variation of `basic/test_01.sh` which setup service on *Node1* (same network).
TC attached on both **EGW** and **Node1**.
TC not configured :

    ./test_03.sh

Expected: PASS
Status: PASS

## test_04.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached on both **EGW** and **Node2**.
TC not configured :

    ./test_04.sh

Expected: PASS
Status: PASS

## test_05.sh

Variation of `basic/test_01.sh` which setup service on *Node1* (same network).
TC attached and configured on both **EGW** and **Node1**.
Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port* :

    ./test_05.sh

Expected: PASS
Status: PASS

## test_06.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached and configured on both **EGW** and **Node2**.
Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port* :

    ./test_06.sh

Expected: PASS
Status: PASS

## test_07.sh

Variation of `basic/test_01.sh` which setup service on *Node1* (same network).
TC attached and configured on both **EGW** and **Node1**.
Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
Setup HTTP service and forwarding.
Send HTTP request from client to *proxy ip:port*: 

    ./test_07.sh

Expected: PASS
Status: PASS

## test_08.sh

Variation of `basic/test_02.sh` which setup service on *Node2* (behind NAT).
TC attached and configured on both **EGW** and **Node2**.
Configure tunnel with empty *remote ip:port* and wait for GUE Ping to fill *remote ip:port*.
Setup HTTP service and forwarding.
Send HTTP request from client to *proxy ip:port*: 

    ./test_08.sh

Expected: PASS
Status: PASS

