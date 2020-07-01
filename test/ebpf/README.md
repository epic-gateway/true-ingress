# eBPF tests

Tests to attach and detach TC programs to **EGW** and/or **NODE**.
Check kernel trace _/sys/kernel/debug/tracing/trace_ for output.

## test_01.sh

Attaches _egw_*_tc.o_ to **EGW** and run ping from **Client** to _PROXY IP_ :

    ./test_01.sh

Expected: PASS
Status: PASS

## test_02.sh

Attaches _pfc_*_tc.o_ to **NODE** and run ping from **Client** to _PROXY IP_ :

    ./test_02.sh

Expected: PASS
Status: PASS

