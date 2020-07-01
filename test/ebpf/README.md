# eBPF tests

Tests to attach and detach TC programs to **EGW** and/or **NODE**.
Check kernel trace =/sys/kernel/debug/tracing/trace= for output.

## test_01.sh

Attaches =egw_*_tc.o= to **EGW** and run ping from **Client** to =PROXY IP= :

    ./test_01.sh

Expected: PASS
Status: PASS

## test_02.sh

Attaches =pfc_*_tc.o= to **NODE** and run ping from **Client** to =PROXY IP= :

    ./test_02.sh

Expected: PASS
Status: PASS

