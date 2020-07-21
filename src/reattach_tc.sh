#!/bin/bash
#
# usage: $0 <bpf.o> <interface>

echo "Before:"
./show_tc.sh $2

./detach_tc.sh $2

./attach_tc.sh $1 $2

echo "DONE"
