#!/bin/bash
#
# usage: $0 <interface> <bpf.o>

echo "Before:"
./show_tc.sh $1 $2

./detach_tc.sh $1 $2

./attach_tc.sh $1 $2

echo "DONE"
