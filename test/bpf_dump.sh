#!/bin/bash
# usage: $0 <obj-file>
#   <obj-file>  - path to bpf obj file
# example:
#    bpf_dump.sh pfc_decap_tc.o
#    bpf_dump.sh pfc_encap_tc.o

if [ ! "$1" ]; then
    echo "usage: $0 <obj-file>"
    exit 1
fi

ls $1
llvm-objdump -S --line-numbers -no-show-raw-insn $1 | less

