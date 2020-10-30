#!/bin/bash
# Show available port pool.
# usage: $0

set -Eeo pipefail

CFG_DIR="/etc/pfc"

if [ ! -f "${CFG_DIR}/gue_port.cfg" ] ; then
    >&2 echo "Port list not initialized!"
    exit 1
fi

cat ${CFG_DIR}/gue_port.cfg
