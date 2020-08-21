#!/bin/bash
# Show available port pool.
# usage: $0

set -Eeo pipefail

BASE_DIR="/tmp/.acnodal"
CFG_DIR="${BASE_DIR}/cfg"


if [ ! -f "${CFG_DIR}/gue_port.cfg" ] ; then
    >&2 echo "Port list not initialized!"
    exit 1
fi

cat /tmp/.acnodal/cfg/gue_port.cfg
