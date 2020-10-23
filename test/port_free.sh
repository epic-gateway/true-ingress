#!/bin/bash
# Setup topology defined in config file
# usage: $0 <port>
#           <port>        - freed port number

set -Eeo pipefail

if [[ $# -ne 1 ]]; then
    echo "Missing parameters!"
    echo "usage: $0 <port>"
    echo "          <port>   - freed port number"
    exit 2
fi

PORT=$1

CFG_DIR="/etc/pfc"

if [ ! -f "${CFG_DIR}/gue_port.cfg" ] ; then
    >&2 echo "Port lidt not initialized!"
    exit 1
fi

echo "${PORT}" >> ${CFG_DIR}/gue_port.cfg
