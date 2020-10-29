#!/bin/bash
# Setup topology defined in config file
# usage: $0 <config> [<docker-image>]
#           <config>        - file with topology description
#           <docker-image>  - (OPTIONAL) docker image to use for containers. If not specified, default image will be used.

set -Eeo pipefail

CFG_DIR="/etc/pfc"

if [ ! -f "${CFG_DIR}/gue_port.cfg" ] ; then
    >&2 echo "Port list not initialized!"
    exit 1
fi

if [[ $(wc -l "${CFG_DIR}/gue_port.cfg" | awk '{print $1}') -eq 0 ]] ; then
    >&2 echo "# Port list is empty"
    exit 1
fi

head -n1 ${CFG_DIR}/gue_port.cfg
sed -i '1d' ${CFG_DIR}/gue_port.cfg
