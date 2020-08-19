#!/bin/bash
# Setup topology defined in config file
# usage: $0 <config> [<docker-image>]
#           <config>        - file with topology description
#           <docker-image>  - (OPTIONAL) docker image to use for containers. If not specified, default image will be used.

set -Eeo pipefail

if [[ $# -ne 2 ]]; then
    echo "Missing parameters!"
    echo "usage: $0 <port-min> <port-max>"
    echo "          <port-min>    - lower bound"
    echo "          <port-max>    - upper bound"
    exit 2
fi

MIN=$1
MAX=$2

BASE_DIR="/tmp/.acnodal"
CFG_DIR="${BASE_DIR}/cfg"

# check basic structure
ls ${CFG_DIR}
if [ ! -d "${CFG_DIR}" ] ; then
    echo "# Creating '${CFG_DIR}'"
    mkdir -p ${CFG_DIR}
fi

if [ -f "${CFG_DIR}/gue_port.cfg" ] ; then
    if [[ $(wc -l /tmp/.acnodal/cfg/gue_port.cfg | awk '{print $1}') -ne 0 ]] ; then
        echo "# Port list already initialized"
        exit 1
    else
        echo "# Port list exists, but empty"
    fi
else
    touch ${CFG_DIR}/gue_port.cfg
fi

for (( i=${MIN}; i<=${MAX}; i++ ))
do
    echo "$i" >> ${CFG_DIR}/gue_port.cfg
done
