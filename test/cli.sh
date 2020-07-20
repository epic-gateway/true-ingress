#!/bin/bash
# usage: $0 <docker-name>
# example:  cli.sh client1

if [ ! "$1" ]; then
    echo "usage: $0 <docker-name>"
    exit 1
fi

docker exec -it $1 bash

