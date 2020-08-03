#!/bin/bash
set -Eeuo pipefail

# Rebuild node docker image
# usage: $0 [<docker-image>]
#           <docker-image>  - (OPTIONAL) docker image name to use. If not specified, default image name will be used.
# The contents of the DOCKER_FLAGS environment variable are passed to the "docker build" command.

. test/common.cfg

if [ ${1+x} ] ; then
    PRODUCTION_IMG="$1"
fi

if [ -z ${DOCKER_FLAGS+x} ] ; then
    DOCKER_FLAGS=""
fi

# build new production image
echo "### Building '${PRODUCTION_IMG}'..."
docker build --tag ${PRODUCTION_IMG} -f test/docker/prod.Dockerfile ${DOCKER_FLAGS} .

echo "### Done ###"
