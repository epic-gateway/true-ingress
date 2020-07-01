# PFC docker image

PFC testing docker image is required for setup testing topology.
It is based on Ubuntu 18.04 LTS and contains:

- Tools for crafting/sending packets and collecting statistics.
- HTTP server for testing service.
- TC programs and attach/detach scripts.

When building Docker image all neccessary files are copied into */tmp/docker* folder first.

There is *docker.sh* script which covers all required activities:

1. Delete old /tmp/docker
2. Create new /tmp/docker
2. Copy .dockerfile, server.py, TC files to /tmp/docker
3. Build docker image

How to build:

    ./docker.sh [<docker-image>]

You can optionally specify docker image name. If not specified, default name from _common.cfg_ will be used:

    LINUX_IMG="acnodal-test:latest"


