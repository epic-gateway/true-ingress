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
2. Copy .dockerfile, server.py, gue_ping.py, pfc TC files to /tmp/docker
3. Build docker image

## Content

Docker image building process is split into 2 steps because it take quite long time and it is annoying to wait each time.

Build process is splint into 2 stages

1. Intermediate *SYSYTEM* image
2. Final *PRODUCTION* image

It will cost you about 600MB of disk space for additional image.

### System image

Based on ubunto 18.04.
Contains latest system updates and required dependencies.
In _common.cfg_ is defined as:

    SYSTEM_IMG="ubuntu:18.04-recent"

#### When

This image can be (re)built only when neccessary system updates are issued or new dependency package is added. It takes about 10 minutes to build.

#### How to (re)build

Simple way from top level makefile:

    make system-img

Detailed from */test/docker* folder:

    ./system.sh

Used *.Dockerfile*:

    ./system.Dockerfile


### Production image

Is built on top of *SYSTEM* image.
Contains latest bimaries from src folder.
This image need be built every time source code changes. It takes only couple of seconds.
In _common.cfg_ is defined as:

    PRODUCTION_IMG="acnodal-pfc:latest"

#### How to (re)build

Simple way from top level makefile:

    make prod-img

Detailed from */test/docker* folder:

    ./prod.sh [<docker-image>]

Used *.Dockerfile*:

    ./prod.Dockerfile

You can optionally specify docker image name otherwise default name from _common.cfg_ will be used.

> If system image does not exists, it will build it first.
