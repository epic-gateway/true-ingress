# PFC docker image

PFC testing docker image is required for setup testing topology.
It is based on Ubuntu and contains:

- Tools for crafting/sending packets and collecting statistics.
- HTTP server for testing service.
- TC programs and attach/detach scripts.

There is *prod.sh* script which covers all required activities:

2. Set up default environment variables (if necessary)
3. Build docker image

## Production image

Contains latest bimaries from src folder.
This image need be built every time source code changes. It takes only couple of seconds.
In _common.cfg_ is defined as:

    PRODUCTION_IMG="acnodal-pfc:latest"

### How to (re)build

Simple way from top level makefile:

    make docker

You can optionally specify docker image name otherwise default name from _test/common.cfg_ will be used.

    make docker TAG=pfc:demo202008031445

### Push to Registry

    make push TAG=registry.gitlab.com/acnodal/epic/true-ingress/pfc:demo202008031445


## Additional scripts

### server.py

Python HTTP server implementation which can serve content of local files.
Can be used as demo TCP service.


### udp_server.py

Python UDP server implementation which can serve content of local files.
Can be used as demo UDP service.


### udp_client.py

Python UDP client to send request with file name and store incomming response into file.
