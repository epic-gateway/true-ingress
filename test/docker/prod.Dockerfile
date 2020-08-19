FROM ubuntu:20.04 as system

ENV DEBIAN_FRONTEND noninteractive

# Install dependencies
RUN apt-get update \
    && apt-get install -y sudo python3 python3-pip vim iputils-ping iptables iproute2 tcpdump wget curl net-tools traceroute nmap iperf3 mtr \
    && rm -rf /var/lib/apt/lists/*

# Install python modules
RUN pip3 install scapy

#
# Compile the PFC
#
FROM system as builder

WORKDIR /usr/src/pfc

RUN apt-get update \
    && apt-get install -y clang llvm gcc-multilib build-essential libelf-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . ./

RUN make build

#
# Assemble the prod image
#
FROM system as prod

RUN mkdir -p /tmp/.acnodal/bin
RUN mkdir -p /tmp/.acnodal/cfg
RUN mkdir -p /tmp/.acnodal/log

WORKDIR /tmp/.acnodal/bin

# Copy eBPF
COPY --from=builder /usr/src/pfc/src/*.o ./
COPY --from=builder /usr/src/pfc/src/*.sh ./
COPY --from=builder /usr/src/pfc/test/docker/*.sh ./

# Copy CLI
COPY --from=builder /usr/src/pfc/src/cli_cfg /usr/src/pfc/src/cli_service /usr/src/pfc/src/cli_tunnel ./
COPY --from=builder /usr/src/pfc/test/port_*.sh ./
COPY --from=builder /usr/src/pfc/test/pfc_*.sh ./

# for WEB Server
COPY --from=builder /usr/src/pfc/test/docker/server.py ./

# for GUE Ping
COPY --from=builder /usr/src/pfc/test/docker/gue_ping*.py ./

# Shell on attach
CMD ["bash"]
