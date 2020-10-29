FROM ubuntu:20.04 as system

ENV DEBIAN_FRONTEND noninteractive

# Install dependencies
RUN apt-get update \
    && apt-get install -y sudo python3 python3-pip vim iputils-ping iptables iproute2 tcpdump wget curl net-tools traceroute nmap iperf3 mtr ethtool golang-go \
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

RUN apt-get update && apt-get install -y bridge-utils

RUN mkdir -p /opt/acnodal/bin
RUN mkdir -p /opt/acnodal/cfg
RUN mkdir -p /opt/acnodal/log

WORKDIR /opt/acnodal/bin
ENV PATH="/opt/acnodal/bin:${PATH}"

# Copy eBPF
COPY --from=builder /usr/src/pfc/src/*.o ./
COPY --from=builder /usr/src/pfc/src/*.sh ./
COPY --from=builder /usr/src/pfc/test/docker/*.sh ./

# Copy CLI
COPY --from=builder /usr/src/pfc/src/cli_cfg /usr/src/pfc/src/cli_service /usr/src/pfc/src/cli_tunnel /usr/src/pfc/src/cli_gc ./
COPY --from=builder /usr/src/pfc/test/port_*.sh ./
COPY --from=builder /usr/src/pfc/test/pfc_*.sh ./

# Copy services for TEST
COPY --from=builder /usr/src/pfc/test/docker/server.py /usr/src/pfc/test/docker/udp_server.py /usr/src/pfc/test/docker/udp_client.py ./

# for GUE Ping
#COPY --from=builder /usr/src/pfc/test/docker/gue_ping*.py ./
COPY --from=builder /usr/src/pfc/test/docker/gue_ping_svc_auto /usr/src/pfc/src/go/pfc_cli_go ./

RUN chmod +x ./*

# Shell on attach
CMD ["bash"]
