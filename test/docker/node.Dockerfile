# Base image
FROM ubuntu:18.04


# Update system
RUN apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y


# Install dependencies
RUN apt-get update && apt-get install -y sudo iputils-ping iptables iproute2 tcpdump wget curl net-tools nmap iperf3 python mtr vim tshark traceroute mtr netcat

# Copy files
# for PFC

# for EGW

# for WEB server
COPY server.py /tmp/


# Shell on attach
CMD ["bash"]
