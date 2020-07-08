# Base image
FROM ubuntu:18.04


# Update system
RUN apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y


# Install dependencies
#RUN apt-get update && apt-get install -y sudo iputils-ping iptables iproute2 tcpdump wget curl net-tools nmap iperf3 python mtr vim tshark traceroute mtr netcat
RUN apt-get install -y sudo python3 python3-pip vim iputils-ping iptables iproute2 tcpdump wget curl net-tools traceroute nmap iperf3 mtr


# Shell on attach
CMD ["bash"]