#!/bin/bash
##############################
if [ ! "$1" ] ; then
    echo "Installing docker-ce"

    sudo apt-get update

    sudo apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg-agent \
        software-properties-common

    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

    sudo apt-key fingerprint 0EBFCD88

    sudo add-apt-repository \
        "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
        $(lsb_release -cs) \
        stable"

    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io
else
    echo "Downloading docker-ce packages"

    mkdir -p /tmp/docker
    cd /tmp/docker

    wget https://download.docker.com/linux/ubuntu/dists/bionic/pool/stable/amd64/containerd.io_1.2.6-3_amd64.deb
    wget https://download.docker.com/linux/ubuntu/dists/bionic/pool/stable/amd64/docker-ce-cli_19.03.9~3-0~ubuntu-bionic_amd64.deb
    wget https://download.docker.com/linux/ubuntu/dists/bionic/pool/stable/amd64/docker-ce_19.03.9~3-0~ubuntu-bionic_amd64.deb

    echo "Installing docker-ce packages"
    sudo dpkg -i *.deb
fi

echo "Verifying docker is running"
sudo docker run hello-world

echo "Adding $USER to docker group"
sudo usermod -aG docker $USER

docker run hello-world
echo "Reboot required to apply changes"
echo "After reboot try 'docker run hello-world'"
