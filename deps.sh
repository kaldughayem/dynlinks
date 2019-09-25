#!/usr/bin/env bash

# install docker
command -v tcset &> /dev/null
if [[ $? != 0 ]] ; then
    echo "Installing docker..."
    sudo apt install docker.io
    sudo usermod -a -G docker ${USER}
    if [[ $? != 0 ]]; then
        echo "something went wrong while installing docker"
        exit 1
    fi
    echo "Installed docker"
else
    echo "Found docker installed"
fi
# Install packages required
go get ./...

# check if tcconfig is installed, and install it if no there
command -v tcset &> /dev/null
if [[ $? != 0 ]] ; then
    echo "Installing tcconfig..."
    pip install tcconfig
    if [[ $? != 0 ]]; then
        echo "something went wrong while installing tcconfig"
        exit 1
    fi
    echo "tcconfig installed"
else
    echo "Found tcconfig installed"
fi

# Install SCION apps
echo "Installing SCION applications"
mkdir ${GOPATH}/src/github.com/netsec-ethz/
cd ${GOPATH}/src/github.com/netsec-ethz/
git clone https://github.com/netsec-ethz/scion-apps.git
cd scion-apps
./deps.sh && make install
if [[ $? != 0 ]]; then
    echo "building SCION apps failed"
    exit 1
else
    echo "Built SCION applications successfully"
fi
