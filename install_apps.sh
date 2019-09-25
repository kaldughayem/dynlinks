#!/usr/bin/env bash

# check if scion apps are installed, and install them if not
echo "[INFO] Installing SCION applications"
mkdir ${GOPATH}/src/github.com/netsec-ethz/
cd ${GOPATH}/src/github.com/netsec-ethz/
git clone https://github.com/netsec-ethz/scion-apps.git
cd scion-apps
./deps.sh && make install

echo "[INFO] Finished building Apps"