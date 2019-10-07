#!/usr/bin/env bash

# check if scion apps are installed, and install them if not
echo "[INFO] Installing SCION applications"
mkdir ${GOPATH}/src/github.com/netsec-ethz/
cd ${GOPATH}/src/github.com/netsec-ethz/
git clone https://github.com/kaldughayem/scion-apps.git
cd scion-apps
git checkout kaldughayem/bwtestclient-find-max-bandwidth
./deps.sh && make install

echo "[INFO] Finished building Apps"