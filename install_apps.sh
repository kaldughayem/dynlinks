#!/usr/bin/env bash

echo "[INFO] Installing SCION applications"
mkdir -p ${GOPATH}/src/github.com/netsec-ethz/
cd ${GOPATH}/src/github.com/netsec-ethz/
#/TODO change later when it is merged
git clone https://github.com/kaldughayem/scion-apps.git
cd scion-apps
git checkout kaldughayem/bwtestclient-find-max-bandwidth
./deps.sh && make install

echo "[INFO] Finished building Apps"