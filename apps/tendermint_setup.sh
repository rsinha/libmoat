#!/bin/bash

echo "Installing Tendermint...."
mkdir -p $GOPATH/src/github.com/tendermint
cd $GOPATH/src/github.com/tendermint
git clone https://github.com/tendermint/tendermint.git
cd tendermint

make get_tools
make get_vendor_deps

make install

echo "Running Tendermint..."
tendermint init
nohup tendermint node --proxy_app=kvstore &


echo "Running LedgerService...."
cd ./ledgerservice/
mvn clean package
nohup mvn exec:java -Dexec.args="tm"  &
