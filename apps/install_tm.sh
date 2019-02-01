#!/bin/bash

echo "Installing Tendermint...."
mkdir -p $GOPATH/src/github.com/tendermint
cd $GOPATH/src/github.com/tendermint
git clone https://github.com/tendermint/tendermint.git
cd tendermint

make get_tools
make get_vendor_deps

make install

