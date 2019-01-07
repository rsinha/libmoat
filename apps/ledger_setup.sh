#!/bin/bash

echo "Removing hyperledger config....."
cd ./ledgerservice/artifacts
./byfn.sh -m down

echo "Generating hyperledger config....."
./byfn.sh -m generate

echo "Copying luciditee chaincode....."
mkdir -p src/github.com/luciditee
cp ../../chaincode/luciditee.go src/github.com/luciditee/

echo "Bring up hyperledger network...."
./byfn.sh -m up

echo "Bring up ledger service....."
cd .. && mvn clean package
nohup mvn exec:java &





