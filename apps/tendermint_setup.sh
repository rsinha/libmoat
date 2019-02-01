#!/bin/bash

echo "Running Tendermint..."
tendermint init
nohup tendermint node --proxy_app=kvstore &


echo "Running LedgerService...."
cd ./ledgerservice/
mvn clean package
nohup mvn exec:java -Dexec.args="tm"  &
