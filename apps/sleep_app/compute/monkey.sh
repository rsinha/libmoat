#!/bin/bash
for i in {0..10}
do
	nohup ./compute.out -c ./config/barbican.$1.json -e enclave.signed.so -s 42 -l /tmp/barbican/$1 &>> ./logs/nohup$1.out
done
