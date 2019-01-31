rm -rf ./logs/*
for i in {0..999}
do
	nohup ./compute.out -c ./config/barbican.$i.json -e enclave.signed.so -s 42 -l /tmp/barbican/$i &> ./logs/nohup$i.out&
done
