for i in {1..500}
do
	nohup ./compute.out -c ./barbican.$i.json -e enclave.signed.so -s 42 -l /tmp/barbican/$i &> ./logs/nohup$i.out&
done
