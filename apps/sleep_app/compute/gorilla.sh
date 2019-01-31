#!/bin/bash
rm -rf ./logs/*
kill -9 $(pidof compute.out)
for i in {0..499}
do
	nohup ./monkey.sh $i &> gorilla_log &
        pids[${i}]=$!
done

for pid in ${pids[*]}; do
    wait $pid
done
