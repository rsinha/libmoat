# Running be nchmarks using YCSB
## Step 0: Start redis server.
You should have redis installed already. If not, install redis using your package
manager.

```
redis-server
```

This starts server on default port 6379.

## Step 1: Download & build YSCB

```
curl -O --location
https://github.com/brianfrankcooper/YCSB/releases/download/0.12.0/ycsb-0.12.0.tar.gz
tar xfvz ycsb-0.12.0.tar.gz
cd ycsb-0.12.0
mvn -pl com.yahoo.ycsb:redis-binding -am clean package
```

## Step 2: Run benchmarks
```
./bin/ycsb load redis -s -P workloads/workloada -p redis.host=localhost -p
redis.port=6379
```

## Output (workload a)
```
Loading workload...
Starting test.
2017-06-19 22:46:23:688 0 sec: 0 operations; est completion in 0 seconds
DBWrapper: report latency for each error is false and specific error codes to
track for latency are: []
2017-06-19 22:46:23:938 0 sec: 1000 operations; 3636.36 current ops/sec;
[CLEANUP: Count=1, Max=429, Min=429, Avg=429, 90=429, 99=429, 99.9=429,
99.99=429] [INSERT: Count=1000, Max=6019, Min=90, Avg=202.48, 90=311, 99=535,
99.9=1210, 99.99=6019]
[OVERALL], RunTime(ms), 275.0
[OVERALL], Throughput(ops/sec), 3636.3636363636365
[TOTAL_GCS_PS_Scavenge], Count, 0.0
[TOTAL_GC_TIME_PS_Scavenge], Time(ms), 0.0
[TOTAL_GC_TIME_%_PS_Scavenge], Time(%), 0.0
[TOTAL_GCS_PS_MarkSweep], Count, 0.0
[TOTAL_GC_TIME_PS_MarkSweep], Time(ms), 0.0
[TOTAL_GC_TIME_%_PS_MarkSweep], Time(%), 0.0
[TOTAL_GCs], Count, 0.0
[TOTAL_GC_TIME], Time(ms), 0.0
[TOTAL_GC_TIME_%], Time(%), 0.0
[CLEANUP], Operations, 1.0
[CLEANUP], AverageLatency(us), 429.0
[CLEANUP], MinLatency(us), 429.0
[CLEANUP], MaxLatency(us), 429.0
[CLEANUP], 95thPercentileLatency(us), 429.0
[CLEANUP], 99thPercentileLatency(us), 429.0
[INSERT], Operations, 1000.0
[INSERT], AverageLatency(us), 202.478
[INSERT], MinLatency(us), 90.0
[INSERT], MaxLatency(us), 6019.0
[INSERT], 95thPercentileLatency(us), 359.0
[INSERT], 99thPercentileLatency(us), 535.0
[INSERT], Return=OK, 1000
```
