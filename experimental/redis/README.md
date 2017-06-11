# Applying libmoat to Redis

Redis is a popular, in-memory key-value store. Unfortunately, its values are
only encrypted on disk - not on memory. The goal is to secure Redis by
performing some basic operations (get, set) in enclaves, while maintaining its
speed and other features.

The `python` and `c` directories have examples of the Redis client APIs in
Python and C, respectively.

The `benchmark` directory will soon have a guide on how to run the Redis benchmarks, and
some generated data.
