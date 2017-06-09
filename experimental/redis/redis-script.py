import redis

r = redis.StrictRedis(host='localhost', port=6379, db=0)

r.set('hello', 'world')
print(r.get('hello')) # outputs world
