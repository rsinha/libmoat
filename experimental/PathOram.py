'''
Security Definition: An ORAM construction is secure if for any two data request sequences y and z of the same length,
                     their access patterns A(y) and A(z) are computationally indistinguishable by the server
'''

import random

# Block's address ranges from {1,..,N}
# Bucket's id ranges from {1,..,N}

READ = 1
WRITE = 2
Z = 4 #capacity of a bucket in blocks
N = 7 #number of blocks outsourced to a server
L = 2 #number of levels

# initialization of client state
S = set()
position = {} #defined for {1,..,N}

# server state
storage = {} #maps bucket id to Z blocks

#######################################################

def ReadBucket(bucket):
	return filter(lambda block: block != dummyBlock(), storage[bucket])

def WriteBucket(bucket, blocks):
	storage[bucket] = blocks + ([dummyBlock()] * (Z - len(blocks)))

def dummyBlock():
	return (0, "")

def P(x,l):
	node = 2**L + x
	level = L
	while level > l:
		node = node / 2
		level = level - 1
	return node

def access(op, a, data):
	x = position[a]
	position[a] = random.randint(0, 2**L-1)
	levels = range(0,L+1)
	for l in levels:
		for (a_p,d_p) in ReadBucket(P(x,l)):
			S.add((a_p,d_p))
	
	if (op == WRITE):
		data_old = filter(lambda (a_p,_): a_p == a, S)
		if (len(data_old) == 1):
			S.remove((a, data_old[0]))
		S.add((a,data))
	else:
		data = filter(lambda (a_p,_): a_p == a, S)[0]

	levels.reverse()
	for l in levels:
		S_p = filter(lambda (a_p,_): P(x,l) == P(position[a_p],l), S)
		S_p_sz = min(len(S_p), Z)
		for i in range(0,len(S_p) - S_p_sz):
			S_p.pop()
		for (a_p, d_p) in S_p:
			S.remove((a_p,d_p))
		WriteBucket(P(x,l), list(S_p))

	return data

#######################################################

def initialize_client():
	S = set()
	for a in range(1,N+1):
		position[a] = random.randint(0, 2**L-1)

def initialize_server():
	for bucket in range(1,N+1):
		WriteBucket(bucket, [dummyBlock()] * Z)

def main():
	initialize_client()
	initialize_server()
	access(WRITE, 1, "boom")
	result = access(READ, 1, None)
	print result

if __name__ == "__main__": main()
