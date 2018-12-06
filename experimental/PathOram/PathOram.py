#!/usr/bin/python3

'''
Security Definition:
  An ORAM construction is secure if for any two data request sequences y and z of the same length,
  their access patterns A(y) and A(z) are computationally indistinguishable by the server
Additional Guarantees:
  For confidentiality, we will encrypt each block within WriteBucket using randomized encryption
  For authenticity, we will use a MAC, or better yet use AES-GCM for authenticated encryption
  For freshness, we will overlay a Merkle tree by including a hash in each bucket:
  H(b1 || b2 || ... || bz || h1 || h2), where 
    - h1 and h2 are hashes of left and right child (0 for leaf)
    - bi, i in {1,...,Z}, are the blocks in the bucket
'''

import random
from crypto import Crypto, CryptoError
import util

# Block's address ranges from {1,..,N}
# Bucket's id ranges from {1,..,N}

READ = 1
WRITE = 2
Z = 4 #capacity of a bucket in blocks
N = 7 #number of blocks outsourced to a server
L = 2 #number of levels

# client state
crypto = Crypto()  #crypto module
keys = ""          #client's encryption key
S = set()          #client stash
position = {}      #defined for blocks {1,...,N}
merkle_tree = {}   #defined for buckets {1,...,N}

# server state
storage = {}       #maps bucket id to Z blocks

#######################################################
# Server API
#######################################################

def ReadBucketServer(bucket_id):
	print("server read request for bucket " + str(bucket_id))
	return storage[bucket_id]

def WriteBucketServer(bucket_id, blocks):
	print("server write request for bucket " + str(bucket_id))
	storage[bucket_id] = blocks

#######################################################
# Client Logic
#######################################################

def ReadBucketClient(bkt_id):
	encrypted_bucket = ReadBucketServer(bkt_id)
	expected_hash = sha(getHashArgument(bkt_id, encrypted_bucket))
	if not (expected_hash == merkle_tree[bkt_id]):
		raise IntegrityError
	cleartext_bucket = list(map(lambda blk: authdec(blk, keys, ''), encrypted_bucket))
	readable_bucket = list(map(lambda blk: util.from_json_string(blk), cleartext_bucket))
	return list(filter(lambda blk: not isDummyBlock(blk), readable_bucket))

def WriteBucketClient(bkt_id, blocks):
	readable_bucket = blocks + [getDummyBlock()] * (Z - len(blocks))
	cleartext_bucket = list(map(lambda blk: util.to_json_string(blk), readable_bucket))
	encrypted_bucket = list(map(lambda blk: authenc(blk, keys, ''), cleartext_bucket))
	merkle_tree[bkt_id] = sha(getHashArgument(bkt_id, encrypted_bucket))
	WriteBucketServer(bkt_id, encrypted_bucket)
	#print("merkle tree[" + str(bkt_id) + "]: " + merkle_tree[bkt_id])

def getHashArgument(bkt_id, encrypted_bucket):
	to_hash = ''.join(list(encrypted_bucket))
	if (bkt_id >= 2**L):
		to_hash = to_hash + '0'*64 + '0'*64
	else:
		to_hash = to_hash + merkle_tree[2*bkt_id] + merkle_tree[2*bkt_id + 1]
	return to_hash

def isDummyBlock(b):
	return getAddr(b) == 0

def getDummyBlock():
	return (0, "")

def P(x,l):
	node = 2**L + x
	level = L
	while level > l:
		node = int(node / 2)
		level = level - 1
	return node

def getAddr(addrdata):
	return addrdata[0]

def getData(addrdata):
	return addrdata[1]

def access(op, a, data):
	x = position[a]
	position[a] = random.randint(0, 2**L-1)
	levels = list(range(0,L+1))
	for l in levels:
		for (a_p,d_p) in ReadBucketClient(P(x,l)):
			S.add((a_p,d_p))
	
	if (op == WRITE):
		data_old = list(filter(lambda blk: getAddr(blk) == a, S))
		if (len(data_old) == 1): #do we have to replace old data?
			to_remove = (a, getData(data_old[0]))
			S.remove(to_remove)
		S.add((a,data)) #add the new data
	else:
		data = set(filter(lambda blk: getAddr(blk) == a, S)).pop()

	levels.reverse()
	for l in levels:
		S_p = set(filter(lambda blk: P(x,l) == P(position[getAddr(blk)],l), S))
		S_p_sz = min(len(S_p), Z)
		for i in range(0,len(S_p) - S_p_sz):
			S_p.pop()
		for (a_p, d_p) in S_p:
			S.remove((a_p,d_p))
		WriteBucketClient(P(x,l), list(S_p))

	return data

#######################################################
# Crypto Primitives
#######################################################

def sha(m):
	return crypto.cryptographic_hash(m, hash_name='SHA256')

def aes_encrypt(m, k):
	iv = crypto.get_random_bytes(16)
	return iv + crypto.symmetric_encrypt(m, k, cipher_name='AES', mode_name='CBC', IV=iv)

def aes_decrypt(c, k):
	return crypto.symmetric_decrypt(c[32:], k, cipher_name='AES', mode_name='CBC', IV=c[0:32])

def mac(m, k):
	return crypto.message_authentication_code(m, k, hash_name='SHA256')

def authenc(m, keys, extradata=''):
	ke = keys[0:32]
	ka = keys[32:64]
	c = aes_encrypt(m, ke)
	tag = mac(c + extradata, ka)
	return tag + c

def authdec(c, keys, extradata=''):
	ke = keys[0:32]
	ka = keys[32:64]
	tag = c[0:64]
	correct_tag = mac(c[64:] + extradata, ka)
	if tag != correct_tag:
		raise IntegrityError
	return aes_decrypt(c[64:], ke)

#######################################################
# Driver
#######################################################

def initialize_client():
	global S
	global keys
	S = set()
	keys = crypto.get_random_bytes(64)
	for a in range(1,N+1):
		position[a] = random.randint(0, 2**L-1)

def initialize_server():
	buckets = list(range(1,N+1))
	buckets.reverse()
	for bucket in buckets:
		WriteBucketClient(bucket, [getDummyBlock()] * Z)

def main():
	print("#################################")
	print("Initializing...")
	print("#################################")
	initialize_client()
	initialize_server()
	print("#################################")
	print("Ready for Commands")
	print("#################################")
	print("WRITE(1): " + str(access(WRITE, 1, "boom1")))
	print("WRITE(5): " + str(access(WRITE, 5, "boom5")))
	print("WRITE(2): " + str(access(WRITE, 2, "boom2")))
	print("WRITE(3): " + str(access(WRITE, 3, "boom3")))
	print("WRITE(4): " + str(access(WRITE, 4, "boom4")))
	print("WRITE(3): " + str(access(WRITE, 3, "boom3.1")))
	print("READ(1): " + str(access(READ, 1, None)))
	print("READ(2): " + str(access(READ, 2, None)))
	print("READ(4): " + str(access(READ, 4, None)))
	print("READ(3): " + str(access(READ, 3, None)))

if __name__ == "__main__": main()
