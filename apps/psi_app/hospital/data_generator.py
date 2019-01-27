import random
import sys

ssn = 0
for i in range(0,int(sys.argv[1])):
	ssn += random.randint(1,2)
	secret = random.randint(0,1000)
	print str(ssn) + "," + str(secret)
