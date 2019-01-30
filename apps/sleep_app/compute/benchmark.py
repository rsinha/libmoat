#!/usr/bin/python

import threading
import time
import os
import sys

class myThread (threading.Thread):
   def __init__(self, threadID, name):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.name = name
   def run(self):
      print "Starting " + self.name
      prepare_environment()
      cmd = prepare_cmd_string(self.threadID)
      print "Invoking " + cmd
      invoke_cmd(cmd)
      print "Exiting " + self.name

def prepare_environment():
   os.system("rm -f log*")

def prepare_cmd_string(threadID):
   cmd = "./compute.out"
   cmd += " -c barbican.json"
   cmd += " -e enclave.signed.so"
   cmd += " -s 42"
   cmd += " -l /tmp/barbican/" + str(threadID)
   cmd += " >> log" + str(threadID)
   return cmd

def invoke_cmd(cmd):
   os.system(cmd) 

if (len(sys.argv) < 2):
    print "Enter number of concurrent processes"
    exit(1)

concurrency = int(sys.argv[1])
threads = {}
for i in range(concurrency):
    threads[i] = myThread(i, "Thread-" + str(i))

for i in range(concurrency):
    threads[i].start()

print "Exiting Main Thread"
