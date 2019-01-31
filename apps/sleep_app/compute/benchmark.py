#!/usr/bin/python

import threading
import time
import os
import sys
import json

class myThread (threading.Thread):
   def __init__(self, threadID, name):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.name = name
   def run(self):
      print "Starting " + self.name
      prepare_json_config(self.threadID)
      cmd = prepare_cmd_string(self.threadID)
      #invoke_cmd(cmd)
      print "Exiting " + self.name

def prepare_json_config(threadID):
   f = open('barbican.json', 'r')
   config = json.load(f)
   config['fs_outputs']['psi_output'] += ("/" + str(threadID))
   f_out = open('config/barbican.' + str(threadID) + '.json', 'w')
   json.dump(config, f_out)

def prepare_environment():
   os.system("rm -f log*")

def prepare_cmd_string(threadID):
   cmd = "./compute.out"
   cmd += (" -c config/barbican." + str(threadID) + ".json")
   cmd += " -e enclave.signed.so"
   cmd += " -s 42"
   cmd += " -l /tmp/barbican/" + str(threadID)
   cmd += (" >> logs/nohup" + str(threadID) + ".out")
   return cmd

def invoke_cmd(cmd):
   os.system(cmd) 

if (len(sys.argv) < 2):
    print "Enter number of concurrent processes"
    exit(1)

prepare_environment()
concurrency = int(sys.argv[1])
threads = {}
for i in range(concurrency):
    threads[i] = myThread(i, "Thread-" + str(i))

for i in range(concurrency):
    threads[i].start()

print "Exiting Main Thread"
