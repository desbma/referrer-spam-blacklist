#!/usr/bin/env python

import subprocess
import re

spamfile = "spammers.txt"
weblogs = "/var/lib/lxc/webserver/rootfs/var/log/apache2/access-*.log /var/lib/lxc/webserver/rootfs/var/log/apache2/access-*.log.1"
ownurls = ["f00l.de"]

# read spammers for later checks
f = open(spamfile, "r")
spammers = f.read().splitlines()
f.close()

# get all duplicated lines (referer spammers mostly post three times in a row)
# if spammers get smarter, i gonna change this procedure :D
cmd = "cat %s | uniq -d" % (weblogs)
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
logs = process.communicate()[0].splitlines()

# regex lines
apacheline = re.compile('^(\d+\.\d+\.\d+\.\d+) ([^ ]+) ([^ ]+) \[([^\]]+)\] "(.+?)" (\d+) (\d+) "([^"]+)" "([^"]+)"$')
urlline = re.compile('^.+?//([^/]+).*?$')

for log in logs:
#  print log

  reg = apacheline.search(log)
  ip = reg.group(1)
  ident = reg.group(2)
  user = reg.group(3)
  date = reg.group(4)
  request = reg.group(5)
  code = reg.group(6)
  size = reg.group(7)
  referer = reg.group(8)
  agent = reg.group(9)

  # empty referer?
  if referer == "-":
    continue

  # get url
  url = urlline.search(referer).group(1)

  # own url?
  if url in ownurls:
    continue

  # already listed?
  if url in spammers:
    continue

  # this url is not known, list it
  print url, "(", log, ")"
