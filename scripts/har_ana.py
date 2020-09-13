#!/usr/bin/python2.7 -tt
# -*- coding: utf-8 -*-

# AUTHOR:       Gu Jian Min
# DATE:         01/08/2020
# PROGRAM:      har_ana.py
# PURPOSE:      To analyse and extract http requests from give HAR file.
#
# HISTORY:
#       version 1.0     01/08/2020              --- program initial
#
version = 'v3.1'

import sys
import os
import getopt
import re
from lxml import etree
import json
from itertools import islice

CMD_STR_UAT = """grep -n '"url": "https://uat.starhub.com/sfapi' {0} | grep -v '.js",' | grep -v '.html' | grep -v '.css' | grep -v '.png' | grep -v '.json' | grep -v '.js?' | grep -v 'woff' | grep -v '.gif' | sed -e 's/ts=[0-9a-z]*//' | sed -e 's/[\?\&]\"\,/",/'"""
CMD_STR_PROD = """grep -n '"url": "https://www.starhub.com/sfapi' {0} | grep -v '.js",' | grep -v '.html' | grep -v '.css' | grep -v '.png' | grep -v '.json' | grep -v '.js?' | grep -v 'woff' | grep -v '.gif' | sed -e 's/ts=[0-9a-z]*//' | sed -e 's/[\?\&]\"\,/",/'"""
CMD_STR_EBS = """grep -n -E '"url": "https://onlinestore-uat.business.starhub.com/sfapismb|fapismb' {0} | grep -v '.js",' | grep -v '.html' | grep -v '.css' | grep -v '.png' | grep -v '.json' | grep -v '.js?' | grep -v 'woff' | grep -v '.gif' | sed -e 's/ts=[0-9a-z]*//' | sed -e 's/[\?\&]\"\,/",/'"""

def usage(arg):
  out_string = '''
A tool used to extract APIs from a given HAR file.

Usage  1: {0} -e env -f file
Usage  2: {0} [-h] -p file start end
Usage  3: {0} [-h] -e env -q file

where
       -e: specify the environment the har file dumped from.
      env: one of the supported environment, UAT, PRD, EBS.
       -f: instruct program to extract all APIs contained within a HAR file.
       -p: instruct program to extract the details of an API.
       -h: optional flag used together with -p option to instruct program to extract API's headers along with rest of the details.
       -q: instruct program to extract the details of all APIs cintained in HAR file.
     file: HAR file name.
    start: start line of API.
      end: suggested end line of API.
'''.format(arg)
  print(out_string)


def process_all_requests(file, env='UAT'):
  lines = extract_requests(file, env, cache=True)
  for i in lines:
    begin, end = i
    print('range: {0} {1}'.format(begin, end))
    process_request(file, begin, end)

def process_request(file, begin, end, header=False):
  buffer = "{"
  with open(file, 'r') as fh:
    for line in islice(fh, begin, end):
      if re.match(r'^      },$', line):
        buffer += "}"
        break
      else: 
        buffer += str(line.replace(r'\n', ''))
  try:
    json_obj =json.loads(buffer)
  except ValueError as e:
    print('Value Error(Tried recover)')
    buffer = re.sub(r'\s*', '', buffer[:1000])
    x = re.match(r'^(.+)\"headers\"', buffer)
    buffer = x.group(1)
    buffer = buffer[:-1] + '}}'
    json_obj =json.loads(buffer)
  method = json_obj["request"].get("method")
  headers = json_obj["request"].get("headers")
  url = json_obj["request"].get("url")
  queryString = json_obj["request"].get("queryString")
  payload = None
  if json_obj["request"].get("postData"):
    payload = json_obj["request"].get("postData").get("text", "").encode('utf-8')
    payload = re.sub(r'>\s*<', '><', payload)
    payload = re.sub(r'^\s*', '', payload)
  
  if payload:
    try:
      pretty_str = json.dumps(json.loads(payload), sort_keys=True, indent=2, separators=(',', ':'))
    except:
      pretty_str = etree.tostring(etree.fromstring(payload), method='xml', pretty_print=True)

  print('')
  if header:
    headers = json.dumps(headers, sort_keys=True, indent=2, separators=(',', ':'))
    print("headers:\n{0}\n".format(headers))
  print("url: {0}".format(url))
  print("method: {0}".format(method))
  print("queryString: {0}".format(queryString))
  if payload:
    print("payload:\n{0}".format(pretty_str))
  print('')


def extract_requests(file, env='UAT', cache=False):
#  cmd_str = """grep -n '"url": "https://uat.starhub.com/sfapi' {0} | grep -v '.js",' | grep -v '.html' | grep -v '.css' | grep -v '.png' | grep -v '.json' | grep -v '.js?' | grep -v 'woff' | grep -v '.gif' | sed -e 's/ts=[0-9a-z]*//' | sed -e 's/[\?\&]\"\,/",/'""".format(file)
  if env == 'UAT':
    cmd_str = CMD_STR_UAT.format(file)
  elif env == 'EBS':
    cmd_str = CMD_STR_EBS.format(file)
  else:
    cmd_str = CMD_STR_PROD.format(file)
  result = os.popen(cmd_str).read().split('\n')
  first = True
  cached = []
  buffer = {} 
  if not cache:
    print('')    
  for l in result:
    a = re.match(r'^([0-9]+): +\"url\": \"([^"]*)\",$', l)
    if a:
      if first:
        buffer["number"] = int(a.group(1)) - 3
        buffer["url"] = a.group(2)
        first = False
      else:
        if int(a.group(1)) - 3 < 1000:
          if not cache:
            print('{0:6d} {1:6d} -- {2}'.format(buffer["number"], int(a.group(1)) - 4, buffer["url"]))
          else:
            cached.append((buffer["number"], int(a.group(1)) - 4))
        else:
          if not cache:
            print('{0:6d} {1:6d} -- {2}'.format(buffer["number"], buffer["number"]+1000, buffer["url"]))
          else:
            cached.append((buffer["number"], int(a.group(1)) - 4))
        buffer["number"] = int(a.group(1)) - 3
        buffer["url"] = a.group(2)
  if not cache:
    print('')    

  return cached


def main():
  q_flag = False
  p_flag = False
  f_flag = False
  header = False
  usg = True
  ENV = 'UAT'

  # parse command line options
  try:
    opts, args = getopt.getopt(sys.argv[1:], "e:f:q:p:h")
  except getopt.GetoptError as err:
    # print help information and exit:
    usage(os.path.basename(sys.argv[0]))
    sys.exit(2)
  for o, a in opts:
    if o == "-f":
      usg = False
      f_flag = True
      file = a
    elif o == "-e":
      ENV = a
    elif o == "-q":
      usg = False
      file = a
      q_flag = True
    elif o == "-p":
      usg = False
      file = a
      p_flag = True
    elif o == "-h":
      header = True
    else:
      usage(os.path.basename(sys.argv[0]))
      exit()

  if usg:
    usage(os.path.basename(sys.argv[0]))
    exit()

  if p_flag:
    begin = int(args[0])
    end = int(args[1])
    process_request(file, begin, end, header)
  elif q_flag:
    process_all_requests(file, ENV)
  elif f_flag:
    extract_requests(file, ENV)
    
if __name__ == "__main__":
  main()
