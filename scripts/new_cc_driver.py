#!/usr/bin/python2.7 -tt
# -*- coding: utf-8 -*-

# AUTHOR:       Gu Jian Min
# DATE:         12/08/2020
# PROGRAM:      new_cc_driver.py
# PURPOSE:
#               Simulating FAPI or service layer to interact with CC App.
#
# HISTORY:
#       version 1.0     12/08/2020              --- program initial
#       version 1.1     12/09/2020              --- change of communication class to new_comm_req.
#
version = 'v1.1'

import sys
import os
import time
from datetime import datetime, timedelta
import requests
import re
import json
import getopt
import logging
from multiprocessing.dummy import Pool
import threading
import Queue
from copy import deepcopy
from new_comm_req import Comm_req, Comm_req2

# lock to serialize output to log file
LOCK = threading.Lock()
TaskQueue = Queue.Queue()

myApp = os.path.basename(sys.argv[0]).split('.')[0] + '.log' # log file name
workingDir = os.getcwd() + '/' # creating log file in current working directory
logger = logging.getLogger(myApp)
l_fh = logging.FileHandler(workingDir + myApp)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
l_fh.setFormatter(formatter)
logger.addHandler(l_fh) 
logger.setLevel(logging.DEBUG)

# global variables
CONTEXT = {'end_point':[], 'u_flag':False, 'debug':False, 'etag':None, 't_log':logger, 'l_log':logger}
HEADERS = {"content-type": "application/json", "Accept": "application/json", "x-dynatrace-test": "SI=ETM_Automation;SN=new_cc_driver.py"}
Tries = 5

def usage(arg):
  out_string = '''
This is a generic testing tool which simulats FAPI or service lyer to interact with CC App. Same tool can be used to test consumer CC APIs and EBS CC APIs.

Usage  1: {0} [-e env] [-U] [-d] [-V] [-L min] [-w sec] [-M th_num] [-B rampup] [-c num] -f tc_file
Usage  2: {0} [-e env] [-U] [-d] [-V] -s tc_id params [+a ::docId:cat]
Usage  3: {0} -S


where
       -e: option for environment.
      env: one of the supported environments, i.e. UAT_EXT, UAT_INT, UAT_EBS, SIT1_EBS
       -M: a flag to instruct program to run in multi-threads.
   th_num: specifying number of threads.
       -B: ramp up indicator.
   rampUp: ramp up criterion, in the form of num:seconds, e.g. 5:20 which means instantiating 5 threads every 20 seconds.
       -c: a flag to instruct program to make num of requests with same set of data in tc_file.
      num: a number e.g. 10
       -f: a flag to instruct program to retrieve TC id as well as TC params from hereafter input file, e.g. tc_file.
  tc_file: a file contains list of test cases, in the form of tc_id, context parameters, e.g. C07,CMPG-S01534,BNDL-M25078,variants
           to get TC context params descriptions, check through: {0} -S option.
       -w: a flag to instruct program to wait some seconds before submitting next request, concept of pacing time.
      sec: number of milli seconds to wait, e.g. 3000 means 3000 milli seconds i.e. 3 seconds.
       -L: a flag to instruct program to run test for x number of minutes.
      min: number of minutes, e.g. 60, which means 60 minutes or 1 hour.
       -s: request to execute one single test case determined by hereafter tc_id
       -d: a flag to instruct program to print detailed execution info.
       -V: a falg to instruct program to turn on verbose printing. It can be worked together with -d option. 
    tc_id: test case id to be invoked.
   params: test case context parameters. Check through {0} -S
       +a: supplementary parameter to instruct program to take additional params specific to certain TCs, e.g. etc.
           the +a option can also be used in multi-threads testing mode, included below is an example which tells program to wait 300 
           milliseconds before entering next iteration, that way it controls per thread's execution rate.
           C07,CMPG-S01534,BNDL-M25078,variants,+a,300

'''.format(arg)
  print(out_string)

# dump scenarios' descriptions
def dump_sce():
  out_string = '''

  TC C00: *enums. Get all enums.
          Param required: Nil
          new_cc_driver.py -e UAT_EBS -d -V -s C00

  TC C01: *campaigns. Get campaigns prescribed by various params.
          Param required: 1) root, LOV:(Mobile, Broadband, CableTV, DigitalVoice, InternationalCallService, Hubbing, InternetTV, DualBB, SmartUC, DualConnect, BRN, Consumer, OTT);
                          2) campaignId, e.g. CMPG-S00656; 3) campaign name; 4) campaign type, LOV:(STANDARD, RETAIL, TARGETED, ROADSHOW, WEEKEND, FESTIVAL, ONLINE, PRODUCT_SERVICE, CIS, ALACARTE, UPSELL, NO_CONTRACT)
          Note: [1] params 1 to 4 are concatenated and delimited by ":", all params are optional, but one must be present.
                [2] root and campaign type LOVs are derived from C00 output.
          e.g. new_cc_driver.py -e UAT_EBS -d -V -s C01 :::STANDARD
          or   new_cc_driver.py -e UAT_EBS -d -V -s C01 :CMPG-S00656 

  TC C02: *campaigns/code_{campaignId}/bundles. Get bundles by campaignId.
          Param required: 1) campaignId*, e.g. CMPG-S00443

  TC C03: *campaigns/bundles/code_{0}/promotions. Get promotions, offers or plans details by bundleId.
          Param required: 1) bundleId*, e.g. BNDL-S00062; 2) type, LOV:(promotions, offers, plans, variants), default to promotions
          e.g. new_cc_driver.py -e UAT_EBS -d -V -s C03 BNDL-S00062
          or   new_cc_driver.py -e UAT_EBS -d -V -s C03 BNDL-S00062 offers
          or   new_cc_driver.py -e UAT_EBS -d -V -s C03 BNDL-S00062 plans

  TC C04: *campaigns/bundles/{bundleId}/plans. Get plans by bundleId.
          Param required: 1) campaignId*, e.g. BNDL-S00062
          e.g. new_cc_driver.py -e UAT_EBS -d -V -s C04 BNDL-S00062

  TC C05: *campaigns. Get plans by bundleId.
          Param required: 1) campaign type*, LOV:(alacarte, cis, festival, online, retail, roadshow, standard, targeted, upsell).
          e.g. new_cc_driver.py -e UAT_EBS -d -V -s C05 standard

  TC C06: *campaigns/code_{campaignId}/bundles. Get all bundles of a given campaign.
          Param required: 1) campaignId e.g. CMPG-S01534
          e.g. new_cc_driver.py -e UAT_EXT -d -V -s C06 CMPG-S01534

  TC C07: *campaigns/code_{campaignId}/bundles/code_{bundleId}. Get offers, plans or commitment of a given bundle.
          Param required: 1) campaignId e.g. CMPG-S01534; 2) bundleId, e.g. BNDL-M25078; 3) selection, LOV:(offers, plans, commitments, variants)
          e.g. new_cc_driver.py -e UAT_EXT -d -V -s C06 CMPG-S01534 BNDL-M25078 offers

  TC C08: *prices. Get device price by epos ProgramId.
          Param required: 1) epos ProgramId*, e.g. AAA0000001; 2) limit*, e.g. 100, default to 10.
          Note: params 1 and 2 are concatenated and delimited by ":".
          e.g. new_cc_driver.py -e UAT_EBS -d -V -s C08 AAA0000001:5

  TC C09: *cpes/variants/devices. Get all devices.
          Param required: Nil
          e.g. new_cc_driver.py -e UAT_EBS -d -V -s C09

  TC C10: *cpes/variants?deviceCode={deviceCode}. Get mobile device by device code.
          Param required: 1) deviceCode*, e.g. NNI-MOBH-01819
          e.g. new_cc_driver.py -e UAT_EBS -d -V -s C10 NNI-MOBH-01819

  TC C11: *cpes/manufacturers. Get CPE manufacturers.
          Param required: 1) code, e.g. ENOK; 2) name, e.g. Nokia
          Note: params 1 and 2 are concatenated and delimited by ":", all params are optional.
          e.g. new_cc_driver.py -e UAT_EBS -d -V -s C11 :Nokia
          or   new_cc_driver.py -e UAT_EBS -d -V -s C11

  TC C12: *campaigns/bundles?root={0}. Get bundle promotion by root product.
          Param required: 1) root*, LOV:(Mobile, Broadband)
          e.g. new_cc_driver.py -e UAT_EXT -d -V -s C12 Broadband

  TC C13: *products/code_{planPartNum}/relate/MUST_HAVE. Get MUST_HAVE components of a plan by planPartNum.
          Param required: 1) planPartNum*, e.g. MOBL-10478_4GFSMAIN
          e.g. new_cc_driver.py -e UAT_EXT -d -V -s C13 MOBL-10478_4GFSMAIN

  TC C14: *products/code_{planPartNum}/relate/CAN_HAVE. Get CAN_HAVE components of a plan by planPartNum.
          Param required: 1) planPartNum*, e.g. MOBL-10478_4GFSMAIN
          e.g. new_cc_driver.py -e UAT_EXT -d -V -s C14 MOBL-10478_4GFSMAIN

  TC C15: *products. Get various products prescribed by type, subtype and rootProd.
          Param required: 1) type* LOV:(Device, Discount, Commitment, Voucher, Root, Plan, VAS, ChannelPack, Channel, Deposit, Charge); 2) subType, LOV:(RETENTION, MARKETING); 3) rootProd, LOV:(Mobile, Broadband); 4) product code.
          Note: [1] params 1 to 4 are concatenated and delimited by ":", all params are optional, but one must be present.
                [2] subType is relevent when type is Voucher
                [2] type is derived from C00 output.
          e.g. new_cc_driver.py -e UAT_EBS -d -V -s C15 Device::Mobile
          or   new_cc_driver.py -e UAT_EBS -d -V -s C15 Voucher:RETENTION
          or   new_cc_driver.py -e UAT_EBS -d -V -s C15 Plan::Mobile
          or   new_cc_driver.py -e UAT_EBS -d -V -s C15 :::NGN-EBS08997_500M_36MTH

  TC C16: *products/code_{partNum}/parameters. Get a given product's parameters.
          Param required: 1) prodPartNum*, e.g. MOBL-10144
          e.g. new_cc_driver.py -e UAT_EXT -d -V -s C16 MOBL-10144

  TC C17: *products/{productId}/{type}. Get a given product's subordinated components.
          Param required: 1) product id*, e.g. 660; 2) type, LOV:(musthave, canhave).
          Note: product id is derived from output of C15.
          e.g. new_cc_driver.py -e UAT_EBS -d -V -s C17 660 canhave  

  TC C18: *cpes. Get CPE info.
          Param required: 1) code e.g. CPE-00140; 2) name e.g. "Xperia T2 Ultra by SONY"; 3) type e.g. MobileHandset
          Note: params 1, 2, and 3 are concatenated and delimited by ":", all params are optional.
          e.g. new_cc_driver.py -e UAT_EBS -d -V -s C18
          or   new_cc_driver.py -e UAT_EBS -d -V -s C18 ::MobileHandset
          or   new_cc_driver.py -e UAT_EBS -d -V -s C18 CPE-00140

  TC C19: *cpes/{cpeCode}/variants. Get a given CPE's variants.
          Param required: 1) cpe code*, e.g. CPE-00140
          Note: cpe code is derived from output of C18.
          e.g. new_cc_driver.py -e UAT_EBS -d -V -s C19 CPE-00140

  TC C20: *cpes/{cpeCode}/variants/{cpeVariantCode}/devices. Get all products under the CPE Variant.
          Param required: 1) cpe code*, e.g. CPE-00140; 2) cpe variant code* e.g. CPEV-00174
          Note: cpe code is derived from output of C18; cpe variant code is derived from C19
          e.g. new_cc_driver.py -e UAT_EBS -d -V -s C19 CPE-00140 CPEV-00174

'''
  print(out_string)


#def login(req, cxt, hubId, passwd, verbose=True):
#  pass


#def isToken(s):
#  '''
#  evaluate if a string is token. Token is a string consists of lower cases alphanumeric e.g. 46d32d20a2176ef253efe1104ad98a204a1087f6
#  '''
#  return re.match("^[\da-z]{40}$", s)


def augmented_print(msg, **kw):
  suppress = kw.get('suppress', False)
  if not suppress:
    print(msg)

devnull = open(os.devnull, 'w')
class RedirectStdStreams(object):
  def __init__(self, stdout=None, stderr=None):
    self._stdout = stdout or sys.stdout
    self._stderr = stderr or sys.stderr

  def __enter__(self):
    self.old_stdout, self.old_stderr = sys.stdout, sys.stderr
    self.old_stdout.flush(); self.old_stderr.flush()
    sys.stdout, sys.stderr = self._stdout, self._stderr

  def __exit__(self, exc_type, exc_value, traceback):
    self._stdout.flush(); self._stderr.flush()
    sys.stdout = self.old_stdout
    sys.stderr = self.old_stderr

def remove_empty(d):
  if not isinstance(d, (dict, list)):
    return d
  if isinstance(d, list):
    return [v for v in (remove_empty(v) for v in d) if v]
  return {k: v for k, v in ((k, remove_empty(v)) for k, v in d.items()) if v}

def fibonacci(n):
  x, y = 0, 1
  for _ in range(n):
    x, y = y, x + y
  return x

def dummy_analyser(content, param_list, debug, verbose=True):
  pass

def C00_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C01_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C02_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C03_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C04_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C05_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C06_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C07_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C08_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C09_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C10_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C11_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C12_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C13_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C14_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C15_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C16_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C17_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C18_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C19_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C20_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

def C99_analyser(content, param_list, debug, verbose=True):
  if content.status_code != 200:
    return None
  data = content.json()
  if debug and verbose:
    pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nResult:')
    print(pretty)
  return data

# dummy payload
def dummy_payload(param_list, query_str_fl):
  return None, None

def C01_payload(param_list, query_str_fl):
  p_list = (param_list[0]+"::::").split(":")
  root = p_list[0]
  code = p_list[1]
  name = p_list[2]
  type = p_list[3].upper()

  payload = {}
  if root:
    payload["root"] = root
  if code:
    payload["code"] = code
  if name:
    payload["name"] = name
  if type:
    payload["type"] = type

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None

def C05_payload(param_list, query_str_fl):
  p_list = (param_list[0]+":").split(":")
  type = p_list[0].upper()

  payload = {}
  if type:
    payload["type"] = type

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None

def C08_payload(param_list, query_str_fl):
  p_list = (param_list[0]+":").split(":")
  eposProgramId = p_list[0]
  limit = p_list[1] if len(p_list[1]) > 0 else '10'

  payload = {}
  if eposProgramId:
    payload["eposProgramId"] = eposProgramId
  if limit:
    payload["limit"] = limit

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None

def C10_payload(param_list, query_str_fl):
  p_list = (param_list[0]+":").split(":")
  deviceCode = p_list[0]

  payload = {}
  if deviceCode:
    payload["deviceCode"] = deviceCode

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None

def C11_payload(param_list, query_str_fl):
  p_list = (param_list[0]+":").split(":")
  code = p_list[0]
  name = p_list[1]

  payload = {}
  if code:
    payload["code"] = code
  if name:
    payload["name"] = name

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None

def C12_payload(param_list, query_str_fl):
  p_list = (param_list[0]+":").split(":")
  root = p_list[0]

  payload = {}
  if root:
    payload["root"] = root

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None

def C15_payload(param_list, query_str_fl):
  p_list = (param_list[0]+":::::").split(":")
  type = p_list[0]
  subType = p_list[1]
  root = p_list[2]
  code = p_list[3]
  
  payload = {}
  if type:
    payload["type"] = type
  if subType:
    payload["subType"] = subType
  if root:
    payload["root"] = root
  if code:
    payload["code"] = code

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None

def C18_payload(param_list, query_str_fl):
  p_list = (param_list[0]+"::").split(":")
  code = p_list[0]
  name = p_list[1]
  type = p_list[2]

  payload = {}
  if code:
    payload["code"] = code
  if name:
    payload["name"] = name
  if type:
    payload["type"] = type

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def S01_func(tc_id, context, param_list, verbose, **kw):
  pass


def common_func(tc_id, context, param_list, verbose=True, **kw):
  # concatenated params passed in to submit function for logging purpose. 
  A_P = kw.get('A_P', '')
  if kw.get('suppress_params', False):
    params_str = ""
  else:
    params_str = ','.join(param_list)
  payload, querystr = get_payload(tc_id, param_list, query_str_fl(tc_id)) # get respective TC payload
  method, res, _, analyser = get_res_n_met(tc_id, param_list) # get respective request method, resource name, auth flag and analyser function.
  #url = get_end_point(tc_id) + res

  headers = get_headers(tc_id)
  retry = get_202_retry(tc_id)

  if kw.get('req'):
    req = kw.pop('req', None)
  else:
    req = Comm_req(CONTEXT.get('t_log', logger), get_end_point(tc_id))
#  if auth:
#    hubId, passwd = (param_list[0]+":").split(":")[:2]
#    if context['u_flag']:
#      u_token = passwd
#    elif isToken(passwd):
#      u_token = passwd
#    else:
#      u_token = login(req, context, hubId, passwd)
#      if u_token is None:
#        if verbose:
#          print(' - Error: {0} failed login.'.format(param_list[0]))
#          logger.debug(' - Error: {0} failed  login'.format(param_list[0]))
#        return
#    headers['authorization'] = u_token

  # integrate with dynatrace
  headers['x-dynatrace-test'] += ';PC={0};TSN={1};VU=Singleton'.format(res, tc_id)

  start = time.time()
  for i in range(Tries):
    r = req.submit_req(res, method, headers, data=payload, params=querystr, TC=tc_id, INPUT=params_str, A_P=A_P)
    if r.status_code != 202 or not retry:
      break
    time.sleep(fibonacci(i+1))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)

  etag = ''
  ret = None # function return value.
  if context['debug']:
    if verbose:
      req_obj = r.request
      print('{0}\n{1}\n{2}\n\n{3}\n{4}'.format(
            '\n-----------raw HTTP request-----------',
            req_obj.method + ' ' + req_obj.url,
            '\n'.join('{0}: {1}'.format(k, v) for k, v in req_obj.headers.items()),
            req_obj.body,
            '-----------raw HTTP request ends------\n'))
      print('\n-status_code: {0}'.format(r.status_code))
      print('-response: {0}'.format(r.content))
  if r.status_code == 200 or r.status_code == 201 or r.status_code == 202:
    ret = analyser(r, param_list, context['debug'], verbose)


  if context['debug']:
    print('\n - Statistics: Transaction Response Time: {0} sec.; Status: {1}; ETag: {2}; Throughput: {3} bytes; TC_ID: {4}. -- Param list: {5}\n'.format(dur, r.status_code, etag, len(r.content), tc_id, params_str))
  return ret


def get_func(tc_id, cxt, param_list, v=True, **kw):
    switcher = {
        'S01': S01_func,
    }
    # Get the function name from switcher dictionary to process the request
    func_name = switcher.get(tc_id, common_func)
    return func_name(tc_id, cxt, param_list, v, **kw)


def get_res_n_met(id, PARAM):
  param = PARAM + ['','','','','']
  switcher = {
    'C00': ('GET', 'enums', False, C00_analyser),
    'C01': ('GET', 'campaigns', False, C01_analyser),
    'C02': ('GET', 'campaigns/code_{0}/bundles'.format(param[0]), False, C02_analyser),
    'C03': ('GET', 'campaigns/bundles/code_{0}/{1}'.format(param[0], 'promotions' if len(param[1]) == 0 else param[1]), False, C03_analyser),
    'C04': ('GET', 'campaigns/bundles/{0}/plans'.format(param[0]), False, C04_analyser),
    'C05': ('GET', 'campaigns', False, C05_analyser),
    'C06': ('GET', 'campaigns/code_{0}/bundles'.format(param[0]), False, C06_analyser),
    'C07': ('GET', 'campaigns/code_{0}/bundles/code_{1}/{2}'.format(param[0], param[1], param[2]), False, C07_analyser),
    'C08': ('GET', 'prices', False, C08_analyser),
    'C09': ('GET', 'cpes/variants/devices', False, C09_analyser),
    'C10': ('GET', 'cpes/variants?deviceCode={0}'.format(param[0]), False, C10_analyser),
    'C11': ('GET', 'cpes/manufacturers', False, C11_analyser),
    'C12': ('GET', 'campaigns/bundles', False, C12_analyser),
    'C13': ('GET', 'products/code_{0}/relate/MUST_HAVE'.format(param[0]), False, C13_analyser),
    'C14': ('GET', 'products/code_{0}/relate/CAN_HAVE'.format(param[0]), False, C14_analyser),
    'C15': ('GET', 'products', False, C15_analyser),
    'C16': ('GET', 'products/code_{0}/parameters'.format(param[0]), False, C16_analyser),
    'C17': ('GET', 'products/{0}{1}'.format(param[0], '' if len(param[1]) == 0 else '/'+param[1]), False, C17_analyser),
    'C18': ('GET', 'cpes', False, C18_analyser),
    'C19': ('GET', 'cpes/{0}/variants'.format(param[0]), False, C19_analyser),
    'C20': ('GET', 'cpes/{0}/variants/{1}/devices'.format(param[0], param[1]), False, C20_analyser),

    'C99': ('GET', '{0}'.format(param[0]), False, C99_analyser),

    'S01': (None, None, False, None),
  }
  # Get the respective API request method and resource name from switcher dictionary
  return switcher.get(id)

# Dictionary Mapping for Functions to access the respective payload templates
def get_payload(arg, context, query_str_fl=False):
    switcher = {
      'C01': C01_payload,
      'C05': C05_payload,
      'C08': C08_payload,
      'C10': C10_payload,
      'C11': C11_payload,
      'C12': C12_payload,
      'C15': C15_payload,
      'C18': C18_payload,

    }
    # Get the paylaod template name from switcher dictionary
    tmpl_name = switcher.get(arg, dummy_payload)
    # return by executing the payload template function
    return tmpl_name(context, query_str_fl)


def query_str_fl(tc_id):
    switcher = {
    }
    flag = switcher.get(tc_id, True)
    return flag

def get_end_point(tc_id):
    switcher = {
    }
    # Get the TC specific end point from switcher dictionary to process the request
    end_point = switcher.get(tc_id, CONTEXT['end_point'][0])
    return end_point


def get_headers(tc_id):
    switcher = {
    }
    # Get the function name from switcher dictionary to process the request
    headers = deepcopy(HEADERS)
    header = switcher.get(tc_id, {"Accept": "application/json"})
    headers.update(header)
    return headers

def get_202_retry(tc_id):
    switcher = {
    }
    # Get the TC specific retry policy from switcher dictionary to process the request
    retry = switcher.get(tc_id, True)
    return retry

def thread_logger(file, threads, appendix):
  logger = logging.getLogger(appendix)
  logger.setLevel(logging.DEBUG)
  fh = logging.FileHandler(file + '_M' + str(threads) + '.' + appendix)
  fmt = '%(threadName)s,%(message)s'
  formatter = logging.Formatter(fmt)
  fh.setFormatter(formatter)

  logger.addHandler(fh)
  return logger
 
# get thread do_worker function name.
def get_do_worker(tc_id):
  switcher = {
    'S01': TS_worker,
  }
  return switcher.get(tc_id, common_worker)

# get end point of environment, default to UAT.
def get_ip_addr(env):
  '''
  Note: 
       [1] UAT_EXT -- refers consumer CC App external HA Proxy, which supports OLS, MSA etc. 
       [2] UAT_INT -- refers consumer CC App internal HA Proxy, which supports iDeal 
       [3] UAT_EBS -- refers EBS CC App HA Proxy, which supports SMB OLS, and SMB iDeal
  '''
  switcher = {
    'SIT1_EBS': ['http://172.20.64.57:8631/comcat/rest/'],
    'UAT_EBS': ['http://172.20.60.215:6700/comcat/rest/'],
    'UAT_EXT': ['http://172.20.60.216:6501/comcat/rest/'],
    'UAT_INT': ['http://172.20.60.215:6001/comcat/rest/'],
  }
  return switcher.get(env)


def TS_worker(req, res, headers, payload, querystr, method, log, tc_id, param_list, retry=True, a_p="N", think_t=0):
  pass

  
def common_worker(req, res, headers, payload, querystr, method, log, tc_id, param_list, retry=True, a_p="N", think_t=0):
  for i in range(Tries):
    r = req.submit_req(res, method, headers, data=payload, params=querystr, TC=tc_id, INPUT=';'.join(param_list[:-1]), A_P=a_p)
    if r.status_code != 202 or not retry:
      break
    time.sleep(fibonacci(i+1))
  
# the worker thread pulls an item from the queue and processes it
def worker(CNT, L_flag, ENDING, DELAY_START, PACING_TIME, log, dt_id, t_name):
  '''
  if L_flag is True, then execution control is duration dominant otherwise it is count dominant.
  Duration dominant has higher priority if both L_flag and CNT are specified.
  All three values: PACING_TIME, L_flag, CNT, can be over-written by thread level params. e.g. 1000:30;;U which means take 1000 milli seconds 
  pacing time for each iteration, and overwritten global execution duration and reset the execution duration to 30 mins for this thread,
  the U flag to tell program to treat hub_id as token for this tread;
  or ;3000:;20, which means overwritten global setting and execute this thread 20 times, it takes 3000 milli seconds think time.
  thread level param is composed of pacing_t;think_t:duration;iteration;U:log_prefix
  '''
  lFlag = L_flag
  cnt = CNT
  ending = ENDING
  pacing_time = int(PACING_TIME)/1000.0
  time.sleep(DELAY_START)
  think_t = 0

  while True:
    if TaskQueue is None or TaskQueue.empty():
      return

    item_x = TaskQueue.get()
    tc_id = item_x.split(',')[0].lstrip().rstrip()
    headers = get_headers(tc_id)
    retry = get_202_retry(tc_id)
    do_work = get_do_worker(tc_id)
    param_list = item_x.split(',')[1:]

    method, res, _, _ = get_res_n_met(tc_id, param_list) # get respective request method, resource name and auth flag
    payload = None
    querystr = None

    # integrate with dynatrace
    headers['x-dynatrace-test'] += ';PC={0};TSN={1};VU={2}'.format(res, tc_id, t_name)

    a_p = "N" # addtional parameter to support statisticss, to sort out different cases.
    if len(param_list) >= 2 and param_list[-2] == '+a':
      a_param_list = (param_list[-1] + ":::").split(":")
      #print(a_param_list)
      # 1st param to overwrite global pacing_time param
      if a_param_list[0]:
        ti_dict = dict(enumerate(a_param_list[0].split(";"))) # pacing time and think time override control
        if ti_dict.get(0, ''): # pacing time
          pacing_time = int(ti_dict.get(0)) / 1000.0
        if ti_dict.get(1, ''): # think time
          think_t = int(ti_dict.get(1)) / 1000.0
      # 2nd additional param consists of 3 control elements, 1) override excution duration; 2) override number of execution count;
      # override globle -U flag.
      if a_param_list[1]:
        ctl_dict = dict(enumerate(a_param_list[1].split(";")))
        #print(ctl_dict)
        if ctl_dict.get(2, ''): # token overwritten control
          if ctl_dict.get(2, '') == 'U':
            CONTEXT['u_flag'] = True
          else:
            CONTEXT['u_flag'] = False
          #print("U override")
        if ctl_dict.get(0, ''): # execution duration overwritten control
          ending = time.time() + float(int(ctl_dict.get(0)) * 60) # set estimated ending time.
          lFlag = True # duration dominant
        if ctl_dict.get(1, '') and not ctl_dict.get(0, '') : # number of execution count overwritten control
          cnt = int(ctl_dict.get(1))
          lFlag = False # count dominant
          
      param_list = param_list[:-2]
      a_p = a_param_list[2] if len(a_param_list[2]) > 0 else "N"

    req = Comm_req(log, get_end_point(tc_id))
#    if auth:
#      hubId, passwd = (param_list[0]+":").split(":")[:2]
#      if CONTEXT['u_flag']:
#        u_token = passwd
#      elif isToken(passwd):
#        u_token = passwd
#      else:
#        u_token = login(req, CONTEXT, hubId, passwd, verbose=False)
#      headers['authorization'] = u_token
#      if u_token is None:
#        TaskQueue.task_done()
#        continue
#      param_list[0] = ':'.join([hubId, u_token])


    if method: # if method is None, it means pseudo TC
      payload, querystr = get_payload(tc_id, param_list, query_str_fl(tc_id)) # get respective TC payload
      #url = get_end_point(tc_id) + res

    param_list.append(1) # param used as a flip and flap switch to some TCs.
    if lFlag: # control by duration
      while True:
        current = time.time()
        if current < ending:
          time.sleep(float(pacing_time))
          param_list[-1] ^= 1
          do_work(req, res, headers, payload, querystr, method, log, tc_id, param_list, retry, a_p, think_t)
        else:
          break
    else: # control by number of iterations
      for _ in range(cnt):
        time.sleep(float(pacing_time))
        param_list[-1] ^= 1
        do_work(req, res, headers, payload, querystr, method, log, tc_id, param_list, retry, a_p, think_t)
    TaskQueue.task_done()

# Define a main() function
def main():
  ###############################
  global CONTEXT, HEADERS
  S_flag = False
  s_flag = False
  L_flag = False
  M_flag = False
  V_flag = False
  ENV = None
  DT_ID = None
  pacing_time = 0
  THREADS = 0
  M_CNT = 1
  RAMPUP = None
  DELAY_START = 1 # postponning some sec before reading item from a queue, give producer some time to prepare the queue
  ending = time.time() + 60
 
  if len(sys.argv) == 1:
    usage(os.path.basename(sys.argv[0]))
    sys.exit(0)

  # parse command line options
  try:
    opts, args = getopt.getopt(sys.argv[1:], "e:f:s:w:L:M:c:D:B:ShdvV")
  except getopt.GetoptError as err:
    # print help information and exit:
    logger.error(err)
    usage(os.path.basename(sys.argv[0]))
    sys.exit(2)
  fn = None
  for o, a in opts:
    if o == "-e":
      CONTEXT['end_point'] = get_ip_addr(a) # get end point
      if not CONTEXT['end_point']: 
        print('\nUnsupported environment: {0}\n'.format(a))
        exit()
      ENV = a
    elif o == "-B":
      RAMPUP = a
    elif o == "-L":
      L_flag = True
      ending = time.time() + float(int(a) * 60) # set estimated ending time.
    elif o == "-D":
      DT_ID = a # Dynatrace id
    elif o == "-w":
      pacing_time = a
    elif o == "-c":
      M_CNT = int(a)
    elif o == "-M":
      M_flag = True
      THREADS = int(a)
    elif o == "-d":
      CONTEXT['debug'] = True
    elif o == "-v":
      print('{0} version: {1}'.format(os.path.basename(sys.argv[0]), version))
      sys.exit(0)
    elif o == "-h":
      usage(os.path.basename(sys.argv[0]))
      sys.exit()
    elif o == "-f":
      if os.path.isfile(a):
        fn = a  # input file name
      else:
        logger.error(" - File: {} doesn't exist.".format(a))
        print("File: {} doesn't exist.".format(a))
        sys.exit(2) 
    elif o == "-V":
      V_flag = True
    elif o == "-S":
      S_flag = True
    elif o == "-s":
      s_flag = True
      tc_id = a  # TC id
      param_list = []
      if len(args) == 1:
        param_list = args[0].split(",")
      elif len(args) == 0:
        pass
      else:
        param_list = args[0:]
      param_list.extend(['', '', '', '', ''])
    else:
      assert False, "unhandled option"
      sys.exit(1)

  logger.info(' - {0} {1} starts with params: {2}.'.format(os.path.basename(sys.argv[0]), version, sys.argv[1:]))
  if V_flag:
    print('\n{0} starts at {1}'.format(os.path.basename(sys.argv[0]), time.strftime("%Y%m%d %H:%M:%S",time.localtime())))
  # main body, branch 1: taking TC ids and TC contexts from an input file; branch 2: taking TC id and TC context params from command line.
  if S_flag:
    dump_sce()
    exit()
  elif fn != None: # with -f option
  ##########################################
    if M_flag == False:
      while True:
        # open the file and keep the file handle in variable fh.
        # iterate through the file to fetch TC id as well as TC context params
        with open(fn, 'r') as fh:
          for line0 in fh:
            context = {}
            context.update(CONTEXT)
            line = line0.rstrip('\n').lstrip() + '#'
            if line.startswith('#') or not line:
              continue
            line = line.split('#')[0].strip('\r').rstrip()
            # prepare respective payload based on the TC id, and context parameters followed
            tc_id = line.split(',')[0]
            param_list = line.split(',')[1:]
            if len(param_list) >= 2 and (param_list[-2] == '+a'):
              a_param_list = (param_list[-1] + ":::").split(":")
              # 2nd additional params to override globle -U flag.
              if a_param_list[1]:
                if a_param_list[1] == '1':
                  context['u_flag'] = True
                else:
                  context['u_flag'] = False
              if a_param_list[2] and a_param_list[3]:
                param_list.pop()
                param_list.append(a_param_list[2]+':'+a_param_list[3])
                #param_list.insert(-2, '')
                #param_list.insert(-2, '')
                #param_list.insert(-2, '')
                #param_list.insert(-2, '')
                #param_list.insert(-2, '')
              else:
                param_list.pop()
                param_list.pop()
            else:
              pass

            get_func(tc_id, context, param_list, V_flag)

            # before fetching next data, check whether ending time reached
            if L_flag == True:
              current = time.time()
              if current > ending:
                break
        # check whether current time exceeds ending time, if not entering into another round of for loop.
        if L_flag == True:
          current = time.time()
          if current > ending:
            break
        else:
          break
    else: # multithreads
    ############################### begining of multi-threading processing
      m_start = time.time()
      ts = time.strftime("%Y%m%d%H%M%S", time.localtime(m_start))
      t_log_name = myApp + '_M' + str(THREADS) + '.' + ts
      print('Program started with multi-threading, checking log file for prograss: {0}'.format(t_log_name))
      t_log = thread_logger(myApp, THREADS, ts) # get thread logger
      CONTEXT['t_log'] = t_log
      while True:
        # stuff work items on the queue (in this case, just a tuple of TC id and param list).
        with open(fn, 'r') as fh:
          for line in fh:
            line = line.rstrip('\n').lstrip() + '#'
            if line.startswith('#') or not line:
              continue
            line = line.split('#')[0].strip('\r').rstrip()
            # put TC id, and context parameters into a queue
            TaskQueue.put(line)

        # Create the queue and thread pool.
        if RAMPUP:
          BAT = int(RAMPUP.split(":")[0])
          #t_w = int(RAMPUP.split(":")[1]) * 60
          t_w = int(RAMPUP.split(":")[1])
        else:
          BAT = THREADS
          t_w = 0
        for i in range(THREADS):
          t_name = 'T{0:02d}'.format(i+1)
          th = threading.Thread(target=worker, name=t_name, args=(M_CNT, L_flag, ending, DELAY_START, pacing_time, t_log, DT_ID, t_name))
          th.daemon = True  # thread dies when main thread (only non-daemon thread) exits.
          th.start()
          if t_w != 0 and (i + 1) % BAT == 0 and i < THREADS - 1:
            time.sleep(t_w)

        TaskQueue.join()       # block until all tasks are done

        # check whether current time exceeds ending time, if not entering into another round of for loop.
        if L_flag == True:
          current = time.time()
          if current > ending:
            break
        else:
          break
      m_end = time.time()
      logger.info(' - Elapsed time: {0:.3f}'.format(m_end-m_start))
      print('Elapsed time: {0:.3f} sec.'.format(m_end-m_start))
    ################################# end of multi-threads processing
  elif s_flag:  # with -s option
    get_func(tc_id, CONTEXT, param_list, V_flag)
  else:
    usage(os.path.basename(sys.argv[0]))
    sys.exit()
    
  if V_flag:
    print('{0} ends at {1}\n'.format(os.path.basename(sys.argv[0]), time.strftime("%Y%m%d %H:%M:%S",time.localtime())))
  logger.info(' - {} ends.'.format(os.path.basename(sys.argv[0])))

# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
  main()
