#!/usr/bin/python2.7 -tt
# -*- coding: utf-8 -*-

# AUTHOR:       Gu Jian Min
# DATE:         26/09/2017
# PROGRAM:      smb_os_sim.py
# PURPOSE:
#               Simulating SMB OS App to interact with ESB Layer(FAPI).
#
# HISTORY:
#       version 1.0     26/09/2017              --- program initial
#       version 3.0     20/08/2020              --- major enhancement.
#       version 3.1     08/09/2020              --- introduced esso login function
#
# Note:
#      [1] For those APIs which require token, follow below steps to get token:
#          step 1: login using EID in https://onlinestore-uat.business.starhub.com/business/store/mobile.html#/
#                  using herewith EID: s1575256d_peter@yopmail.com / Starhub123; BRN: 1959946162S; BA: 8.20017646
#          step 2: after successful login, click herewith url to get session id: https://onlinestore-uat.business.starhub.com/content/smb/en/dev/login/status.txt
#          step 3: searching for keyword SM_SERVERSESSIONID to find session id. e.g. wOrPiXSojaKLijDCIy1P5jByddI=
#
version = 'v3.1'

import sys
import os
import re
import datetime
import time
import requests
import json
import getopt
import logging
import threading
import Queue
from copy import deepcopy
#from comm_req import Comm_req, Comm_req2
from new_comm_req import Comm_req, Comm_req2
import urllib
from esso_login import login


# lock to serialize output to log file
lock = threading.Lock()
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
CONTEXT = {'end_point':[], 'ua':None, 'u_flag':False, 'debug':False, 'etag':None, 't_log':logger, 'l_log':logger}
#HEADERS = {'X-Content-Type': 'application/json', 'Accept': 'application/json', 'X-User-Agent': 'starhub/online/smb'}
HEADERS = {'X-Content-Type': 'application/json', 'Content-Type': 'application/json', 'Accept': 'application/json', 'X-User-Agent': 'c9e089752a5cc0ec76984b4f0b7a4431', "x-dynatrace-test": "SI=ETM_Automation;SN=smb_os_sim.py"}
PROXIES = {'https':'proxy.starhubsg.sh.inc:8080', 'http':'proxy.starhubsg.sh.inc:8080'}
Tries = 15

def usage(arg):
  out_string = '''
Simulating SMB OS App to interact with ESB Layer(FAPI).

Usage 1: {0} [-e env] [-U] [-d] [-L min] [-w sec] [-M th_num] [-B rampup] [-c num] -f tc_file
Usage 2: {0} [-e env] [-U] [-d] -s tc_id params
Usage 3: {0} -S
Usage 4: {0} -A json_f [Y/N]

where
       -e: option for environment, default is UAT.
      env: one of the supported environment, i.e. UAT, only one environment exists for now.
       -M: a flag to instruct program to run in multi-threads.
   th_num: indicate number of threads.
       -B: ramp up indicator.
   rampUp: ramp up criterion, in the form of num:seconds, e.g. 5:20 which means instantiating 5 threads every 20 seconds.
       -c: a flag to instruct program to make num of requests with same set of data in tc_file.
      num: a number e.g. 10
       -f: a flag to instruct program to retrieve TC id as well as TC params from hereafter input file, e.g. tc_file.
  tc_file: a file contains list of test cases, in the form of tc_id, context parameters, e.g. Z09,xyz@hotmail.com,98001010 
           per test case dependant params descriptions, check through: {0} -S option.
       -w: a flag to instruct program to wait some seconds before submitting next request.
      sec: number of seconds to wait.
       -L: a flag to instruct program to run x number of minutes.
      min: number of minutes.
       -s: request to execute one single test case determined by hereafter tc_id
       -U: a flag to instruct program to treat the parameter for hub_id as authorization token, i.e. skip the login the process.
       -d: a flag to instruct program to print detailed execution info.
    tc_id: test case id to be invoked.
   params: test case dependent parameters. Check through {0} -S
 +i|+o|+b: supplementary parameter to instruct program to dump the TC result into an out put file or get the payload from an input file.
           +i stipulates that the TC's payload from hereafter input file; +o stipulates that the TC's results will be generated in hereafter
           output file; +b stipulates both input and output files. If both input and output files exist, then input and output file names are 
           sperated by ":" character, e.g. ba.json:promo.json
       -A: a flag to instruct program to print the here after json file in pretty mode or one line mode depending the the flag Y or N, default to Y.
   json_f: a file contains json data.

Note: 1) For authorized TC, the 2nd parameter of TC dependent params is token or password.

'''.format(arg)
  print(out_string)

# dump scenarios' descriptions
def dump_sce():
  out_string = '''

  TC X00:  *login. Get token.
           Params required: 1) eid:brn*; 2) password*
           Note: [1] eid stands for Enterprise ID, usually it is an email address; brn stands for Business register number.
                 [2] if brn is omitted, the first brn in eid_brn_list will be selected.
           e.g. smb_os_sim.py -e UAT -d -V 2 -s X00 edtf00001@mailinator.com Starhub123
           or   smb_os_sim.py -e UAT -d -V 2 -s X00 edtf00001@mailinator.com:EDTF00001 Starhub123

  TC X01:  *esso login. Get sm_serversessionid.
           Params required: 1) eid*; 2) password*.
           e.g. smb_os_sim.py -e UAT -d -V 2 -s X01 edtf00001@mailinator.com Starhub123

  TC X02:  *login/enterprise. Get token from sm_serversessionid.
           Params required: 1) eid*; 2) sm_serversessionid*

  TC X03:  *authtoken.
           Params required: 1) brn*; 2) token* e.g. 318154874179c495233d3bd32c1b70569713bfc2; 3) docType* e.g. BRN_SME
           e.g. smb_os_sim.py -e UAT -d -V 2 -s X03 EDTF00001 027cd77fe9acfb966fd6c1f1f9a33129a09a842e BRN_SME 

  TC X04:  *getUserInfo.
           Params required: 1) eid:brn*; 2) password|token*; 3) docType e.g. BRN_SME
           e.g. smb_os_sim.py -e UAT -d -V 2 -s X04 xyz_123@yopmail.com Starhub123 BRN_SME

  TC X05:  *login/verifyBRN.
           Params required: 1) eid:brn*; 2) password|token*; 3) brn*
           e.g. smb_os_sim.py -e UAT -d -V 2 -s X05 xyz_123@yopmail.com 3bbf4a0ba88809478523a08125f6938c124640e3 19840010L

  TC A01:  *customerinfo. Get BRN customer's details.
           Params required: 1) eid:brn*; 2) password|token*;
           e.g. smb_os_sim.py -e UAT -d -V 2 -s A01 xyz_123@yopmail.com Starhub123

  TC A02:  *bills/{billingAC}. Get billing account info.
           Params required: 1) eid:brn*; 2) password|token; 3) billingAC e.g. 8.20009081.
           e.g. smb_os_sim.py -e UAT -d -V 2 -s A02 xyz_123@yopmail.com Starhub123 8.20017633

  TC A03:  get given mobile number's contract.
           Params required: 1) eid:brn*; 2) password|token*; 3) msisdn*.
           e.g. smb_os_sim.py -e UAT -d -V 2 -s A03 20171013007f@mailinator.com Starhub123 94593482

  TC A04:  *bills/checkPaidOverdueAmt. Check BRN customer's overdue amount.
           Param required: 1) eid:brn*; 2) password|token*.
           e.g. smb_os_sim.py -e UAT -d -V 2 -s A04 20171013007f@mailinator.com Starhub123

  TC A05:  *contracts/{prodType}.
           Params required: 1) eid:brn*; 2) password|token*; 3) prodType*; 4) billingAC*; 5) mobileType, LOV:(voice, data).
           Note: param 4 and 5 are concatenated and delimited by ":"
           e.g. smb_os_sim.py -e UAT -d -V 2 -s A05 edtf00001@mailinator.com Starhub123 SmartUC 8.20016885:VOICE
           or   smb_os_sim.py -e UAT -d -V 2 -s A05 edtf00001@mailinator.com Starhub123 broadband 8.20016885

  TC A06:  *bills/{billingAC}. Get billing account info.
           Param required: 1) eid:brn*; 2) password|token*; 3) billingAC*
           e.g. smb_os_sim.py -e UAT -d -V 2 -s A06 edtf00001@mailinator.com Starhub123 8.20016885 

  TC A07:  *new/{prodType}/ebg. Check eligibility of signing up new contract.
           Params required: 1) eid:brn*; 2) password|token*; 3) prodType*, LOV: (Broadband, SmartUC, mobile); 4) billingAC; 5) samAddressId; 6) baCreaditFlag, LOV: (Y)
           e.g. smb_os_sim.py -e UAT -d -V 2 -s A07 edtf00001@mailinator.com Starhub123 SmartUC 8.20016885
           or   smb_os_sim.py -e UAT -d -V 2 -s A07 edtf00001@mailinator.com Starhub123 SmartUC
           or   smb_os_sim.py -e UAT -d -V 2 -s A07 edtf00001@mailinator.com Starhub123 Broadband 8.20016885 AA01603780

  TC A08:  *ebsucgroup. Get UC group info.
           Param required: 1) eid:brn*; 2) password|token;
           e.g. smb_os_sim.py -e UAT -d -V 2 -s A08 edtf00001@mailinator.com:EDTF00001 Starhub123

  TC A09:  *inventory/queryResource. Query SmartUC resources.
           Params required: 1) eid*; 2) resGrpId* e.g. UCG122818; 3) attrVal e.g. 3309; 4) qty e.g. 30, default to 20.
           e.g. smb_os_sim.py -e UAT -d -V 2 -s A09 xyz_123@yopmail.com:::30
           or   smb_os_sim.py -e UAT -d -V 2 -s A09 xyz_123@yopmail.com:UCG122818:3309:

  TC A10:  *transactions. Get history of transactions. 
           Params required: 1) eid:brn*; 2) password|token*; 3) orderDate*; 4) status, LOV: (Completed, In Progress, Cancelled, All Status), default to All Status.
           e.g. smb_os_sim.py -e UAT -d -V 2 -s A10 edtf00001@mailinator.com:EDTF00001 Starhub123 90


  TC B01:  *basket(GET). Retrieve the basket.
           Params required: 1) eid:brn*; 2) password|token*; 3) basketId
           e.g. smb_os_sim.py -e UAT -d -V 2 -s B01 xyz_123@yopmail.com Starhub123

  TC B02:  *basket/pick(PUT). Put various picks into basket.
           Params required: 1) eid:brn*; 2) password|token*; 3) pickType*, see Note [1]; 4) pick*, a payload json string or a file which contains pick payload json string.
           Note: [1] pickType LOV:(promo, subscription, product, device, resource, voucher). promo pick is the first pick to create a basket.

  TC B03:  *basket/eligibility. Check the eligibility of the basket.
           Params required: 1) eid:brn*; 2) password|token*
           e.g. smb_os_sim.py -e UAT -d -V 2 -s B03 s2794155i_peter@yopmail.com Starhub123

  TC B04:  *basket(DELETE). Delete the basket under this customer.
           Params required: 1) eid:brn*; 2) password|token*
           e.g smb_os_sim.py -e UAT -d -V 2 -s B04 s2794155i_peter@yopmail.com Starhub123

  TC B05:  *basket/status. Get basket status.
           Params required: 1) eid:brn*; 2) password|token*; 3) basketId*.
           e.g. smb_os_sim.py -e UAT -d -V 2 -s B05 s2794155i_peter@yopmail.com Starhub123 23652

  TC B06:  *basket/totals. Get total charge of a basket.
           Params required: 1) eid:brn*; 2) password|token*; 3) basketId*
           e.g. smb_os_sim.py -e UAT -d -V 2 -s B06 s2794155i_peter@yopmail.com Starhub123 23653

  TC B07:  *basket/customerinfo(put).
           Params required: 1) eid:brn*; 2) password|token*; 3) groupAdminInfo*, see Note [1].
           Note: [1] groupAdminInfo is a tuple of 4 elements (groupAdminId, name, phone, email) delimited by ":", if an UC group exist, groupAdminId will be given, otherwise 
                     name, phone and email info need to be provided to create.
           e.g. smb_os_sim.py -e UAT -d -V 2 -s B07 s2794155i_peter@yopmail.com Starhub123 UC12345 
           or   smb_os_sim.py -e UAT -d -V 2 -s B07 s2794155i_peter@yopmail.com Starhub123 :Peter:98001010:peter@yopmail.com

  TC B08:  *basket/pick(DELETE). Delete a given pick from basket.
           Params required: 1) eid:brn*; 2) password|token*; 3) pickId*
           e.g smb_os_sim.py -e UAT -d -V 2 -s B08 s2794155i_peter@yopmail.com Starhub123 6861578

  TC B09:  *contractdocs/{basketId}/scannedFiles.
           Params required: 1) eid:brn*; 2) password|token*; 3) basketId*
           e.g. smb_os_sim.py -e UAT -d -V 2 -s B09 edtf00001@mailinator.com Starhub123 27465

  TC B10:  *checkout. Checkout a verified basket (othan than Broadband).
           Params required: 1) eid:brn*; 2) password|token*; 3) basketId*
           e.g smb_os_sim.py -e UAT -d -V 2 -s B10 xyz@hotmail.com Starhub123 6861578

  TC B11:  *checkout. Checkout a verified Broadband basket.
           Params required: 1) eid:brn*; 2) password|token*; 3) basketId*.
           e.g smb_os_sim.py -e UAT -d -V 2 -s B11 xyz@hotmail.com Starhub123 6861578

  TC B12:  *basket/pick/billdeliverymethod/{basketId}. Update bill delivery method.
           Params required: 1) eid:brn*; 2) password|token*; 3) basketId*; 4) promoPickId; 5) subsPickId; 6) billDeliveryMethod, default to "Electronic Invoice"
           e.g smb_os_sim.py -e UAT -d -V 2 -s B12 xyz@hotmail.com Starhub123 27174 6920154 6920155

  TC B13:  update the collectionInfo into the basket. Param required:
           Params required: 1) eid:brn*; 2) password|token*; 3) payload in json string or a file which contains payload in json string

  TC B14:  *basket/pick/subscription/eligibility. Check eligibility of a given subscription.
           Params required: 1) eid:brn*; 2) password|token; 3) subsPickId*.

  TC B15:  *basket/pick(POST). Update various picks already in basket.
           Params required: 1) eid:brn*; 2) password|token*; 3) pickType*, see Note [1]; 4) pick*, a payload json string or a file which contains pick payload json string
           Note: [1] pickType LOV: (promo, subscription, product, device, resource, voucher).

  TC B16:  basket/finalise. Finalise the basket.
           Params required: 1) eid:brn*; 2) password|token*.

  TC B17:  checkout the basket.
           Params required: 1) eid:brn*; 2) password|token*; 3) basketId*

  TC B18:  retrieve the illustrative basket (existing assets) of a given the service id.
           Params required: 1) eid:brn*; 2) password|token*; 3) serviceId*


  TC D01:  *devices. List out all the devices of a given combination of prodType, campaign, bundle, offerType and filterVariant.
           Params required: 1) prodType*; 2) campaignId; 3) bundleId; 4) offerType; 5) planCategory; 6) filterVariant
           Note: [1] param 2 to 6 are concatenated and delimited by ":"
                 [2] a list of devices are concatenated and delimited by "%" 
           e.g. smb_os_sim.py -e UAT -d -V 2 -s D01 mobile CMPG-S00528:BNDL-B01373:RECONTRACT:VOICE:CPEV-00484%CPEV-00605%CPEV-00604%CPEV-00486

  TC D02:  *devices?bundleId={bundleId}&campaignId={campaignId}. List out all the devices of a given combination of campaignId and bundleId.
           Params required: 1) campaignId*; 2) bundleId*.
           Note: param 1 and 2 are concatenated and delimited by ":"
           e.g. smb_os_sim.py -e UAT -d -V 2 -s D02 CMPG-S00536:BNDL-B00314

  TC D03:  *devices/mobile/handset/{devStockCode}. Retrieve given mobile devices.
           Params required: 1) devStockCode* e.g. EAPP0019301; 2) campaignId; 3) bundleId; 4) offerType, LOV:(NEW, RECONTRACT); 5) planCategory, LOV:(VOICE, DATA); 6) contractType, LOV:(NEW, RECONTRACT).
           Note: params 2 onwards are concatenated and delimited by ":"
           e.g. smb_os_sim.py -e UAT -d -V 2 -s D03 EAPP0019301 CMPG-S00328:BNDL-M00459:RECONTRACT:VOICE
           or   smb_os_sim.py -e UAT -d -V 2 -s D03 UC-EBS800001 CMPG-S00777:BNDL-S00072:RECONTRACT::RECONTRACT

  TC D04:  *inventory. Get inventory status by list of stock codes.
           Params required: 1) devStockCode*; 2) devPartNum e.g. CPEV-00218
           Note: devStockCode can be a list of stock code delimited by ":", e.g. EAPP0007303:ESAM0030002
           e.g. smb_os_sim.py -e UAT -d -V 2 -s D04 EHUA0004601:EHUA0004602:EHUA0004603


  TC P01:  *promotions. List promitions for pertaining to type and customerType.
           Params required: 1) type, LOV: (SIM_ONLY); 2) customerType, LOV:(BRN).
           Note: params 1 and 2 are concatenated and delimited by ":"
           e.g. smb_os_sim.py -e UAT -d -V 2 -s P01 SIM_ONLY:BRN

  TC P02:  *promotions. List promitions for pertaining to an offerType and/or a prodType.
           Params required: 1) offerType, LOV: (RECONTRACT, NEW); 2) prodType, LOV:(Mobile, SmartUC, Broadband); 3) planCategory, LOV: (VOICE, DATA); 3) ucType, e.g. Lite
           Note: param 1 to 3 are concatenated and delimited by ":".
           e.g. smb_os_sim.py -e UAT -d -V 2 -s P02 NEW:Mobile:VOICE
           or   smb_os_sim.py -e UAT -d -V 2 -s P02 :SmartUC::Lite
           or   smb_os_sim.py -e UAT -d -V 2 -s P02 :Broadband

  TC P03:  *promotions/{prodType}/{bundle}.
           Params required: 1) prodType*, LOV:(Mobile, SmartUC, Broadband); 2) bundleId*; 3) broadbandType; 4) model; 5) speed.
           Note: [1] param 3, 4, and 5 are only applicable for prodType broadband, they are concatenated and delimited by ":"
           e.g. smb_os_sim.py -e UAT -d -V 2 -s P03 SmartUC BNDL-S00029
           or   smb_os_sim.py -e UAT -d -V 2 -s P03 Broadband BNDL-B00314 "NGN Fibre":Dynamic:1G
           or   smb_os_sim.py -e UAT -d -V 2 -s P03 Mobile BNDL-M00459

  TC P04:  *plans. List out all the plans of a given combination of prodTypei, campaign and bundle.
           Params required: 1) prodType*, LOV:(SmartUC, Broadband, Mobile); 2) campaignId; 3) bundleId.
           Note: param 2 and 3 are concatenated and delimited by ":"
           e.g. smb_os_sim.py -e UAT -d -V 2 -s P04 SmartUC CMPG-S00540:BNDL-S00029
           e.g. smb_os_sim.py -e UAT -d -V 2 -s P04 Broadband

  TC P05:  *products. Retrieve VASs of a given plan.
           Params required: 1) eid:brn*; 2) password|token*; 3) planPartNumber*; 4) campaignId; 5) bundleId; 6) promoCode
           Note: params 4, 5, and 6 are comcatenated and delimited by ":"
           e.g. smb_os_sim.py -e UAT -U -d -V 2 -s P05 edtf00001@mailinator.com Starhub123 NGN-EBS08433_1G_24MTH CMPG-S00536:BNDL-B00314:BSD91558
           or   smb_os_sim.py -e UAT -U -d -V 2 -s P05 edtf00001@mailinator.com Starhub123 UC-EBS26609 CMPG-S00777:BNDL-S00072

  TC P06:  *products/<prodType>/plans. This API supports two usages: 1) retrieve list of plans under given campaignId and bundleId; 2) retrieve commercial offers given to a given plan.
           Params required: 1) prodType*; 2) planPartNum; 3) campaignId; 4) bundleId.
           Note: [1] if planPartNum is irrelevant, use NA to keep the position.
                 [2] params 3 and 4 are concatenated and delimited by ":" if they do exist.
           e.g. smb_os_sim.py -e UAT -d -V 2 -s P06 DualConnect NGN-EBS08433_1G_24MTH
           or   smb_os_sim.py -e UAT -d -V 2 -s P06 Mobile NA CMPG-S00328:BNDL-M00459
           or   smb_os_sim.py -e UAT -d -V 2 -s P06 Mobile MOBL-EBS10750_STAND

  TC P07:  *products. Retrieve a given VAS detail.
           Params required: 1) eid:brn*; 2) password|token; 3) prodPartNumber* e.g. MOBL-10135
           e.g. smb_os_sim.py -e UAT -d -V 2 -s P07 edtf00001@mailinator.com Starhub123 MOBL-10135

  TC P08:  *vas/recommended.
           Params required: 1) eid:brn*; 2) password|token*; 3) prodType*
           e.g. smb_os_sim.py -e UAT -U -d -V 2 -s P08 edtf00001@mailinator.com Starhub123 Mobile


  TC G02:  *numbers. Retrieve list of numbers.
           Params required: 1) simType* e.g. "3G TriSIM Card"; 2) simCategory, LOV:(voice, data), default to voice; 3) quantity, default to 10 
           e.g. smb_os_sim.py -e UAT -d -V 2 -s G02 "3G TriSIM Card" voice 1

  TC G03:  check whether the given number is returning customer. Param required: 1) port in number (MSUSDN)

  TC G04:  check the eligibility for the AO/Shareholder/Director. Param required: 1) userEailId; 2) password or user token

  TC G05:  *brneligibility/smartsharecheck. Check whether the given BRN customer is eligible to get the Smartshare.
           Params required: 1) eid:brn*; 2) password|token*; 3) billingAC* e.g. 8.20009081
           e.g. smb_os_sim.py -e UAT -d -V 2 -s G05 edtf00001@mailinator.com Starhub123 8.20016885

  TC G06:  *recontract/changeplan/mobile/{0}/ebg. Check whether customer is eligible to sign up for sim only plan when recontracting.
           Params required: 1) eid:brn*; 2) password|token*; 3) MSISDN*.
           e.g. smb_os_sim.py -e UAT -d -V 2 -s G06 20171013013f@mailinator.com Starhub123 87220696

  TC G08:  *brneligibility/aocheck?aoEmailId={eid}. Check whether the given eid exists in other BRN company
           Params required: 1) eid:brn*; 2) password|token*; 3) aoEmail* e.g. xyz@hutmail.com
           e.g. smb_os_sim.py -e UAT -d -V 2 -s G08 edtf00001@mailinator.com Starhub123 20171013058f@mailinator.com

  TC H01:  *new/mobile/ebg. Check new mobile line sign up eligibility.
           Param required: 1) eid:brn*; 2) password|token*; 3) mode*, LOV:(cashncarry or delivery); 4) number of new line to signup*; 5) samAddressId* e.g. AA02605929; 6)  billing account e.g. 8.20009081
           e.g. smb_os_sim.py -e UAT -d -V 2 -s H01 edtf00001@mailinator.com Starhub123 delivery 1 AA00895109 8.20016885

  TC H02:  check mobile recontract eligibility.
           Params required: 1) eid:brn*; 2) password|token*; 3) msisdn* e.g. 99103289
           smb_os_sim.py -e UAT -d -V 2 -s H02 20171013013f@mailinator.com Starhub123 87220696


  TC J01:  *address. Get address info.
           Params required: 1) postalCode*;
           e.g. smb_os_sim.py -e UAT -d -V 2 -s J01 140057

  TC J02:  *address/coveragecheck.
           Params required: 1) postalCode*; 2) floor*
           e.g. smb_os_sim.py -e UAT -d -V 2 -s J02 140057 02


  TC K01:  retrieve voucher offer.
           Params required: 1) eid:brn*; 2) password|token*.
           e.g. smb_os_sim.py -e UAT -d -V 2 -s K01 edtf00001@mailinator.com Starhub123

  TC L01:  *brnappointments/{date}?root={prodType}. Get appointment slots of a given date.
           Params required: 1) eid:brn*; 2) password|token*; 3) date* in YYYY-MM-DD format; 4) prodType, LOV:(Mobile)
           e.g. smb_os_sim.py -e UAT -d -V 2 -s L01 edtf00001@mailinator.com Starhub123 2020-08-23 Mobile

  TC L02:  *brnappointments. Confirm BRN apppointment dates.
           Param required: 1) eid:brn*; 2) password|token; 3) list of subscription pick ids seperated by '^' e.g. 1234^5678;
                           4) list of date and time slots pair seperated by '^' e.g. 2017-10-20%09:00-10:30^2017-10-23%10:30-12:00
           Note: the paired date and time slot are seperated by '%'.

  TC L03:  *brnappointments/{ref_id}. Cancel BRN appointment dates.
           Param required: 1) eid:brn*; 2) password|token; 3) ref id (returned value from L02)


  TC M16:  put existing components pick into the basket. This is the step after putting device/resource pick into basket. Param required:
             1) userEailId; 2) password or user token; 3) main pick id (here refers subscription pick id);
             4) existing components pick payload json object (optional).
             Note: if +i existing_com.json supplementary parameters exist, it supersedes the 4th optional parameter

  TC O13:  check status of contract generation. Param required:
           params required: 1) eid:brn*; 2) password|token*; 3) shoppingCartNumber*

  TC O14:  download the contract.
           Param required: 1) eid:brn*; 2) password|token*; 3) orderId*


  TC S04:  *pseudo TC to create an new mobile contract under existing billing account. Param required:
           Params required: 1) eid*; 2) password|token*; 3) billingAC; 4) campaignId:offerId e.g. CMPG-S00757:142974; 5) bundleId; 6) planPartNum; 7) VASes; 8) msisdn:iccid 9) devStockCode, e.g. EAPP0007303.
           Note: [1] call P02 to get available campaigns, e.g. smb_os_sim.py -e UAT -d -V 2 -s P02 NEW:Mobile:VOICE
                 [2] call P03 to get offer details by taking a bundleId derived from P02 output, e.g. smb_os_sim.py -e UAT -d -V 2 -s P03 Mobile BNDL-M01520 
                 [3] call P04 w/wo campaignId and bundleId to get available VASes (preselected under campaignedId and bundle, or full list of VASes under the plan),
                     e.g. smb_os_sim.py -e UAT -d -V 2 -s P05 edtf00001@mailinator.com Starhub123 MOBL-EBS10750_STAND CMPG-S00757:BNDL-M01520
                 [4] call S09 to list all available Handsets (status: IN_STOCK), e.g. smb_os_sim.py -e UAT -s S09 CMPG-S00757 BNDL-M01520 Handset
           e.g. smb_os_sim.py -e UAT -s S04 edtf00001@mailinator.com Starhub123 8.20016885 CMPG-S00757:142975 BNDL-M01520 MOBL-EBS10750_STAND MOBL-10136 : EAPP0014301
         
  TC S05:  *pseudo TS to create a Broadband order.
           Param required: 1) eid*; 2) password|token*; 3) billingAC; 4) campaignId:offerId; 5) bundleId; 6) planPartNum; 7) suppInfo; 8) VASes; 9) addrInfo; 10) deviceStockCode; 11) submitFlag
           Note: [1] call P02 to get available campaigns, e.g. smb_os_sim.py -e UAT -d -V 2 -s P02 NEW:Broadband
                 [2] call P03 to get offer details by taking a bundleId derived from P02 output, e.g. smb_os_sim.py -e UAT -d -V 2 -s P03 Broadband BNDL-B00323
                 [3] call P04 w/wo campaignId and bundleId to get available VASes (preselected under campaignedId and bundle, or full list of VASes under the plan),
                     e.g. smb_os_sim.py -e UAT -d -V 2 -s P05 edtf00001@mailinator.com Starhub123 NGN-EBS08997_350M_36MTH CMPG-S00561:BNDL-B00323 
                 [4] call D02 to find the devices under the offer, e.g. smb_os_sim.py -e UAT -d -V 2 -s D02 CMPG-S00561:BNDL-B00323
           e.g. smb_os_sim.py -e UAT -s S05 edtf00001@mailinator.com Starhub123 8.20016885 CMPG-S00561:116857 BNDL-B00323 NGN-EBS08997_350M_36MTH "NGN Fibre:Dynamic:1G" NGN-EBS99005 609479:AA00458453 NGN-EBS800069

  TC S06:  *pseudo TS to create a SmartUC order with n number of lines.
           Param required: 1) eid*; 2) password|token*; 3) billingAC|addrInfo; 4) campaignId:offerId; 5) bundleId; 6) planPartNum; 7) VASes; 8) msisdn info, see Note [5]; 9) devStockCode, e.g. CPEV-U0001; 10) ucGrpName; 11) submitFlag
           Note: [1] call P02 to get available campaigns, e.g. smb_os_sim.py -e UAT -d -V 2 -s P02 NEW:SmartUC or smb_os_sim.py -e UAT -d -V 2 -s P02 NEW:SmartUC::Lite
                 [2] call P03 to get offer details by taking a bundleId derived from P02 output, e.g. smb_os_sim.py -e UAT -d -V 2 -s P03 SmartUC BNDL-S00026
                 [3] call P04 w/wo campaignId and bundleId to get available VASes (preselected under campaignedId and bundle, or full list of VASes under the plan),
                     e.g. smb_os_sim.py -e UAT -d -V 2 -s P05 edtf00001@mailinator.com Starhub123 UC-EBS12044 CMPG-S00515:BNDL-S00026
                 [4] for param 3, if billingAC provided, service will be created under giveb billingAC, otherwise a new billing account will be created with given address.
                 [5] param 8, msisdn info is either a number or a list of msisdn delimited by ":", e.g. 60005211:60005212:60005213. In case of number, it instructs program to take number of msisdn from resource pool.
                 [6] for IP phone, device is required, call D02 to choose a device from D02 response, e.g. smb_os_sim.py -e UAT -d -V 2 -s D02 CMPG-S00777:BNDL-S00072
           e.g. smb_os_sim.py -e UAT -s S06 edtf00001@mailinator.com Starhub123 8.20016885 CMPG-S00515:110479 BNDL-S00026 UC-EBS12044 : 1 : :
           or   smb_os_sim.py -e UAT -s S06 edtf00001@mailinator.com Starhub123 609479:AA00458453 CMPG-S00515:110479 BNDL-S00026 UC-EBS12044 MOBL-10043 5 : :
           or   smb_os_sim.py -e UAT -s S06 edtf00001@mailinator.com Starhub123 609479:AA00458453 CMPG-S00777:156591 BNDL-S00072 UC-EBS26609 UC-EBS12036:UC-EBS27212 2 UC-EBS800001 :

  TC S09:  pseudo TC to find out devices with status IN_STOCK.
           Param required: 1) campaignId*; 2) bundleId*; 3) deviceType, LOV:(Handset, Tablet).
           e.g. smb_os_sim.py -e UAT -s S09 CMPG-S00757 BNDL-M01520 Handset
         

  Note: In above TC/TS specication eid stands for Enterprise ID, usually it is an email address; brn stands for Business register number.

'''
  print(out_string)

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

def fibonacci(n):
  '''
  fibonacci sequences: 0,1,1,2,3,5,8,13,21,34,55,89,144,233,377,610,987,1597,2584,4181,6765
  cumelative waiting time in seconds: 0,1,2,4,7,12,20,33,54,88,143,232,376,609,986,1596,2583,4180,6764,10945,17710
  if tried 15 times, the cumulative waiting time will be 1596 sec. or 26.6 mins
  '''
  x, y = 0, 1
  for i in range(n):
    x, y = y, x + y
  return x

def isToken(s):
  '''
  evaluate if a string is token. Token is a string consists of lower cases alphanumeric e.g. 46d32d20a2176ef253efe1104ad98a204a1087f6
  '''
  return re.match("^[\da-z]{40}$", s)

def augmented_print(msg, **kw):
  suppress = kw.get('suppress', False)
  if not suppress:
    print(msg)


def get_202_retry(tc_id):
    switcher = {
      'B02': False,
      'B07': False,
      'B12': False,
      'B13': False,
      'L02': False,
    }
    # Get the TC specific retry policy from switcher dictionary to process the request
    retry = switcher.get(tc_id, True)
    return retry

def remove_empty(d):
  '''
  Remove Null/None Values From a Dictionary
  '''
  if not isinstance(d, (dict, list)):
    return d
  if isinstance(d, list):
    return [v for v in (remove_empty(v) for v in d) if v or v == 0]
  return {k: v for k, v in ((k, remove_empty(v)) for k, v in d.items()) if v or v == 0}

def ana_json(f, flag=True):
  with open(f, 'r') as fh:
    json_dict = json.load(fh)
  if flag:
    print(json.dumps(json_dict, indent=2, sort_keys=True))
  else:
    print(json.dumps(json_dict))


def fetch_ba(ba_list, cuscode):
  for ba in ba_list["billingAccount"]:
    if ba["billingAccountNo"][:10] == cuscode[:10]:
      return remove_empty(ba)


def collectInfoPayload(addrInfo, app_dt, time_slot, deliType, **kw):
  contactNum = kw.get("contactNum", "98001010")
  deliveryTo = kw.get("deliveryTo", "Mr. ETM")
  pmtMtd = kw.get("pmtMtd", "Cash")
  pmtType = kw.get("pmtType", "Cash on Delivery")
  email = kw.get("email", "")
  remark = kw.get("remark", "")

  payload = {}
  payload["deliveryAddress"] = addrInfo
  payload["type"] = deliType
  payload["appointDetail"] = {"absdetail": {"contactNumber": contactNum, "deliveryTo": deliveryTo, "paymentMethod": pmtMtd, "paymentType": pmtType, "preferredDeliveryDate": app_dt+"T00:00:00.000Z", "preferredDeliveryTime": time_slot}} 
  payload["contactDetail"] = {"contactNumber": contactNum, "email": email, "remark": remark}

  return payload


def resPickPayload(mainPickId, **kw):
  res_type = kw.get('res_type', 'Mobile')
  msisdn = kw.get('msisdn')
  if res_type == 'Mobile':
    simCat = kw.get('simCat', 'Voice')
    simType = kw.get('simType', '3G TriSIM Card')
    iccid = kw.get('iccid')

  payload = {"mainPickId": mainPickId, "resource": {"msisdnInfo":{"number": msisdn}}}
  
  if res_type == 'Mobile':
    payload["resource"]["msisdnInfo"]["iccid"] = iccid
    payload["resource"]["msisdnInfo"]["simcategory"] = simCat
    payload["resource"]["msisdnInfo"]["simType"] = simType

  #print(json.dumps(payload, sort_keys=True, indent=2, separators=(',', ':')))
  return payload


def vasPickPayload(mainPickId, comOffers, **kw):
  '''
  This is a generic vas pick, which accepts below keyword parameters:
    1) vas_list:
    2) addi_vas_list
    3) vas_pn:
    4) quantity:
  '''
  vas_list = kw.get("vas_list")
  addi_vas_list = kw.get("addi_vas_list")
  merged_vas_list = vas_list["product"] + addi_vas_list["product"] if addi_vas_list else vas_list["product"]

  vas_pn = kw.get("vas_pn")
  quantity = kw.get("quantity", "1")

  payload = {"mainPickId": mainPickId, "product": {"commercialOffers": {"commercialOffer":[]}}}
  for c in comOffers["commercialOffers"]["commercialOffer"]:
    if c.get("partnumber") == vas_pn and c.get("type") != "VAS":
      offer = remove_empty(c)
      offer["select"] = {"value": True}
      payload["product"]["commercialOffers"]["commercialOffer"].append(offer)
  if len(payload["product"]["commercialOffers"]["commercialOffer"]) == 0:
    payload["product"].pop("commercialOffers") 

  product = None
  #for p in vas_list["product"]:
  for p in merged_vas_list:
    if p.get("partNum") == vas_pn:
      p.pop("publishInfo", None)
      p["quantity"] = quantity
      p.pop("select", None)
      p["select"] = {"suppress":"off", "value":True}
      product = remove_empty(p)
      break
      
  for k, v in product.items():
    payload["product"][k] = v

  #print(json.dumps(payload, sort_keys=True, indent=2, separators=(',', ':')))
  return payload

  
def newDevicePickPayload(context, mainPickId, devStockCode, comOffers, **kw):
  '''
  This is a generic device pick, which accepts below keyword parameters:
    1) plan_pn:
    2) quantity:
    3) campaignId:
    4) bundleId:
    5) offerId:
    6) reserve:
    7) isRRP:
  '''
  req = kw.pop('req', None)
  plan_pn = kw.get("plan_pn")
  quantity = kw.get("quantity", "1")
  campaignId = kw.get("campaignId")
  bundleId = kw.get("bundleId")
  offerId = kw.get("offerId")
  reserve = kw.pop('reserve', 'no')
  isRRP = kw.pop('isRRP', 'Y')

  w_list = [devStockCode, ':'.join([campaignId, bundleId, '', '', '', isRRP])]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    device = common_func('D03', context, w_list, verbose=0, req=req, A_P=kw.pop('A_P', None))
  if device is None:
    return None
  device["quantity"] = quantity
  device["stockCode"] = devStockCode
  deviceOffers = device.pop("deviceOffers", {"deviceOffer": []})

  payload = {"mainPickId": mainPickId, "reserve": reserve, "device": device}
  payload["device"]["deviceOffers"] = {"deviceOffer":[]}

  if isRRP == 'Y':
    for d in deviceOffers["deviceOffer"]:
      #if d.get("offerId") == offerId or d.get("planPartNum", {}).get("value", 'NA') == plan_pn:
      if d.get("offerId") == offerId:
        offer = remove_empty(d)
        payload["device"]["deviceOffers"]["deviceOffer"].append(offer)
  else:
    for d in comOffers["deviceOffers"]["deviceOffer"]:
      #if d.get("offerId") == offerId or d.get("planPartNum", {}).get("value", 'NA') == plan_pn:
      if d.get("offerId") == offerId:
        offer = remove_empty(d)
        payload["device"]["deviceOffers"]["deviceOffer"].append(offer)

  #print(json.dumps(payload, sort_keys=True, indent=2, separators=(',', ':')))
  return payload


def newPlanPickPayload(context, mainPickId, comOffers, **kw):
  '''
  This is a generic plan pick, which accepts below keyword parameters:
    1) plan_pn:
    2) quantity:
    3) campaignId:
    4) bundleId:
    5) req:
    6) A_P:
  '''
  con_name_map = {'MOBL': 'Mobile', 'NGN': 'BroadBand', 'UC': 'SmartUC'}
  root_prod_map = {'MOBL': 'MOBL-10001', 'NGN': 'NGNR-EBS10002', 'UC': 'UCR-EBS10003'}

  req = kw.pop('req', None)
  plan_pn = kw.get("plan_pn")
  campaignId = kw.get("campaignId", "")
  bundleId = kw.get("bundleId", "")
  quantity = kw.get("quantity", "1")
  w_list = [con_name_map.get(plan_pn.split("-")[0]), ':'.join([campaignId, bundleId])]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('P04', context, w_list, verbose=0, req=req, A_P=kw.pop('A_P', None))
  if ret is None:
    return None

  product = None
  for p in ret["product"]:
    if p.get("partNum") == plan_pn:
      product = p
      break
  if product is None:
    return None
  product.pop("publishInfo", None)
  product["quantity"] = quantity
  product.pop("select", None)
  product["select"] = {"suppress":"off", "value":True}

  payload = {"mainPickId": mainPickId, "product": {"commercialOffers": {"commercialOffer":[]}}}
  for c in comOffers["commercialOffers"]["commercialOffer"]:
    if c.get("partnumber") == plan_pn and c["requiresGroups"]["requiresGroup"][0]["loV"]["value"][0]["value"] == plan_pn:
      offer = remove_empty(c)
      offer["select"] = {"value": True}
      payload["product"]["commercialOffers"]["commercialOffer"].append(offer)

  for k, v in product.items():
    payload["product"][k] = v
  payload["product"]["rootPartNum"] = root_prod_map.get(plan_pn.split("-")[0])

  #print(json.dumps(payload, sort_keys=True, indent=2, separators=(',', ':')))
  return payload


def newSubsPickPayload(mainPickId, billingAC, **kw):
  '''
  It is a generic subscription pick, which accepts below keyword parameters:
    1) appointment: True/False
    2) plan_pn: e.g. MOBL-10720_4GSTAND
    3) svc_addr:
    4) mos: e.g. 5G, default to 4G
    5) sd_num: short dial number used for SmartUC.
    5) remarks:
    6) bill_DeliMtd:
    7) bill_addr:
  If billingAC is None, it will create one when provisioing service.
  '''
  root_prod_map = {'MOBL': 'MOBL-10001', 'NGN': 'NGNR-EBS10002', 'UC': 'UCR-EBS10003'}
  con_name_map = {'MOBL': 'Mobile', 'NGN': 'broadband'}
  plan_pn = kw.get('plan_pn')
  svc_addr = kw.get('svc_addr')
  bill_addr = kw.get('bill_addr')
  bill_DeliMtd = kw.get('bill_DeliMtd')
  coverage_dtl = kw.get('coverage_dtl', False)
  if kw.get('appointment'):
    app_dt = kw.get('app_dt', (datetime.today() + timedelta(days=3)).strftime('%Y-%m-%d'))
    time_bd = kw.get('time_bd', '09:00-10:45')
    rfs_dt = kw.get('rfs_dt', app_dt)
    type_ = kw.get('type', 'Installation')

  payload = {"mainPickId": mainPickId, "subscription": {"contract":{}}}
  if billingAC:
    payload["subscription"]["billingAccount"] = billingAC
  else:
    payload["subscription"]["billingAccount"] = {"paymentProfile":{}}
  if bill_DeliMtd:
    payload["subscription"]["billingAccount"]["billDeliveryMethod"] = bill_DeliMtd
  if bill_addr:
    payload["subscription"]["billingAccount"]["billingAddress"] = bill_addr

  payload["subscription"]["contract"]["planPartNum"] = plan_pn
  if svc_addr:
    payload["subscription"]["contract"]["contractInfo"] = {"serviceAddress": svc_addr}
  payload["subscription"]["deviceCategory"] = "Others"
  payload["subscription"]["partNum"] = plan_pn
  payload["subscription"]["rootPartNum"] = root_prod_map.get(plan_pn.split("-")[0])
  payload["subscription"]["type"] = "new"
  if kw.get("remarks"):
    payload["subscription"]["remarks"] = kw.get("remarks")
  payload["subscription"]["contract"]["contractParams"] = {"serviceParam": [{"svcParamName": "Mode of Service", "svcParamValue": kw.get("mos", "4G")}, {"svcParamName": "Type of Plan", "svcParamValue": "Standalone"}]}

  if kw.get("sd_num"):
    payload["subscription"]["contract"]["contractParams"]["serviceParam"].append({"svcParamName": "Sd Number", "svcParamValue": kw.get("sd_num")})

  if plan_pn.split('-')[0] == 'NGN':
    payload["subscription"]["contract"]["broadband"] = {"serviceAddress": svc_addr}
    payload["subscription"]["contract"]["contractType"] = 'broadband'
  
  #print(json.dumps(payload, sort_keys=True, indent=2, separators=(',', ':')))
  return payload


def newPromoPickPayload(comOffers, offerId, **kw):
  payload = {'promo':{}}
  payload['promo']["campaignId"] = comOffers.get("campaignId")
  payload['promo']["campaignType"] = comOffers.get("campaignType")
  payload['promo']["ccCode"] = comOffers.get("ccCode")
  payload['promo']["ccSubType"] = comOffers.get("ccSubType")
  payload['promo']["code"] = comOffers.get("code")
  payload['promo']["contractType"] = comOffers.get("contractType")
  payload['promo']["defaultedMRC"] = comOffers.get("defaultedMRC")
  payload['promo']["defaultedMRCAfterDiscount"] = comOffers.get("defaultedMRCAfterDiscount")
  payload['promo']["defaultedMRCAfterDiscountWithGST"] = comOffers.get("defaultedMRCAfterDiscountWithGST")
  payload['promo']["defaultedMRCWithGST"] = comOffers.get("defaultedMRCWithGST")
  payload['promo']["deviceExists"] = comOffers.get("deviceExists")
  payload['promo']["displayName"] = comOffers.get("displayName")
  payload['promo']["displayName"] = comOffers.get("displayName")
  payload['promo']["offerId"] = offerId
  payload['promo']["premiumsOffered"] = comOffers.get("premiumsOffered")
  payload['promo']["priority"] = comOffers.get("priority")
  payload['promo']["promoCategory"] = comOffers.get("promoCategory")
  payload['promo']["promoEndDate"] = comOffers.get("promoEndDate")
  payload['promo']["promoPartNumber"] = comOffers.get("promoPartNumber")
  payload['promo']["promoStartDate"] = comOffers.get("promoStartDate")
  payload['promo']["promoSubType"] = comOffers.get("promoSubType")
  payload['promo']["promoType"] = comOffers.get("promoType")
  payload['promo']["scmId"] = comOffers.get("scmId")

  if kw.get('device_offer'):
    payload["promo"]["deviceOffers"] = {"deviceOffer":[]}
    for d in comOffers["deviceOffers"]["deviceOffer"]:
      if d.get("offerId") == offerId:
        offer = remove_empty(d)
        payload["promo"]["deviceOffers"]["deviceOffer"].append(offer)



  #print(json.dumps(payload, sort_keys=True, indent=2, separators=(',', ':')))
  return payload

  
def dummy_analyser(content, param_list, verbose):
  pass

def A01_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def A02_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data


def A03_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data
#  co = content.json()["mainContext"]["present"]["any"][0]["contract"][0]
#  ba = co["accountNo"]
#  commit = co["commitmentPeriod"]
#  promo = co["promotionName"]
#  co_sta = co["contractStatus"]
#  plan = co["planPartNum"]
#  if verbose == True:
#    print('\nBilling AC: {0}; Contract Status: {1}; Promo: {2}; Commit Period: {3}; Plan: {4}\n'.format(ba, json.dumps(co_sta), promo, commit, plan))
#  return (ba, co_sta, promo, commit, plan)
  

def A04_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data


def A05_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data


def A06_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data


def A07_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    eligible = resp_data["eligible"]
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
    print('\nEligible: {0}'.format(eligible))
  return resp_data


def A08_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def A09_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"]
  if verbose > 1:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def A10_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def P01_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
    print('\nSummary: (campaignId, name, bundleId, promoCode, ccSubType)')
    for i in data["promo"]:
      if not i.get("campaignId", None):
        continue
      print('\n{0}, {1}, {2}, {3}, {4}'.format(i["campaignId"], i["name"], i["promoPartNumber"], i["code"], i.get("ccSubType", "")))
      new_list = []
      recon_list = []
      nocon_list = []
      if i.get("applicabilitiesForNew", None):
        for j in i["applicabilitiesForNew"]["planPartNum"]:
          sub_val = ','.join([j.get("broadbandType", "") or '', j.get("model", "") or '', j.get("speed", "") or ''])
          if sub_val == ',,':
            sub_val = ''
          else:
            sub_val = '(' + sub_val + ')'
          new_list.append(j["value"] + sub_val)
      print('    applicabilitiesForNew: {0}'.format(', '.join(new_list)))
      if i.get("applicabilitiesForRecontract", None):
        for j in i["applicabilitiesForRecontract"]["planPartNum"]:
          sub_val = ','.join([j.get("broadbandType", "") or '', j.get("model", "") or '', j.get("speed", "") or ''])
          if sub_val == ',,':
            sub_val = ''
          else:
            sub_val = '(' + sub_val + ')'
          recon_list.append(j["value"] + sub_val)
      print('    applicabilitiesForRecontract: {0}'.format(', '.join(recon_list)))
      if i.get("applicabilitiesForNoContract", None):
        for j in i["applicabilitiesForNoContract"]["planPartNum"]:
          sub_val = ','.join([j.get("broadbandType", "") or '', j.get("model", "") or '', j.get("speed", "") or ''])
          if sub_val == ',,':
            sub_val = ''
          else:
            sub_val = '(' + sub_val + ')'
          nocon_list.append(j["value"] + sub_val)
      print('    applicabilitiesForNoContract: {0}'.format(', '.join(nocon_list)))
  return data

def P02_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
    print('\nSummary: (campaignId, name, bundleId, promoCode, ccSubType)')
    for i in data["promo"]:
      if not i.get("campaignId", None):
        continue
      print('\n{0}, {1}, {2}, {3}, {4}'.format(i["campaignId"], i["name"], i["promoPartNumber"], i["code"], i.get("ccSubType", "")))
      new_list = []
      recon_list = []
      nocon_list = []
      if i.get("applicabilitiesForNew", None):
        for j in i["applicabilitiesForNew"]["planPartNum"]:
          sub_val = ','.join([j.get("broadbandType", "") or '', j.get("model", "") or '', j.get("speed", "") or ''])
          if sub_val == ',,':
            sub_val = ''
          else:
            sub_val = '(' + sub_val + ')'
          new_list.append(j["value"] + sub_val)
      print('    applicabilitiesForNew: {0}'.format(', '.join(new_list)))
      if i.get("applicabilitiesForRecontract", None):
        for j in i["applicabilitiesForRecontract"]["planPartNum"]:
          sub_val = ','.join([j.get("broadbandType", "") or '', j.get("model", "") or '', j.get("speed", "") or ''])
          if sub_val == ',,':
            sub_val = ''
          else:
            sub_val = '(' + sub_val + ')'
          recon_list.append(j["value"] + sub_val)
      print('    applicabilitiesForRecontract: {0}'.format(', '.join(recon_list)))
      if i.get("applicabilitiesForNoContract", None):
        for j in i["applicabilitiesForNoContract"]["planPartNum"]:
          sub_val = ','.join([j.get("broadbandType", "") or '', j.get("model", "") or '', j.get("speed", "") or ''])
          if sub_val == ',,':
            sub_val = ''
          else:
            sub_val = '(' + sub_val + ')'
          nocon_list.append(j["value"] + sub_val)
      print('    applicabilitiesForNoContract: {0}'.format(', '.join(nocon_list)))
  return data

def P03_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  data = remove_empty(resp_data)
  if data is None:
    return None
  if verbose > 0:
    data_pretty = json.dumps(data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)

    print('\n\nSummary:')
    print('Applicable to New:')
    i_list = []
    if data.get("applicabilitiesForNew", None):
      for i in data["applicabilitiesForNew"]["planPartNum"]:
        sub_val = ','.join([i.get("broadbandType", ""), i.get("model", ""), i.get("speed", "")])
        if sub_val == ',,':
          sub_val = ''
        else:
          sub_val = '(' + sub_val + ')'
        i_list.append(i["value"] + sub_val)
    print('    {0}'.format(', '.join(i_list)))
    print('Applicable to Recontract:')
    i_list = []
    if data.get("applicabilitiesForRecontract", None):
      for i in data["applicabilitiesForRecontract"]["planPartNum"]:
        sub_val = ','.join([i.get("broadbandType", ""), i.get("model", ""), i.get("speed", "")])
        if sub_val == ',,':
          sub_val = ''
        else:
          sub_val = '(' + sub_val + ')'
        i_list.append(i["value"] + sub_val)
    print('    {0}'.format(', '.join(i_list)))
    print('Applicable to Nocontract:')
    i_list = []
    if data.get("applicabilitiesForNoContract", None):
      for i in data["applicabilitiesForNoContract"]["planPartNum"]:
        sub_val = ','.join([i.get("broadbandType", ""), i.get("model", ""), i.get("speed", "")])
        if sub_val == ',,':
          sub_val = ''
        else:
          sub_val = '(' + sub_val + ')'
        i_list.append(i["value"] + sub_val)
    print('    {0}'.format(', '.join(i_list)))

    print('commercialOffers (partNum, type, desc, bundleId, promoCode, preselected, mandatory):')
    #i_list = []
    for i in data["commercialOffers"]["commercialOffer"]:
      if i["type"] == "Charge":
       charge = ':'.join([i["charge"]["chargePartNum"], i["charge"]["name"], i["charge"]["chargeValue"]["type"], str(i["charge"]["chargeValue"]["value"])])
       print('    {0}, {1}, {2}, {3}, {4}'.format(i["type"], charge, i["waiver"]["waivePartNum"] if i.get("waiver", None) else "", str(i["preselected"]), str(i["mandatory"])))
      elif i["type"] == "Waiver":
       waiver = ':'.join([i["waiver"]["waivePartNum"], i["waiver"]["waiveValue"]["type"], str(i["waiver"]["waiveValue"]["value"])])
       print('    {0}, {1}, {2}, {3}, {4}'.format(i["type"], waiver, i["charge"]["chargePartNum"], str(i["preselected"]), str(i["mandatory"])))
      else:
        if i.get("discount", None):
          discount = ':'.join([i["discount"]["discPartNum"], i["discount"]["appliedTo"], i["discount"]["discValue"]["type"], str(i["discount"]["discValue"]["value"])])
          print('    {0}, {1}, {2}, {3}, {4}, {5}, {6}'.format(i["partnumber"], i["type"], discount, i["ccCode"], i["promoCode"], str(i["preselected"]), str(i["mandatory"])))

    print('deviceOffers: (campaignId, bundleId, offerId, promoCode, planPartNum, commitment, devicePartNum)')
    for i in data["deviceOffers"]["deviceOffer"]:
      commitment = ':'.join([i["commitment"]["commitPartNum"], i["commitment"]["name"], str(i["commitment"]["commitPeriod"])])
      print('    {0}, {1}, {2}, {3}, {4}, {5}, {6}'.format(i["campaignId"], i["ccCode"], i["offerId"], i["promoCode"], i["planPartNum"]["value"], commitment, i["partnumber"]))

  return resp_data


def P04_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  resp_data = remove_empty(resp_data)
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
    print('\nSummary (partNum, prodType, prodSubType, prodName):')
    for i in resp_data["product"]:
      print('{0}; {1}; {2}; {3}'.format(i.get("partNum", ""), i.get("prodType", ""), i.get("prodSubType", ""), i.get("prodName", "")))
  return resp_data

def P05_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
    print('\nSummary (partNum, prodType, prodName, preselected, mandatory):')
    for i in resp_data["product"]:
      print('{0}, {1}, {2}, {3}, {4}'.format(i["partNum"], i["prodType"], i["prodName"], str(i["preselected"]), str(i["mandatory"]))) 
  return resp_data

def P06_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  resp_data = remove_empty(resp_data)
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
    if resp_data.get("commercialOffers", None):
      print('\nSummary (bundleId; discPartNum; appliedTo; discName, preselected, mandatory):')
      for i in resp_data["commercialOffers"]["commercialOffer"]:
        print('{0}, {1}, {2}, {3}, {4}, {5}'.format(i["ccCode"], i["discount"]["discPartNum"], i["discount"]["appliedTo"], i["discount"]["name"], str(i.get("preselected", "")), str(i.get("mandatory", "")))) 
    if resp_data.get("product", None):
      print('\nSummary (partNum; prodType; prodSubType; prodName; rootPartNum, preselected, mandatory):')
      for i in resp_data["product"]:
        print('{0}, {1}, {2}, {3}, {4}, {5}, {6}'.format(i["partNum"], i["prodType"], i.get("prodSubType", ""), i["prodName"], i.get("rootPartNum", ""), str(i.get("preselected", "")), str(i.get("mandatory", "")))) 
  return resp_data

def P07_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def P08_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
    print('\nSummary (partNum, prodName, preselected, mandatory):')
    for p in resp_data["vas"][0]["product"]:
      print('{0}, {1}, {2}, {3}'.format(p.get("partNum"), p.get("prodName"), str(p.get("preselected", "")), str(p.get("mandatory", ""))))
  return resp_data

  
def D01_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def D02_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    if verbose > 1:
      data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
      print('\nData:')
      print(data_pretty)
    print('\nSummary (devicePartNum, deviceName, deviceSubType, devStockCode, devStockCodePartNum, issuance):')
    for i in resp_data["device"]:
      devStockCode_list = []
      devStockCode_pn_list = []
      for d in i["deviceVariants"]["deviceVariant"]:
        devStockCode_list.append(d.get("deviceStockCode", ""))
        devStockCode_pn_list.append(d.get("deviceStockPartNumber", ""))
      print('{0}, {1}, {2}, {3}, {4}, {5}'.format(i.get("devicePartNum", ""), i.get("deviceName", ""), i.get("deviceSubType", ""), ':'.join(devStockCode_list), ':'.join(devStockCode_pn_list), i.get("issuance", "")))
  return resp_data

def D03_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  resp_data = remove_empty(resp_data)
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def D04_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data
  

def G02_analyser(content, param_list, verbose):
  if content.status_code != 200 or content.json()["mainContext"].get("present") is None:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

  
def G04_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

  
def G05_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

  
def G06_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

  
def G08_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

  
def H01_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data
  

def H02_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data
  
  
def J01_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
    print('\nSummary(samAddressId, block, floor, unit):')
    for i in resp_data:
      print('{0}, {1}, {2}, {3}'.format(i.get("samAddressId"), i.get("block"), i.get("floor"), i.get("unit")))
  return resp_data

def J02_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data


def K01_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

  
def L01_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data
  
def L02_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data
  
def L03_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data
  
def B01_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    basketId = resp_data.get("id", "")
    cartNum = resp_data.get("cartNumber", "")
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
    print('\nCartNum: {0}; BasketId: {1}'.format(cartNum, basketId))
  return resp_data

def B02_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def B03_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    basket_status = resp_data["basketStatus"]
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
    print('\nBasket status: {0}'.format(basket_status))
  return resp_data

def B04_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def B05_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def B06_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def B07_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def B09_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def B08_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def B12_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def B13_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def B14_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def B15_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(remove_empty(resp_data), sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data


def B18_analyser(content, param_list, verbose):
  if param_list[-2] == '+o' and param_list[-1] != '':
    out_f = param_list[-1]
  elif param_list[-2] == '+b' and param_list[-1] != '':
    out_f = param_list[-1].split(':')[1]
  else:
    out_f = '/dev/null'
  x_list = content.json()["mainContext"]["present"]["any"][0]["existingComponents"]["pick"]
  list = remove_empty(x_list)
  if verbose == True:
    print('')
    for n, i in enumerate(list):
      print('\nExisting pick: {0}\n'.format(n))
      for k, v in i.iteritems():
        print('{0}: {1}'.format(json.dumps(k), json.dumps(v)))
    print('')
  with open(out_f, 'w') as outfile:  
    json.dump(list, outfile)
  return list
  
  
def X02_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()
  token = resp_data["userDetails"]["utoken"]
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
    print('\ntoken: {0}'.format(token))
  return token

  

def X04_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

def X05_analyser(content, param_list, verbose):
  if content.status_code != 200:
    return None
  resp_data = content.json()["mainContext"]["present"]["any"][0]
  if verbose > 0:
    data_pretty = json.dumps(resp_data, sort_keys=True, indent=2, separators=(',', ':'))
    print('\nData:')
    print(data_pretty)
  return resp_data

  
# dummy payload
def dummy_payload(param_list, query_str_fl):
  return None, None

# login payload
def login_payload(u_id, s_id):
  payload = {"enterpriseLogin":{"appId":"smbonline","appSecret":"smbonlineappsecret",
                                "sessionId":"{0}".format(s_id),
                                "emailUserId": "{0}".format(u_id)}
            }
  return payload

def A01_payload(param_list, query_str_fl):
  p_list = (param_list[0]+"::::::::::").split(":")
  aoEmail = p_list[0]

  payload = {}
  if aoEmail:
    payload["aoEmail"] = aoEmail

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None

def A05_payload(param_list, query_str_fl):
  p_list = (param_list[3]+"::::::::::").split(":")
  billAccountId = p_list[0]
  mobileType = p_list[1]

  payload = {"billAccountId": billAccountId, "pageSize": "50"}
  if mobileType:
    payload["mobileType"] = mobileType

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def A07_payload(param_list, query_str_fl):
  billingAccountNo = param_list[3].split(':')[0] if len(param_list) > 3 else None
  samAddressId = param_list[4].split(':')[0] if len(param_list) > 4 else None

  payload = {}
  if billingAccountNo:
    payload["billingAccountNo"] = billingAccountNo
  if samAddressId:
    payload["billingAddress"] = {"samAddressId": samAddressId}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def A08_payload(param_list, query_str_fl):
  _, DocNo = (param_list[0]+':').split(':')[:2]

  payload = {"DocNo": DocNo, "DocType": "BRN"}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def A09_payload(param_list, query_str_fl):
  p_list = (param_list[0]+"::::::::::").split(":")
  sourceUserID = p_list[0]
  resourceGroupID = p_list[1]
  attrValue = p_list[2]
  qty = p_list[3] if p_list[3] else "20"
  locParam2 = "UC_SHORT_DIAL_NBR" if attrValue else "UC_NUMBER"

  payload = {"sourceUserID": sourceUserID, "locParam1": "SMB ONLINE STORE", "locParam2": locParam2, "locParam3": "DELIVERY", "source": "OLS-EBG", "queryType": "INV",
             "resourceSubType": "UC_USER_NUMBER", "qty": qty, "page": "1", "pageSize": "30"}
  if resourceGroupID:
    payload["resourceGroupID"] = resourceGroupID
  if attrValue:
    payload["attrValue"] = attrValue

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def A10_payload(param_list, query_str_fl):
  orderDate = param_list[2]
  orderStatus = param_list[3] if len(param_list) > 3 and len(param_list[3]) > 0 else "All Status"

  payload = {"orderDate": orderDate, "orderStatus": orderStatus}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def P01_payload(param_list, query_str_fl):
  p_list = (param_list[0]+"::::::::::").split(":")
  _type = p_list[0]
  customerType = p_list[1]

  payload = {}
  if _type:
    payload["type"] = _type
  if customerType:
    payload["customerType"] = customerType

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def P02_payload(param_list, query_str_fl):
  p_list = (param_list[0]+"::::::::::").split(":")
  offerType = p_list[0]
  prodType = p_list[1]
  planCategory = p_list[2]
  ucType = p_list[3]

  payload = {"customerType": "BRN", "channel": "eshop"}
  if offerType:
    payload["offerType"] = offerType
  if prodType:
    payload["prodType"] = prodType
  if planCategory:
    payload["planCategory"] = planCategory
  if ucType:
    payload["ucType"] = ucType

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None

def P03_payload(param_list, query_str_fl):
  p_list = (param_list[2]+"::::::::::").split(":") if len(param_list) > 2 else '::'.split(":")
  prodType = param_list[0]
  broadbandType = p_list[0]
  model =  p_list[1]
  speed = p_list[2]

  payload = {"customerType": "BRN", "channel": "eshop", "prodType": prodType}
  if broadbandType:
    payload["broadbandType"] = broadbandType
  if model:
    payload["model"] = model
  if speed:
    payload["speed"] = speed

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def P04_payload(param_list, query_str_fl):
  p_list = (param_list[1]+"::::::::::").split(":") if len(param_list) > 1 else "::".split(":")
  campaignId = p_list[0]
  bundleId = p_list[1]

  payload = {"customerType": "BRN", "channel": "eshop"}
  if campaignId:
    payload["campaignId"] = campaignId
  if bundleId:
    payload["bundleId"] = bundleId

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def P05_payload(param_list, query_str_fl):
  p_list = (param_list[3]+"::::::::::").split(":") if len(param_list) > 3 else ":::".split(":")
  planPartNumber = param_list[2].split(":")[0] if len(param_list[2].split(":")[0]) > 0 else '[object%20Object]'
  campaignId = p_list[0]
  bundleId = p_list[1]
  promoCode = p_list[2]

  payload = {"planPartNumber": planPartNumber, "customerType": "BRN", "channel": "eshop"}
  if campaignId:
    payload["campaignId"] = campaignId
  if bundleId:
    payload["bundleId"] = bundleId
  if promoCode:
    payload["promoCode"] = promoCode

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def P06_payload(param_list, query_str_fl):
  p_list = (param_list[2]+"::::::::::").split(":")
  campaignId = p_list[0]
  bundleId = p_list[1]

  payload = {"customerType": "BRN", "channel": "eshop"}
  if campaignId:
    payload["campaignId"] = campaignId
  if bundleId:
    payload["bundleId"] = bundleId

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def P07_payload(param_list, query_str_fl):
  p_list = (param_list[2]+"::::::::::").split(":")

  payload = {"customerType": "BRN"}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def P08_payload(param_list, query_str_fl):
  type_ = param_list[2]
  customerType = "BRN"

  payload = {"type": type_, "customerType": customerType}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def D01_payload(param_list, query_str_fl):
  p_list = (param_list[1]+"::::::::::").split(":")
  campaignId = p_list[0]
  bundleId = p_list[1]
  offerType = p_list[2]
  planCategory = p_list[3]
  filterVariant = ','.join(p_list[4].split("%"))

  payload = {"customerType": "BRN", "quantity": "18", "page": "1", "defaulted": "true"}
  if campaignId:
    payload["campaignId"] = campaignId
  if bundleId:
    payload["bundleId"] = bundleId
  if offerType:
    payload["offerType"] = offerType
  if planCategory:
    payload["planCategory"] = planCategory
  if filterVariant:
    payload["filterVariant"] = filterVariant

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def D02_payload(param_list, query_str_fl):
  p_list = (param_list[0]+"::::::::::").split(":")
  campaignId = p_list[0]
  bundleId = p_list[1]

  payload = {"customerType": "BRN"}
  if campaignId:
    payload["campaignId"] = campaignId
  if bundleId:
    payload["bundleId"] = bundleId

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def D03_payload(param_list, query_str_fl):
  p_list = (param_list[1]+"::::::::::").split(":")
  campaignId = p_list[0]
  bundleId = p_list[1]
  offerType = p_list[2]
  planCategory = p_list[3]
  contractType = p_list[4]
  isRRP = True if p_list[5] == 'Y' else None

  payload = {"customerType": "BRN"}
  if campaignId:
    payload["campaignId"] = campaignId
  if bundleId:
    payload["bundleId"] = bundleId
  if offerType:
    payload["offerType"] = offerType
  if planCategory:
    payload["planCategory"] = planCategory
  if contractType:
    payload["contractType"] = contractType
  if isRRP:
    payload["isRRP"] = isRRP

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def D04_payload(param_list, query_str_fl):
  inv_list = param_list[0].split(':')
  inv_list = filter(None, inv_list)
  payload = {}
  if len(inv_list) > 0:
    payload = {"inventory":[]}
    for e in inv_list:
      payload["inventory"].append({"deviceStockCode":"{0}".format(e)})

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def J01_payload(param_list, query_str_fl):
  postalCode = param_list[0]

  payload = {"postalCode": postalCode}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def J02_payload(param_list, query_str_fl):
  postalCode = param_list[0]
  floorUnit = param_list[1]

  payload = {"postalCode": postalCode, "floorUnit": floorUnit}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def X00_login(tc_id, cxt, p_list, verbose, **kw):
  u_id, docNum = (p_list[0]+':').split(':')[:2]
  password = 'U3Rhcmh1YjEyM3xeX158U3Rhcmh1YjEyM3xeX158U3Rhcmh1YjEyM3xeX158U3Rhcmh1YjEyM3xeX158U3Rhcmh1YjEyMw%3D%3D'

  login_obj = login(u_id, password)
  ret = login_obj.eid_login()
  if ret is None:
    return None
  if len(docNum) == 0:
    docNum = ret.get('EID_BRN_LIST')[0]

  w_list = [u_id, ret.get('SM_SERVERSESSIONID')]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    token = common_func('X02', cxt, w_list, verbose=0)

  w_list = [docNum, token, 'BRN_SME']
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    common_func('X03', cxt, w_list, verbose=0)

  if verbose > 0:
    print('\neid brn list: {0}'.format(','.join(ret.get('EID_BRN_LIST'))))
    print('\nToken: {0}\n'.format(token))
  return token
  

def X01_esso_login(tc_id, cxt, p_list, verbose, **kw):
  u_id = p_list[0]
  password = 'U3Rhcmh1YjEyM3xeX158U3Rhcmh1YjEyM3xeX158U3Rhcmh1YjEyM3xeX158U3Rhcmh1YjEyM3xeX158U3Rhcmh1YjEyMw%3D%3D'

  login_obj = login(u_id, password)
  ret = login_obj.eid_login()
  if ret is None:
    return None

  if verbose > 0:
    print('\neid brn list: {0}'.format(','.join(ret.get('EID_BRN_LIST'))))
    print('\nsm_serversessionid: {0}\n'.format(ret.get('SM_SERVERSESSIONID')))
  return ret.get('SM_SERVERSESSIONID')


def X02_payload(param_list, query_str_fl):
  emailUserId = param_list[0]
  sessionId = param_list[1]
  payload = \
{
  "enterpriseLogin": {
    "appId": "smbonline",
    "appSecret": "smbonlineappsecret",
    "sessionId": sessionId,
    "emailUserId": emailUserId
  }
}
  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def X03_payload(param_list, query_str_fl):
  docNo = param_list[0]
  docType = param_list[2]

  payload = {"docNo": docNo, "docType": docType}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def X04_payload(param_list, query_str_fl):
  email = param_list[0]
  category = param_list[2]

  payload = {"email": email, "category": category}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def X05_payload(param_list, query_str_fl):
  ao = param_list[0]
  brn = param_list[2]

  payload = {"brnLogin": {"ao": ao, "brn": brn}}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def G02_payload(param_list, query_str_fl):
  simType = param_list[0]
  simCategory = param_list[1]
  quantity = param_list[2] if len(param_list) > 2 and len(param_list[2]) > 0 else "10"

  payload = {"simType": simType, "simCategory": simCategory, "quantity": quantity}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def G05_payload(param_list, query_str_fl):
  billingAccountNo = param_list[2] if len(param_list) > 2 and len(param_list[2]) > 0 else None
  
  payload = {}
  if billingAccountNo:
    payload["billingAccountNo"] = billingAccountNo

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def H01_payload(param_list, query_str_fl):
  addr = param_list[4]
  ba = param_list[5] if len(param_list) > 5 else ''
  if ba == '':
    payload = {"billingAddress":{"samAddressId":"{0}".format(addr)}}
  else:
    payload = {"billingAccountNo":"{0}".format(ba),"billingAddress":{"samAddressId":"{0}".format(addr)}}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def L02_payload(param_list, query_str_fl):
  id_list = param_list[2].split('^')
  slot_list = param_list[3].split('^')
  payload_list = []
  for i, id in enumerate(id_list):
    dt = slot_list[i].split('%')[0] + 'T00:00:00.000Z'
    start = (slot_list[i].split('%')[1].split('-')[0] + ':00')[:8]
    end = (slot_list[i].split('%')[1].split('-')[1] + ':00')[:8]
    slot = start + ' - ' + end
    payload = {
	"absappointDetail" : {  
		"type":"Delivery",
		"subscriptionId":"{0}".format(id),
		"absdetail":{
			"preferredDeliveryDate":"{0}".format(dt),
			"preferredDeliveryTime":"{0}".format(slot)
		}
	}
}
    payload_list.append(payload)

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def B01_payload(param_list, query_str_fl):
  '''
  get basket.
  '''
  id = param_list[2] if len(param_list) > 2 and param_list[2].isdigit() else None

  payload = {}
  if id:
    payload["id"] = id

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def B02_payload(param_list, query_str_fl):
  '''
  put various picks into basket.
  '''
  if os.path.isfile(param_list[3]):
    with open(param_list[3], 'r') as fh:
      payload = json.loads(fh.read())
  else:
    payload = json.loads(param_list[3])

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def B07_payload(param_list, query_str_fl):
  p_list = (param_list[2]+"::::::::::").split(":")
  id = p_list[0]
  name = p_list[1]
  phone = p_list[2]
  email = p_list[3]

  payload = {"groupAdmin": {}}
  if id:
    payload["groupAdmin"]["id"] = id
  else:
    payload["groupAdmin"]["name"] = name
    payload["groupAdmin"]["phone"] = phone
    payload["groupAdmin"]["email"] = email

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def B10_payload(param_list, query_str_fl):
  eid_email = param_list[0].split(":")[0]
  sm_user = eid_email
  utoken = param_list[1]
  basketid = param_list[2]

  payload = {"basketid": basketid, "utoken": utoken, "eid_email": eid_email, "sm_user": sm_user}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def B11_payload(param_list, query_str_fl):
  eid_email = param_list[0].split(":")[0]
  sm_user = eid_email
  utoken = param_list[1]
  basketid = param_list[2]

  payload = {"basketid": basketid, "utoken": utoken, "eid_email": eid_email, "sm_user": sm_user}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def B12_payload(param_list, query_str_fl):
  mainPickId = param_list[3]
  id = param_list[4]
  billDeliveryMethod = param_list[5] if len(param_list) > 5 and len(param_list[5]) > 0 else 'Electronic Invoice'

  payload = {"id": id, "mainPickId": mainPickId, "subscription": {"billingAccount": {"billDeliveryMethod": billDeliveryMethod, "billUpdateAction":"Modify"}}}

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def B13_payload(param_list, query_str_fl):
  if os.path.isfile(param_list[2]):
    with open(param_list[2], 'r') as fh:
      payload = json.loads(fh.read())
  else:
    payload = json.loads(param_list[2])

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def B15_payload(param_list, query_str_fl):
  '''
  put various picks into basket.
  '''
  if os.path.isfile(param_list[3]):
    with open(param_list[3], 'r') as fh:
      payload = json.loads(fh.read())
  else:
    payload = json.loads(param_list[3])

  if query_str_fl:
    return None, payload
  else:
    return json.dumps(payload), None


def B17_payload(param_list, query_str_fl):
  cartNum = param_list[3]
  payload = {
 "cartNumber": "{0}".format(cartNum), 
 "collectionInfo": {
                    "type": "delivery",
                    "deliveryAddress": {
                                        "addressId": "1-Q3ZZ7",
                                        "blockNo": "57",
                                        "street": "COMMONWEALTH%20DRIVE",
                                        "level": "01",
                                        "unit": "211",
                                        "postalCode": "140057"
                                       }},
 "paymentInfo": {"type": "cashOnDelivery", "paymentMethod": "Cash"}
}
  payload = json.dumps(payload)

  return payload, None


def M16_payload(param_list, query_str_fl):
  if param_list[-2] == '+i' and param_list[-1] != '':
    in_f = param_list[-1]
  elif param_list[-2] == '+b' and param_list[-1] != '':
    in_f = param_list[-1].split(':')[0]
  else:
    in_f = None

  if in_f:
    with open(in_f, 'r') as fh:
      exist_pick_lst = json.load(fh)
  else:
    exist_pick_lst = json.loads(param_list[2])
  payload = {}
  payload["pick"] = exist_pick_lst

  return payload, None



def get_svc_addr_info(context, postalCode, samAddressId, **kw):
  w_list = [postalCode]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('J01', context, w_list, verbose=0, req=kw.pop('req', None), A_P=kw.pop('A_P', None))
  if ret is None:
    return None
  svc_addr = None
  for i in ret:
    if i["samAddressId"] == samAddressId:
      svc_addr = remove_empty(i)
      break
  return svc_addr


def S04_func(tc_id, cxt, p_list, verbose, **kw):
  '''
  create a new Mobile order
  '''
  req = kw.pop('req', None)
  suppress = kw.get('suppress', False)
  prefix = kw.get('prefix', '')
  think_time = kw.get('think_time', 1)

  step = 0
  app_dt = (datetime.datetime.today() + datetime.timedelta(days=3)).strftime('%Y-%m-%d')

  context = cxt.copy()
  u_id, _brn = (p_list[0]+":").split(":")[:2]
  passwd = p_list[1]
  ba = p_list[2]
  campaignId, offerId = (p_list[3]+":").split(":")[:2]
  bundleId = p_list[4]
  plan_pn = p_list[5]
  vas_list_in = p_list[6].split(":")
  vas_list_in = filter(None, vas_list_in)
  msisdn, iccid, nth = (p_list[7]+"::").split(":")[:3]
  dev_stk_code = p_list[8] # device stock code e.g. EAPP0007301

  u_token = None
  if req is None:
    req = Comm_req(logger, get_end_point('A01'), proxies=PROXIES)
  if isToken(passwd):
    u_token = passwd
  else:
    # login
    step += 1
    augmented_print('\nStep {0}: login'.format(step), suppress=suppress)
    start = time.time()
    w_list = [':'.join([u_id, _brn]), passwd]
    u_token = X00_login(tc_id, context, w_list, verbose=0)
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if u_token is None:
      augmented_print('\nFail to login: eid: {0}; password: {1} -- at step: {2}'.format(u_id, passwd, step), suppress=suppress)
      if suppress:
        return
      else:
        exit()

  augmented_print('token: {0}'.format(u_token), suppress=suppress)


  # get billing account info
  step += 1
  augmented_print('\nStep {0}: get billing account info'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, ba]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    billing_acct = common_func('A02', context, w_list, verbose=0, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if billing_acct is None:
    augmented_print('\nFail to get billing account -- at step: {0}'.format(step), suppress=suppress)
    if suppress:
      return
    else:
      exit()
  billing_acct = fetch_ba(billing_acct, ba)

  # get commercial offers
  step += 1
  augmented_print('\nStep {0}: get commercial offers'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = False
  w_list = ['Mobile', bundleId]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    #commercialOffers = common_func('P03', context, w_list, verbose=False)
    commercialOffers = common_func('P03', context, w_list, verbose=False, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if commercialOffers is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- promotions/<prodType>/<bundleId> at step: {1}'.format('P03', step), suppress=suppress)
    if suppress:
      return
    else:
      exit()

  # get candidate vas list
  step += 1
  augmented_print('\nStep {0}: get list of VASes under given plan'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, plan_pn]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    #candidate_vas_list = common_func('P05', context, w_list, verbose=0)
    candidate_vas_list = common_func('P05', context, w_list, verbose=0, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if candidate_vas_list is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- products?planPartNumber={1} at step: {2}'.format('P05', step), plan_pn, suppress=suppress)
    if suppress:
      return
    else:
      exit()

  # get MSISDN from pool
  if len(msisdn) == 0:
    # get Mobile resource
    step += 1
    augmented_print('\nStep {0}: get Mobile resource'.format(step), suppress=suppress)
    start = time.time()
    context['u_flag'] = False
    p_list = ["3G TriSIM Card", "voice", "1"]
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      res = common_func('G02', context, p_list, verbose=0, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if res is None or len(res) == 0:
      augmented_print('\nFail to get Mobile resource -- at step: {0}'.format(step), suppress=suppress)
      if suppress:
        return
      else:
        exit()
    msisdn = res[0]["msisdnInfo"]["number"]
    iccid = res[0]["msisdnInfo"]["iccid"]
    simType = res[0]["msisdnInfo"]["simtype"]
  else:
    msisdn = msisdn[-8:]
    simType = '3G TriSIM Card'

  #################### start of testing zone
#  devPick = newDevicePickPayload(context, '12345', dev_stk_code, commercialOffers, campaignId=campaignId, bundleId=bundleId, offerId=offerId, plan_pn=plan_pn, isRRP='N')
#  payload = collectInfoPayload(billing_acct["billingAddress"], '2020-08-23', '14:00:00 - 17:30:00', 'delivery', email=u_id)
#  vasPick = vasPickPayload('12345', commercialOffers, vas_list=candidate_vas_list, vas_pn='MOBL-10543')
#  planPick = newPlanPickPayload(context, '1234', commercialOffers, plan_pn=plan_pn)
#  subsPick = newSubsPickPayload('12345', billing_acct, plan_pn=plan_pn, mos="5G")
#  promoPick = newPromoPickPayload(commercialOffers, offerId)
#  augmented_print(json.dumps(devPick, sort_keys=True, indent=2, separators=(',', ':')))
#  exit()
  ################### end of testing zone

  #================================promo pick================================
  step += 1
  augmented_print('\nStep {0}: prepare promo pick.'.format(step), suppress=suppress)
  promoPick = newPromoPickPayload(commercialOffers, offerId)
  # submit promo pick
  step += 1
  time.sleep(think_time)
  augmented_print('\nStep {0}: put promo pick.'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, 'promo', json.dumps(promoPick)]
  #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- while put promo pick at step: {1}'.format('B02', step), suppress=suppress)
    if suppress:
      logger.error("S04 put promo pick(B02) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  promoPickId = ret.get("id")
  augmented_print('promoPickId: {0}\n'.format(promoPickId), suppress=suppress)

  #================================subs pick=================================
  step += 1
  subsPick = newSubsPickPayload(promoPickId, billing_acct, plan_pn=plan_pn, mos="5G")
  # submit subscription pick
  step += 1
  time.sleep(think_time)
  augmented_print('\nStep {0}: put subscription picks.'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, 'subscription', json.dumps(subsPick)]
  #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- while put subscription pick at step: {1}'.format('B02', step), suppress=suppress)
    if suppress:
      logger.error("S04 put subs pick(B02) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  subsPickId = ret.get("id")
  augmented_print('subsPickId: {0}\n'.format(subsPickId), suppress=suppress)

  #================================plan pick=================================
  step += 1
  planPick = newPlanPickPayload(context, subsPickId, commercialOffers, plan_pn=plan_pn, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  # submit plan pick
  step += 1
  time.sleep(think_time)
  augmented_print('\nStep {0}: put plan pick.'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, 'product', json.dumps(planPick)]
  #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- while put plan pick at step: {1}'.format('B02', step), suppress=suppress)
    if suppress:
      logger.error("S04 put plan pick(B02) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  planPickId = ret.get("id")
  augmented_print('planPickId: {0}\n'.format(planPickId), suppress=suppress)

  #================================device pick=================================
  if len(dev_stk_code) > 0:
    step += 1
    devPick = newDevicePickPayload(context, subsPickId, dev_stk_code, commercialOffers, req=req, campaignId=campaignId, bundleId=bundleId, offerId=offerId, plan_pn=plan_pn)
    # submit device pick
    step += 1
    time.sleep(think_time)
    augmented_print('\nStep {0}: put device pick.'.format(step), suppress=suppress)
    start = time.time()
    context['u_flag'] = True
    w_list = [u_id, u_token, 'device', json.dumps(devPick)]
    #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if ret is None:
      augmented_print('\nBusiness flow failed at TC: {0} -- while put device pick at step: {1}'.format('B02', step), suppress=suppress)
      if suppress:
        logger.error("S04 put device pick(B02) Failed. Input: {0}".format(w_list))
        return
      else:
        exit()
    devicePickId = ret.get("id")
    augmented_print('devicePickId: {0}\n'.format(devicePickId), suppress=suppress)

  #================================VAS pick=================================
  for vas in vas_list_in:
    step += 1
    vasPick = vasPickPayload(subsPickId, commercialOffers, vas_list=candidate_vas_list, vas_pn=vas)
    # submit vas pick
    step += 1
    time.sleep(think_time)
    augmented_print('\nStep {0}: put vas pick.'.format(step), suppress=suppress)
    start = time.time()
    context['u_flag'] = True
    w_list = [u_id, u_token, 'product', json.dumps(vasPick)]
    #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if ret is None:
      augmented_print('\nBusiness flow failed at TC: {0} -- while put vas pick at step: {1}'.format('B02', step), suppress=suppress)
      if suppress:
        logger.error("S04 put vas pick(B02) Failed. Input: {0}".format(w_list))
        return
      else:
        exit()
    vasPickId = ret.get("id")
    augmented_print('vasPickId: {0}\n'.format(vasPickId), suppress=suppress)
  
  #================================Mobile resource picks=================================
  step += 1
  augmented_print('\nStep {0}: prepare Mobile resource pick.'.format(step), suppress=suppress)
  resPick = resPickPayload(subsPickId, res_type='Mobile', msisdn=msisdn, iccid=iccid, simType=simType, simCat='Voice')
  # submit resource pick
  step += 1
  time.sleep(think_time)
  augmented_print('\nStep {0}: put resource pick.'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, 'resource', json.dumps(resPick)]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- while put Mobile resource pick at step: {1}'.format('B02', step), suppress=suppress)
    if suppress:
      logger.error("S04 put resource pick(B02) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  resPickId = ret.get("id")
  augmented_print('resPickId: {0}\n'.format(resPickId), suppress=suppress)

  #================================get basket=================================
  step += 1
  augmented_print('\nStep {0}: get basket.'.format(step), suppress=suppress)
  time.sleep(think_time)
  start = time.time()
  context['u_flag'] = True
  w_list = ['NA', u_token]
  #ret = common_func('B01', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B01', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- basket at step: {1}'.format('B01', step), suppress=suppress)
    if suppress:
      logger.error("S04 basket(B01) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  basketId = ret.get("id")
  cartNum = ret.get("cartNumber")
  augmented_print('basketId: {0}; cartNum: {1}\n'.format(basketId, cartNum), suppress=suppress)

  #================================basket/totals=================================
  step += 1
  augmented_print('\nStep {0}: check basket/totals.'.format(step), suppress=suppress)
  time.sleep(think_time)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, basketId]
  #ret = common_func('B06', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B06', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- basket/totals at step: {1}'.format('B06', step), suppress=suppress)
    if suppress:
      logger.error("S04 basket/totals (B06) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  netPayNow = ret["basketTotals"]["nettPayNow"]
  nettRecurring = ret["basketTotals"]["nettRecurring"]
  augmented_print('basketTotal -- netPayNow: {0}; nettRecurring: {1}\n'.format(netPayNow, nettRecurring), suppress=suppress)

  #================================check subscription eligibility=================================
  step += 1
  augmented_print('\nStep {0}: check subscription eligibility.'.format(step), suppress=suppress)
  time.sleep(think_time)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, subsPickId]
  #ret = common_func('B14', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B14', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} basket/pick/subscription/eligibility at step: {1}'.format('B14', step), suppress=suppress)
    if suppress:
      logger.error("S04 basket/pick/subscription/eligibility (B14) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  pick_dict = {}
  eligible = True
  for r in ret["bdmsrequest"]:
    pick_dict[r["referenceNumber"]] = r["bdmsresponse"]["eligible"]
    if not r["bdmsresponse"]["eligible"]:
      eligible = False
  for k, v in pick_dict.items():
    augmented_print('referenceNum: {0}; eligible: {1}'.format(k, v), suppress=suppress)
  if not eligible:
    augmented_print('\nBusiness flow failed at TC: {0} -- basket/pick/subscription/eligibility step: {1}'.format('B14', step), suppress=suppress)
    if suppress:
      logger.error("S04 basket/pick/subscription/eligibility (B14) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()

  #================================check appointment slots=================================
  step += 1
  augmented_print('\nStep {0}: check appointment slots.'.format(step), suppress=suppress)
  time.sleep(think_time)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, app_dt, 'Mobile']
  #ret = common_func('L01', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('L01', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None or len(ret) == 0:
    augmented_print('\nBusiness flow failed at TC: {0} brnppointments/{date}?root=Mobile at step: {1}'.format('L01', step), suppress=suppress)
    if suppress:
      logger.error("S04 brnppointments/{date}?root=Mobile (L01) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  app_dt = slot_start = ret["appointmentSlots"][0]["slotStartDateTime"].split('T')[0]
  slot_start = ret["appointmentSlots"][0]["slotStartDateTime"].split('T')[1].split('.')[0]
  slot_end = ret["appointmentSlots"][0]["slotEndDateTime"].split('T')[1].split('.')[0]
  augmented_print('appointmentDate: {0}; slot: {1} - {2}.\n'.format(app_dt, slot_start, slot_end), suppress=suppress)

  #================================confirm appointment date=================================
  step += 1
  augmented_print('\nStep {0}: confirm appointment date.'.format(step), suppress=suppress)
  time.sleep(think_time)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, subsPickId, '%'.join([app_dt, '-'.join([slot_start, slot_end])])]
  #ret = common_func('L02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('L02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None or len(ret) == 0:
    augmented_print('\nBusiness flow failed at TC: {0} brnappointments(POST) at step: {1}'.format('L01', step), suppress=suppress)
    if suppress:
      logger.error("S04 brnppointments(POST) (L02) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  moliRefNo = ret[0]["absappointDetail"]["absdetail"]["moliRefNo"]
  augmented_print('moliRefNo: {0}.\n'.format(moliRefNo), suppress=suppress)

  #================================update billdeliverymethod=================================
  step += 1
  augmented_print('\nStep {0}: update billdeliverymethod.'.format(step), suppress=suppress)
  time.sleep(think_time)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, basketId, promoPickId, subsPickId, "Electronic Invoice"]
  #ret = common_func('B12', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B12', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} billdeliverymethod/{basketId} at step: {1}'.format('B12', step), suppress=suppress)
    if suppress:
      logger.error("S04 billdeliverymethod/{basketId} (B12) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()

  #================================update collectionInfo into basket=================================
  step += 1
  augmented_print('\nStep {0}: update collectionInfo into basket.'.format(step), suppress=suppress)
  collectInfo = collectInfoPayload(billing_acct["billingAddress"], app_dt, ' - '.join([slot_start, slot_end]), 'delivery', email=u_id)
  time.sleep(think_time)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, json.dumps(collectInfo)]
  #ret = common_func('B13', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B13', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} update collectionInfo at step: {1}'.format('B13', step), suppress=suppress)
    if suppress:
      logger.error("S04 update collectionInfo (B13) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  updateStatus = ret
  augmented_print('updateStatus: {0}.\n'.format(updateStatus), suppress=suppress)

  #================================basket/eligibility=================================
  step += 1
  augmented_print('\nStep {0}: basket/eligibility.'.format(step), suppress=suppress)
  time.sleep(think_time)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token]
  #ret = common_func('B03', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B03', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None or ret.get("basketStatus") == "Invalid":
    augmented_print('\nBusiness flow failed at TC: {0} basket/eligibility at step: {1}'.format('B03', step), suppress=suppress)
    if suppress:
      logger.error("S04 basket/eligibility (B03) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  basketStatus = ret["basketStatus"]
  augmented_print('basketStatus: {0}.\n'.format(basketStatus), suppress=suppress)

  #================================check basket status=================================
  step += 1
  augmented_print('\nStep {0}: check basket status.'.format(step), suppress=suppress)
  time.sleep(think_time)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, basketId]
  #ret = common_func('B05', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B05', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None or ret == "INVALID":
    augmented_print('\nBusiness flow failed at TC: {0} -- basket/status at step: {1}'.format('B05', step), suppress=suppress)
    if suppress:
      logger.error("S04 basket/status (B05) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  basketSta = ret
  augmented_print('basketStatus: {0}\n'.format(basketSta), suppress=suppress)

  #================================contractdocs/{basketId}/scannedFiles=================================
  step += 1
  augmented_print('\nStep {0}: contractdocs/{1}/scannedFiles.'.format(step, basketId), suppress=suppress)
  time.sleep(think_time)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, basketId]
  #ret = common_func('B09', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B09', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} contractdocs/{1}/scannedFiles at step: {2}'.format('B09', basketId, step), suppress=suppress)
    if suppress:
      logger.error("S04 contractdocs/{0}/scannedFiles (B09) Failed. Input: {1}".format(basketId, w_list))
      return
    else:
      exit()
  refId = ret["contractDoc"][0]["refId"]
  augmented_print('refId: {0}.\n'.format(refId), suppress=suppress)

  #augmented_print(json.dumps(ret, sort_keys=True, indent=2, separators=(',', ':')))
  augmented_print('\nEnd here. Token: {0}\n'.format(u_token), suppress=suppress)

###############################################end of S04_func


def S05_func(tc_id, cxt, p_list, verbose, **kw):
  '''
  create a new Broadband order
  input params:
  1)  eid
  2)  token
  3)  billing account
  4)  campaignId:offerId
  5)  bundleId
  6)  planPartNum
  7)  suppInfo
  8)  VASes, delimited by ":"
  9)  zipCode:samAddrId
  10)  deviceStockCode
  11) submitFlag
  e.g. smb_os_sim.py -e UAT -s S05 edtf00001@mailinator.com 7664f3ba90e4ee858fd183370a18fa200bdbb202 8.20016885 CMPG-S00561:116857 BNDL-B00323 NGN-EBS08997_350M_36MTH NGN-EBS99005 609479:AA00458453 NGN-EBS800069
  '''
  req = kw.pop('req', None)
  suppress = kw.get('suppress', False)
  prefix = kw.get('prefix', '')
  think_time = kw.get('think_time', 1)

  step = 0
  app_dt = (datetime.datetime.today() + datetime.timedelta(days=3)).strftime('%Y-%m-%d')

  context = cxt.copy()
  u_id, _brn = (p_list[0]+":").split(":")[:2]
  passwd = p_list[1]
  ba = p_list[2]
  campaignId, offerId = (p_list[3]+":").split(":")[:2]
  bundleId = p_list[4]
  plan_pn = p_list[5]
  suppInfo = p_list[6]
  vas_list_in = p_list[7].split(":")
  vas_list_in = filter(None, vas_list_in)
  postalCode, samAddressId = (p_list[8]+":").split(":")[:2]
  dev_stk_code = p_list[9]

  u_token = None
  if req is None:
    req = Comm_req(logger, get_end_point('A01'), proxies=PROXIES)
  if isToken(passwd):
    u_token = passwd
  else:
    # login
    step += 1
    augmented_print('\nStep {0}: login'.format(step), suppress=suppress)
    start = time.time()
    w_list = [':'.join([u_id, _brn]), passwd]
    u_token = X00_login(tc_id, context, w_list, verbose=0)
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if u_token is None:
      augmented_print('\nFail to login: eid: {0}; password: {1} -- at step: {2}'.format(u_id, passwd, step), suppress=suppress)
      if suppress:
        return
      else:
        exit()

  augmented_print('token: {0}'.format(u_token), suppress=suppress)


  # get billing account info
  step += 1
  augmented_print('\nStep {0}: get billing account info'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, ba]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    billing_acct = common_func('A02', context, w_list, verbose=0, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if billing_acct is None:
    augmented_print('\nFail to get billing account -- at step: {0}'.format(step), suppress=suppress)
    if suppress:
      return
    else:
      exit()
  billing_acct = fetch_ba(billing_acct, ba)

  # get commercial offers
  step += 1
  augmented_print('\nStep {0}: get commercial offers'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = False
  w_list = ['Broadband', bundleId, suppInfo]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    #commercialOffers = common_func('P03', context, w_list, verbose=False)
    commercialOffers = common_func('P03', context, w_list, verbose=False, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if commercialOffers is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- promotions/<prodType>/<bundleId> at step: {1}'.format('L13', step), suppress=suppress)
    if suppress:
      return
    else:
      exit()

  # get candidate vas list
  step += 1
  augmented_print('\nStep {0}: get list of VASes under given plan'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, plan_pn]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    #candidate_vas_list = common_func('P05', context, w_list, verbose=0)
    candidate_vas_list = common_func('P05', context, w_list, verbose=0, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if candidate_vas_list is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- products?planPartNumber={1} at step: {2}'.format('P05', step), plan_pn, suppress=suppress)
    if suppress:
      return
    else:
      exit()

  # get service address info.
  step += 1
  augmented_print('\nStep {0}: get service address info'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = False
  svc_addr_info = get_svc_addr_info(context, postalCode, samAddressId, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if svc_addr_info is None:
    augmented_print('\nBusiness flow failed address at TC: {0} --  at step: {1}'.format('J01', step), suppress=suppress)
    if suppress:
      return
    else:
      exit()

#  # check service address coverage.
#  step += 1
#  augmented_print('\nStep {0}: check address/coverage'.format(step), suppress=suppress)
#  start = time.time()
#  context['u_flag'] = False
#  w_list = [postalCode, svc_addr_info["floor"]]
#  with RedirectStdStreams(stdout=devnull, stderr=devnull):
#    ret = common_func('J02', context, w_list, verbose=0, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
#  end = time.time()
#  dur = '{0:.3f}'.format(end-start)
#  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
#  if ret is None or not ret["eligible"]:
#    augmented_print('\nBusiness flow failed address/coveragecheck at TC: {0} --  at step: {1}'.format('J02', step), suppress=suppress)
#    if suppress:
#      return
#    else:
#      exit()


  #################### start of testing zone
#  devPick = newDevicePickPayload(context, '12345', dev_stk_code, commercialOffers, req=req, campaignId=campaignId, bundleId=bundleId, offerId=offerId, plan_pn=plan_pn)
#  planPick = newPlanPickPayload(context, '12345', commercialOffers, plan_pn=plan_pn, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]), campaignId=campaignId, bundleId=bundleId)
#  subsPick = newSubsPickPayload('12345', billing_acct, plan_pn=plan_pn, svc_addr=svc_addr_info, mos='Normal')
#  promoPick = newPromoPickPayload(commercialOffers, offerId)
#  augmented_print(json.dumps(devPick, sort_keys=True, indent=2, separators=(',', ':')))
#  exit()
  ################### end of testing zone

  #================================promo pick================================
  step += 1
  augmented_print('\nStep {0}: prepare promo pick.'.format(step), suppress=suppress)
  promoPick = newPromoPickPayload(commercialOffers, offerId)
  # submit promo pick
  step += 1
  time.sleep(think_time)
  augmented_print('\nStep {0}: put promo pick.'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, 'promo', json.dumps(promoPick)]
  #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- while put promo pick at step: {1}'.format('B02', step), suppress=suppress)
    if suppress:
      logger.error("S04 put promo pick(B02) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  promoPickId = ret.get("id")
  augmented_print('promoPickId: {0}\n'.format(promoPickId), suppress=suppress)

  #================================subs pick=================================
  step += 1
  subsPick = newSubsPickPayload(promoPickId, billing_acct, plan_pn=plan_pn, svc_addr=svc_addr_info, mos='Normal')
  # submit subscription pick
  step += 1
  time.sleep(think_time)
  augmented_print('\nStep {0}: put subscription picks.'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, 'subscription', json.dumps(subsPick)]
  #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- while put subscription pick at step: {1}'.format('B02', step), suppress=suppress)
    if suppress:
      logger.error("S04 put subs pick(B02) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  subsPickId = ret.get("id")
  augmented_print('subsPickId: {0}\n'.format(subsPickId), suppress=suppress)

  #================================plan pick=================================
  step += 1
  planPick = newPlanPickPayload(context, subsPickId, commercialOffers, plan_pn=plan_pn, campaignId=campaignId, bundleId=bundleId, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  # submit plan pick
  step += 1
  time.sleep(think_time)
  augmented_print('\nStep {0}: put plan pick.'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, 'product', json.dumps(planPick)]
  #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- while put plan pick at step: {1}'.format('B02', step), suppress=suppress)
    if suppress:
      logger.error("S04 put plan pick(B02) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  planPickId = ret.get("id")
  augmented_print('planPickId: {0}\n'.format(planPickId), suppress=suppress)

  #================================device pick=================================
  if len(dev_stk_code) > 0:
    step += 1
    devPick = newDevicePickPayload(context, subsPickId, dev_stk_code, commercialOffers, req=req, campaignId=campaignId, bundleId=bundleId, offerId=offerId, plan_pn=plan_pn)
    # submit device pick
    step += 1
    time.sleep(think_time)
    augmented_print('\nStep {0}: put device pick.'.format(step), suppress=suppress)
    start = time.time()
    context['u_flag'] = True
    w_list = [u_id, u_token, 'device', json.dumps(devPick)]
    #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if ret is None:
      augmented_print('\nBusiness flow failed at TC: {0} -- while put device pick at step: {1}'.format('B02', step), suppress=suppress)
      if suppress:
        logger.error("S04 put device pick(B02) Failed. Input: {0}".format(w_list))
        return
      else:
        exit()
    devicePickId = ret.get("id")
    augmented_print('devicePickId: {0}\n'.format(devicePickId), suppress=suppress)

  #================================VAS pick=================================
  for vas in vas_list_in:
    step += 1
    vasPick = vasPickPayload(subsPickId, commercialOffers, vas_list=candidate_vas_list, vas_pn=vas)
    # submit vas pick
    step += 1
    time.sleep(think_time)
    augmented_print('\nStep {0}: put vas pick.'.format(step), suppress=suppress)
    start = time.time()
    context['u_flag'] = True
    w_list = [u_id, u_token, 'product', json.dumps(vasPick)]
    #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if ret is None:
      augmented_print('\nBusiness flow failed at TC: {0} -- while put vas pick at step: {1}'.format('B02', step), suppress=suppress)
      if suppress:
        logger.error("S04 put vas pick(B02) Failed. Input: {0}".format(w_list))
        return
      else:
        exit()
    vasPickId = ret.get("id")
    augmented_print('vasPickId: {0}\n'.format(vasPickId), suppress=suppress)
  

  #augmented_print(json.dumps(ret, sort_keys=True, indent=2, separators=(',', ':')))
  augmented_print('\nEnd here. Token: {0}\n'.format(u_token), suppress=suppress)

###############################################end of S05_func


def S06_func(tc_id, cxt, p_list, verbose, **kw):
  '''
  create a new SmartUC order
  input params:
  1)  eid
  2)  token
  3)  billing account or billing addr. If billing addr, s new billing account will be created, and ervice will be provisioned under new billing account.
  4)  campaignId:offerId
  5)  bundleId
  6)  planPartNum
  7)  VASes, delimited by ":"
  8)  msisdn
  9)  deviceStockCode
  10) ucGrpName: used to create when uc group doesn't exist.
  11) submitFlag
  e.g. smb_os_sim.py -e UAT -s S05 edtf00001@mailinator.com token 8.20016885 CMPG-S00515:110479 BNDL-S00026 UC-EBS12044 : :
  '''
  req = kw.pop('req', None)
  suppress = kw.get('suppress', False)
  prefix = kw.get('prefix', '')
  think_time = kw.get('think_time', 1)

  step = 0
  app_dt = (datetime.datetime.today() + datetime.timedelta(days=3)).strftime('%Y-%m-%d')

  context = cxt.copy()
  u_id, _brn = (p_list[0]+":").split(":")[:2]
  passwd = p_list[1]
  ba = p_list[2]
  if re.match(r'^\d\.\d+$', p_list[2]):
    ba = p_list[2]
  else:
    ba = None
    postalCode, samAddrId = p_list[2].split(':')[:2]
  campaignId, offerId = (p_list[3]+":").split(":")[:2]
  bundleId = p_list[4]
  plan_pn = p_list[5]
  vas_list_in = p_list[6].split(":")
  vas_list_in = filter(None, vas_list_in)
  msisdn = p_list[7]
  if len(p_list[7]) < 3 and p_list[7].isdigit():
    num_lines = int(p_list[7])
    msisdn_list = []
  else:
    msisdn_list = p_list[7].split(":")
    msisdn_list = filter(None, msisdn_list)
    num_lines = len(msisdn_list)
  dev_stk_code = p_list[8] if len(p_list) > 8 else None
  ucGrpName = p_list[9].split(':')[0] if len(p_list) > 9 else None
  submitFlag = True if len(p_list) > 10 and p_list[10] == 'Y' else False

  u_token = None
  if req is None:
    req = Comm_req(logger, get_end_point('A01'), proxies=PROXIES)
  if isToken(passwd):
    u_token = passwd
  else:
    # login
    step += 1
    augmented_print('\nStep {0}: login'.format(step), suppress=suppress)
    start = time.time()
    w_list = [':'.join([u_id, _brn]), passwd]
    u_token = X00_login(tc_id, context, w_list, verbose=0)
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if u_token is None:
      augmented_print('\nFail to login: eid: {0}; password: {1} -- at step: {2}'.format(u_id, passwd, step), suppress=suppress)
      if suppress:
        return
      else:
        exit()

  augmented_print('token: {0}'.format(u_token), suppress=suppress)

  # get customer info
  step += 1
  augmented_print('\nStep {0}: get customer info'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    cus_info = common_func('A01', context, w_list, verbose=0, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if cus_info is None:
    augmented_print('\nFail to get customer info -- at step: {0}'.format(step), suppress=suppress)
    if suppress:
      return
    else:
      exit()
  docNum = cus_info.get("docNo")
  

#  # below authtoken section has been commented, due to it is redundent, login API(X00) has included authtoken.
#  # authtoken
#  step += 1
#  augmented_print('\nStep {0}: authtoken'.format(step), suppress=suppress)
#  start = time.time()
#  context['u_flag'] = True
#  w_list = [docNum, u_token, 'BRN_SME']
#  with RedirectStdStreams(stdout=devnull, stderr=devnull):
#    common_func('X03', context, w_list, verbose=0, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
#  end = time.time()
#  dur = '{0:.3f}'.format(end-start)
#  augmented_print('Duration: {0}'.format(dur), suppress=suppress)

  # get UC group info
  step += 1
  augmented_print('\nStep {0}: get UC group info'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [':'.join([u_id, docNum]), u_token, 'BRN_SME']
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ucGrp_info = common_func('A08', context, w_list, verbose=0, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ucGrp_info is None:
    augmented_print('\nFail to get UC group info -- at step: {0}'.format(step), suppress=suppress)
    if suppress:
      return
    else:
      exit()
  ucGrpId = ucGrp_info.get("ucgroupInfo", {}).get("ucgroupID")
  if ucGrpId is None and len(ucGrpName) == 0:
    augmented_print('\nUC group name is missing. -- at step: {0}'.format(step), suppress=suppress)
    if suppress:
      return
    else:
      exit()

  if ba:
    # get billing account info
    step += 1
    augmented_print('\nStep {0}: get billing account info'.format(step), suppress=suppress)
    start = time.time()
    context['u_flag'] = True
    w_list = [u_id, u_token, ba]
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      billing_acct = common_func('A02', context, w_list, verbose=0, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if billing_acct is None:
      augmented_print('\nFail to get billing account -- at step: {0}'.format(step), suppress=suppress)
      if suppress:
        return
      else:
        exit()
    billing_acct = fetch_ba(billing_acct, ba)
    addr_info = None
  else:
    # get address by postalCode and samAddrId
    step += 1
    augmented_print('\nStep {0}: get address info'.format(step), suppress=suppress)
    start = time.time()
    context['u_flag'] = False
    w_list = [postalCode]
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      ret = common_func('J01', context, w_list, verbose=0, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if ret is None:
      augmented_print('\nFail to get addresses -- at step: {0}'.format(step), suppress=suppress)
      if suppress:
        return
      else:
        exit()
    for i in ret:
      if i.get("samAddressId") == samAddrId:
        addr_info = i
        break
    bill_deliMtd = "Electronic Invoice"
    billing_acct = None

  # get commercial offers
  step += 1
  augmented_print('\nStep {0}: get commercial offers'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = False
  w_list = ['SmartUC', bundleId]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    commercialOffers = common_func('P03', context, w_list, verbose=False, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if commercialOffers is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- promotions/<prodType>/<bundleId> at step: {1}'.format('L13', step), suppress=suppress)
    if suppress:
      return
    else:
      exit()

  # get candidate vas list
  step += 1
  augmented_print('\nStep {0}: get list of VASes under given plan'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, plan_pn, ':'.join([campaignId, bundleId])]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    candidate_vas_list = common_func('P05', context, w_list, verbose=0, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if candidate_vas_list is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- products?planPartNumber={1} at step: {2}'.format('P05', step), plan_pn, suppress=suppress)
    if suppress:
      return
    else:
      exit()

  # get additional candidate vas list
  step += 1
  augmented_print('\nStep {0}: get list of VASes under given plan'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, '', ':'.join([campaignId, bundleId])]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    addi_candidate_vas_list = common_func('P05', context, w_list, verbose=0, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if candidate_vas_list is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- products?planPartNumber={1} at step: {2}'.format('P05', step), plan_pn, suppress=suppress)
    if suppress:
      return
    else:
      exit()

  # get number resource from pool
  if len(msisdn_list) == 0:
    # get number resource
    step += 1
    augmented_print('\nStep {0}: get number resource'.format(step), suppress=suppress)
    start = time.time()
    context['u_flag'] = False
    p_list = [':'.join([u_id, '', '', str(num_lines)])]
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      res = common_func('A09', context, p_list, verbose=0, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if res is None or len(res[0]["resourceInfoList"]) == 0:
      augmented_print('\nFail to get number resource -- at step: {0}'.format(step), suppress=suppress)
      if suppress:
        return
      else:
        exit()
    for i in res[0]["resourceInfoList"]:
      msisdn_list.append(i["number"])

  #################### start of testing zone
#  vasPick = vasPickPayload('12345', commercialOffers, vas_list=candidate_vas_list, addi_vas_list=addi_candidate_vas_list, vas_pn='MOBL-10043')
#  augmented_print(json.dumps(vasPick, sort_keys=True, indent=2, separators=(',', ':')))
#  exit()
  ################### end of testing zone

  first_time = True
  for j, msisdn in enumerate(msisdn_list):
    sd_num = msisdn[-4:]
    augmented_print('\nPreparing number {0} contract.'.format(j+1), suppress=suppress)

    #================================promo pick================================
    step += 1
    augmented_print('\nStep {0}: prepare promo pick.'.format(step), suppress=suppress)
    promoPick = newPromoPickPayload(commercialOffers, offerId, device_offer=True)
    # submit promo pick
    step += 1
    time.sleep(think_time)
    augmented_print('\nStep {0}: put promo pick.'.format(step), suppress=suppress)
    start = time.time()
    context['u_flag'] = True
    w_list = [u_id, u_token, 'promo', json.dumps(promoPick)]
    #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if ret is None:
      augmented_print('\nBusiness flow failed at TC: {0} -- while put promo pick at step: {1}'.format('B02', step), suppress=suppress)
      if suppress:
        logger.error("S04 put promo pick(B02) Failed. Input: {0}".format(w_list))
        return
      else:
        exit()
    promoPickId = ret.get("id")
    augmented_print('promoPickId: {0}\n'.format(promoPickId), suppress=suppress)
  
    #================================subs pick=================================
    step += 1
    subsPick = newSubsPickPayload(promoPickId, billing_acct, plan_pn=plan_pn, mos="Normal", sd_num=sd_num, bill_addr=addr_info, bill_deliMth=bill_deliMtd)
    # submit subscription pick
    step += 1
    time.sleep(think_time)
    augmented_print('\nStep {0}: put subscription picks.'.format(step), suppress=suppress)
    start = time.time()
    context['u_flag'] = True
    w_list = [u_id, u_token, 'subscription', json.dumps(subsPick)]
    #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if ret is None:
      augmented_print('\nBusiness flow failed at TC: {0} -- while put subscription pick at step: {1}'.format('B02', step), suppress=suppress)
      if suppress:
        logger.error("S04 put subs pick(B02) Failed. Input: {0}".format(w_list))
        return
      else:
        exit()
    subsPickId = ret.get("id")
    augmented_print('subsPickId: {0}\n'.format(subsPickId), suppress=suppress)
  
    #================================plan pick=================================
    step += 1
    planPick = newPlanPickPayload(context, subsPickId, commercialOffers, plan_pn=plan_pn, campaignId=campaignId, bundleId=bundleId, req=req, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    # submit plan pick
    step += 1
    time.sleep(think_time)
    augmented_print('\nStep {0}: put plan pick.'.format(step), suppress=suppress)
    start = time.time()
    context['u_flag'] = True
    w_list = [u_id, u_token, 'product', json.dumps(planPick)]
    #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if ret is None:
      augmented_print('\nBusiness flow failed at TC: {0} -- while put plan pick at step: {1}'.format('B02', step), suppress=suppress)
      if suppress:
        logger.error("S04 put plan pick(B02) Failed. Input: {0}".format(w_list))
        return
      else:
        exit()
    planPickId = ret.get("id")
    augmented_print('planPickId: {0}\n'.format(planPickId), suppress=suppress)
  
    #================================number resource pick=================================
    step += 1
    augmented_print('\nStep {0}: prepare number resource pick.'.format(step), suppress=suppress)
    resPick = resPickPayload(subsPickId, res_type='SmartUC', msisdn=msisdn)
    # submit resource pick
    step += 1
    time.sleep(think_time)
    augmented_print('\nStep {0}: put resource pick.'.format(step), suppress=suppress)
    start = time.time()
    context['u_flag'] = True
    w_list = [u_id, u_token, 'resource', json.dumps(resPick)]
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if ret is None:
      augmented_print('\nBusiness flow failed at TC: {0} -- while put resource pick at step: {1}'.format('B02', step), suppress=suppress)
      if suppress:
        logger.error("S06 put resource pick(B02) Failed. Input: {0}".format(w_list))
        return
      else:
        exit()
    resPickId = ret.get("id")
    augmented_print('resPickId: {0}\n'.format(resPickId), suppress=suppress)

    #================================device pick=================================
    if len(dev_stk_code) > 0:
      step += 1
      devPick = newDevicePickPayload(context, subsPickId, dev_stk_code, commercialOffers, req=req, campaignId=campaignId, bundleId=bundleId, offerId=offerId, plan_pn=plan_pn)
      # submit device pick
      step += 1
      time.sleep(think_time)
      augmented_print('\nStep {0}: put device pick.'.format(step), suppress=suppress)
      start = time.time()
      context['u_flag'] = True
      w_list = [u_id, u_token, 'device', json.dumps(devPick)]
      #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
      with RedirectStdStreams(stdout=devnull, stderr=devnull):
        ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
      end = time.time()
      dur = '{0:.3f}'.format(end-start)
      augmented_print('Duration: {0}'.format(dur), suppress=suppress)
      if ret is None:
        augmented_print('\nBusiness flow failed at TC: {0} -- while put device pick at step: {1}'.format('B02', step), suppress=suppress)
        if suppress:
          logger.error("S04 put device pick(B02) Failed. Input: {0}".format(w_list))
          return
        else:
          exit()
      devicePickId = ret.get("id")
      augmented_print('devicePickId: {0}\n'.format(devicePickId), suppress=suppress)
  
    #================================VAS pick=================================
    for vas in vas_list_in:
      step += 1
      vasPick = vasPickPayload(subsPickId, commercialOffers, vas_list=candidate_vas_list, addi_vas_list=addi_candidate_vas_list, vas_pn=vas)
      # submit vas pick
      step += 1
      time.sleep(think_time)
      augmented_print('\nStep {0}: put vas pick.'.format(step), suppress=suppress)
      start = time.time()
      context['u_flag'] = True
      w_list = [u_id, u_token, 'product', json.dumps(vasPick)]
      #ret = common_func('B02', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
      with RedirectStdStreams(stdout=devnull, stderr=devnull):
        ret = common_func('B02', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
      end = time.time()
      dur = '{0:.3f}'.format(end-start)
      augmented_print('Duration: {0}'.format(dur), suppress=suppress)
      if ret is None:
        augmented_print('\nBusiness flow failed at TC: {0} -- while put vas pick at step: {1}'.format('B02', step), suppress=suppress)
        if suppress:
          logger.error("S04 put vas pick(B02) Failed. Input: {0}".format(w_list))
          return
        else:
          exit()
      vasPickId = ret.get("id")
      augmented_print('vasPickId: {0}\n'.format(vasPickId), suppress=suppress)

    if first_time:
      first_time = False
      #================================get basket=================================
      step += 1
      augmented_print('\nStep {0}: get basket.'.format(step), suppress=suppress)
      time.sleep(think_time)
      start = time.time()
      context['u_flag'] = True
      w_list = ['NA', u_token]
      #ret = common_func('B01', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
      with RedirectStdStreams(stdout=devnull, stderr=devnull):
        ret = common_func('B01', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
      end = time.time()
      dur = '{0:.3f}'.format(end-start)
      augmented_print('Duration: {0}'.format(dur), suppress=suppress)
      if ret is None:
        augmented_print('\nBusiness flow failed at TC: {0} -- basket at step: {1}'.format('B01', step), suppress=suppress)
        if suppress:
          logger.error("S04 basket(B01) Failed. Input: {0}".format(w_list))
          return
        else:
          exit()
      basketId = ret.get("id")
      cartNum = ret.get("cartNumber")
      augmented_print('basketId: {0}; cartNum: {1}\n'.format(basketId, cartNum), suppress=suppress)

    #================================basket/totals=================================
    step += 1
    augmented_print('\nStep {0}: check basket/totals.'.format(step), suppress=suppress)
    time.sleep(think_time)
    start = time.time()
    context['u_flag'] = True
    w_list = [u_id, u_token, basketId]
    #ret = common_func('B06', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      ret = common_func('B06', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('*Duration: {0}'.format(dur), suppress=suppress)
    if ret is None:
      augmented_print('\nBusiness flow failed at TC: {0} -- basket/totals at step: {1}'.format('B06', step), suppress=suppress)
      if suppress:
        logger.error("S04 basket/totals (B06) Failed. Input: {0}".format(w_list))
        return
      else:
        exit()
    netPayNow = ret["basketTotals"]["nettPayNow"]
    nettRecurring = ret["basketTotals"]["nettRecurring"]
    augmented_print('basketTotal -- netPayNow: {0}; nettRecurring: {1}\n'.format(netPayNow, nettRecurring), suppress=suppress)

  
  
  #================================update UC group=================================
  step += 1
  time.sleep(think_time)
  augmented_print('\nStep {0}: update/create UC Group.'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = True
  if ucGrpId:
    w_list = [u_id, u_token, ucGrpId]
  else:
    w_list = [u_id, u_token, ':'.join(['', ucGrpName, '98001010', u_id])]
  #ret = common_func('B07', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B07', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- while update/create UC group at step: {1}'.format('B07', step), suppress=suppress)
    if suppress:
      logger.error("S06 put update/create UC group (B07) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()

  #================================check subscription eligibility=================================
  step += 1
  augmented_print('\nStep {0}: check subscription eligibility.'.format(step), suppress=suppress)
  time.sleep(think_time)
  start = time.time()
  context['u_flag'] = True
  w_list = [u_id, u_token, subsPickId]
  #ret = common_func('B14', context, w_list, verbose=2, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    ret = common_func('B14', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if ret is None:
    augmented_print('\nBusiness flow failed at TC: {0} basket/pick/subscription/eligibility at step: {1}'.format('B14', step), suppress=suppress)
    if suppress:
      logger.error("S04 basket/pick/subscription/eligibility (B14) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()
  pick_dict = {}
  eligible = True
  for r in ret["bdmsrequest"]:
    pick_dict[r["referenceNumber"]] = r["bdmsresponse"]["eligible"]
    if not r["bdmsresponse"]["eligible"]:
      eligible = False
  for k, v in pick_dict.items():
    augmented_print('referenceNum: {0}; eligible: {1}'.format(k, v), suppress=suppress)
  if not eligible:
    augmented_print('\nBusiness flow failed at TC: {0} -- basket/pick/subscription/eligibility step: {1}'.format('B14', step), suppress=suppress)
    if suppress:
      logger.error("S04 basket/pick/subscription/eligibility (B14) Failed. Input: {0}".format(w_list))
      return
    else:
      exit()

  #================================submit order if submitFlag is True=================================
  if submitFlag:
    step += 1
    time.sleep(think_time)
    augmented_print('\nStep {0}: upload scanned contract documents.'.format(step), suppress=suppress)
    start = time.time()
    context['u_flag'] = True
    w_list = [u_id, u_token, basketId]
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      ret = common_func('B09', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
    if ret is None:
      augmented_print('\nBusiness flow failed at TC: {0} -- while upload scanned contract documents at step: {1}'.format('B09', step), suppress=suppress)
      if suppress:
        logger.error("S06 upload scanned contract documents (B09) Failed. Input: {0}".format(w_list))
        return
      else:
        exit()
    refId = ret["contractDoc"]["refId"]
    augmented_print('document refId: {0}\n'.format(refId), suppress=suppress)
  
#    step += 1
#    time.sleep(think_time)
#    augmented_print('\nStep {0}: checkout.'.format(step), suppress=suppress)
#    start = time.time()
#    context['u_flag'] = True
#    w_list = [u_id, u_token, basketId]
#    with RedirectStdStreams(stdout=devnull, stderr=devnull):
#      ret = common_func('B10', context, w_list, verbose=0, req=req, suppress_params=True, A_P='_'.join([prefix, '{0:02d}'.format(step)]))
#    end = time.time()
#    dur = '{0:.3f}'.format(end-start)
#    augmented_print('Duration: {0}'.format(dur), suppress=suppress)
#    if ret is None:
#      augmented_print('\nBusiness flow failed at TC: {0} -- while checkout at step: {1}'.format('B10', step), suppress=suppress)
#      if suppress:
#        logger.error("S06 check (B10) Failed. Input: {0}".format(w_list))
#        return
#      else:
#        exit()
  
  #augmented_print(json.dumps(ret, sort_keys=True, indent=2, separators=(',', ':')))
  augmented_print('\nEnd here. Token: {0}\n'.format(u_token), suppress=suppress)

###############################################end of S06_func


def S09_func(tc_id, cxt, p_list, verbose, **kw):
  '''
  exhaustively search devices in status IN_STOCK.
  '''
  req = kw.pop('req', None)
  suppress = kw.get('suppress', False)
  think_time = kw.get('think_time', 1)

  step = 0

  context = cxt.copy()
  campaignId = p_list[0]
  bundleId = p_list[1]
  devType = p_list[2] if len(p_list) > 2 and len(p_list[2]) > 0 else None

  # get all the devices of a given combination of campaignId and bundleId
  step += 1
  augmented_print('\nStep {0}: get all the devices of a given combination of campaignId and bundleId'.format(step), suppress=suppress)
  start = time.time()
  context['u_flag'] = False
  w_list = [':'.join([campaignId,bundleId])]
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    device_list = common_func('D02', context, w_list, verbose=0)
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  augmented_print('Duration: {0}'.format(dur), suppress=suppress)
  if device_list is None:
    augmented_print('\nBusiness flow failed at TC: {0} -- devices?bundleId={bundleId}&campaignId={campaignId} at step: {1}'.format('D02', step), suppress=suppress)
    if suppress:
      return
    else:
      exit()

  # iterate through device list to find out device in status IN_STOCK
  for d in device_list["device"]:
    if devType is None or devType == d.get("deviceSubType"):
      pass
    else:
      continue
    step += 1
    augmented_print('\nStep {0}: check through {1}, {2}, {3}, {4}'.format(step, d["deviceBrand"], d["devicePartNum"], d["deviceName"], devType), suppress=suppress)
    start = time.time()

    devStockCode_list = []
    for v in d["deviceVariants"]["deviceVariant"]:
      devStockCode_list.append(v["deviceStockCode"])
    w_list = [':'.join(devStockCode_list)]
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      inv_list = common_func('D04', context, w_list, verbose=0)
    if inv_list is None:
      continue
    for i in inv_list["inventory"]:
      if i["stockStatus"] != "OUT_OF_STOCK":
        print('{0} -- {1}'.format(i["deviceStockCode"], i["stockStatus"]))

    end = time.time()
    dur = '{0:.3f}'.format(end-start)
    augmented_print('Duration: {0}'.format(dur), suppress=suppress)



# dummy pseudo TC for demo purpose
def S99_func(tc_id, cxt, p_list, verbose):
  context = cxt
  u_id = p_list[0]
  u_token = p_list[1]
  devStkCode = "EAPP0007303"
  simType = "3G TriSIM Card"
  ret = common_func('D04', context, [devStkCode, '','','','','','','','','',''], verbose)
  ret = common_func('G02', context, [simType, 'Voice', '10', '','','','','','','','','',''], verbose)
  ret = common_func('A01', context, [u_id, u_token, '', '', '', '', ''], verbose)


def common_func(tc_id, context, param_list, verbose, **kw):
  A_P = kw.get('A_P', '')
  if kw.get('suppress_params', False):
    params_str = ""
  else:
    params_str = ','.join(param_list)
  if kw.get('req'):
    req = kw.pop('req', None)
  else:
    #req = Comm_req2(get_end_point(tc_id), proxies=PROXIES)
    req = Comm_req(CONTEXT.get('t_log', logger), get_end_point(tc_id), proxies=PROXIES)

  headers = get_headers(tc_id)
  payload, querystr = get_payload(tc_id, param_list, query_str_fl(tc_id)) # get respective TC payload
  method, res, auth, analyser = get_res_n_met(tc_id, param_list) # get respective request method, resource name and auth flag
  url = get_end_point(tc_id) + res

  if auth == 'Y':
    if context['u_flag'] or len(param_list) > 1 and isToken(param_list[1]):
      u_token = param_list[1]
    else:
      u_token = X00_login(tc_id, context, param_list, verbose)
      if u_token is None:
        if verbose:
          print(' - Error: {0} failed login.'.format(param_list[0]))
          logger.debug(' - Error: {0} failed  login'.format(param_list[0]))
        return
    if context['etag']:
      headers['Authorization'] = u_token
      headers['If-None-Match'] = context['etag']
    else:
      headers['Authorization'] = u_token
  else:
    if context['etag']:
      headers['If-None-Match'] = context['etag']

  start = time.time()
  for i in range(Tries):
    #r = req.submit_req(res, method, headers, payload, query_str_fl(tc_id), TC=tc_id, INPUT=params_str)
    r = req.submit_req(res, method, headers, data=payload, params=querystr, TC=tc_id, INPUT=params_str, A_P=A_P)
    if r.status_code != 202:
      break
    time.sleep(fibonacci(i+1))
  end = time.time()
  dur = '{0:.3f}'.format(end-start)
  etag = ''
  ret = None
  if r.status_code == 200 or r.status_code == 202:
    if verbose > 1:
      print('\nresponse: {0}'.format(r.content))
    ret = analyser(r, param_list, verbose)
    etag = r.request.headers.get('If-None-Match') if r.request.headers.get('If-None-Match') else r.headers.get('ETag')
  else:
    if verbose > 1:
      req_obj = r.request
      print('{0}\n{1}\n{2}\n\n{3}\n{4}'.format(
            '\n-----------raw HTTP request-----------',
            req_obj.method + ' ' + req_obj.url,
            '\n'.join('{0}: {1}'.format(k, v) for k, v in req_obj.headers.items()),
            req_obj.body,
            '-----------raw HTTP request ends------\n'))
      print('\n-status_code: {0}'.format(r.status_code))
      print('-response: {0}'.format(r.content))
    etag = ''

  if context['debug']:
    print('\n - Statistics: Transaction Response Time: {0} sec.; Status: {1}; ETag: {2}; Throughput: {3} bytes. -- Param list: {4}\n'.format(dur, r.status_code, etag, len(r.content), param_list))
  logger.debug(' - Response: code: {0}; content: {1}'.format(r.status_code, r.content))
  logger.info(' - Statistics: Transaction Response Time: {0} sec.; Status: {1}; Throughput: {2} bytes. -- Param list: {3}'.format(dur, r.status_code, len(r.content), param_list))
  return ret

def get_func(tc_id, cxt, param_list, v=0, **kw):
    switcher = {
        'X00': X00_login,
        'X01': X01_esso_login,
        'R01': R01_func,
        'S04': S04_func,
        'S05': S05_func,
        'S06': S06_func,
        'S09': S09_func,
        'S99': S99_func,
    }
    # Get the function name from switcher dictionary to process the request
    func_name = switcher.get(tc_id, common_func)
    return func_name(tc_id, cxt, param_list, v, **kw)

# Dictionary Mapping for API request method and resource name
def get_res_n_met(id, PARAM):
  param = PARAM + ['','','','','']
  switcher = {
    'A00': ('OTHERS', '', 'N', dummy_analyser),
    'A01': ('GET', 'sfapismb/esbapi/smbonline/customerinfo', 'Y', A01_analyser),
    'A02': ('GET', 'sfapismb/esbapi/smbonline/bills/{0}'.format(param[2]), 'Y', A02_analyser),
    'A03': ('GET', 'sfapismb/esbapi/smbonline/contracts/mobile/{0}'.format(param[2]), 'Y', A03_analyser),
    'A04': ('GET', 'sfapismb/esbapi/smbonline/bills/checkPaidOverdueAmt', 'Y', A04_analyser),
    'A05': ('GET', 'sfapismb/esbapi/smbonline/contracts/{0}'.format(param[2]), 'Y', A05_analyser),
    'A06': ('GET', 'sfapismb/esbapi/smbonline/bills/{0}'.format(param[2]), 'Y', A06_analyser),
    'A07': ('POST', 'sfapismb/esbapi/smbonline/new/{0}/ebg{1}'.format(param[2], '?baCreaditFlag=true' if param[5].upper() == 'Y' else ''), 'Y', A07_analyser),
    'A08': ('POST', 'sfapismb/esbapi/smbonline/ebsucgroup', 'Y', A08_analyser),
    'A09': ('POST', 'fapismb/esbapi/smbonline/inventory/queryResource', 'N', A09_analyser),
    'A10': ('GET', 'sfapismb/esbapi/smbonline/transactions', 'Y', A10_analyser),

    'B01': ('GET', 'sfapismb/esbapi/smbonline/basket', 'Y', B01_analyser),
    'B02': ('PUT', 'sfapismb/esbapi/smbonline/basket/pick?{0}=1'.format(param[2]), 'Y', B02_analyser),
    'B03': ('GET', 'sfapismb/esbapi/smbonline/basket/eligibility', 'Y', B03_analyser),
    'B04': ('DELETE', 'sfapismb/esbapi/smbonline/basket', 'Y', B04_analyser),
    'B05': ('GET', 'sfapismb/esbapi/smbonline/basket/status?id={0}'.format(param[2]), 'Y', B05_analyser),
    'B06': ('GET', 'sfapismb/esbapi/smbonline/basket/totals/{0}'.format(param[2]), 'Y', B06_analyser),
    'B07': ('PUT', 'sfapismb/esbapi/smbonline/basket/customerinfo', 'Y', B07_analyser),
    'B08': ('DELETE', 'sfapismb/esbapi/smbonline/basket/pick/{0}'.format(param[2]), 'Y', B08_analyser),
    'B09': ('POST', 'sfapismb/esbapi/smbonline/contractdocs/{0}/scannedFiles'.format(param[2]), 'Y', B09_analyser),
    'B10': ('GET', 'content/smb/en/dev/checkout.html', 'N', dummy_analyser),
    'B11': ('GET', 'sfapismb/esbapi/smbonline/broadband-checkout.html', 'N', dummy_analyser),
    'B12': ('POST', 'sfapismb/esbapi/smbonline/basket/pick/billdeliverymethod/{0}'.format(param[2]), 'Y', B12_analyser),
    'B13': ('POST', 'sfapismb/esbapi/smbonline/basket/collectioninfo', 'Y', B13_analyser),
    'B14': ('GET', 'sfapismb/esbapi/smbonline/basket/pick/subscription/eligibility/{0}'.format(param[2]), 'Y', B14_analyser),
    'B15': ('POST', 'sfapismb/esbapi/smbonline/basket/pick?{0}=1'.format(param[2]), 'Y', B15_analyser),
    'B16': ('POST', 'sfapismb/esbapi/smbonline/basket/finalise', 'Y', dummy_analyser),
    'B17': ('POST', 'sfapismb/esbapi/smbonline/basket/checkout/{0}'.format(param[2]), 'Y', dummy_analyser),
    'B18': ('GET', 'sfapismb/esbapi/smbonline/basket/illustrative/{0}'.format(param[2]), 'Y', B18_analyser),

    'D01': ('GET', 'fapismb/esbapi/smbonline/devices/{0}'.format(param[0]), 'N', D01_analyser),
    'D02': ('GET', 'fapismb/esbapi/smbonline/devices', 'N', D02_analyser),
    'D03': ('GET', 'fapismb/esbapi/smbonline/devices/mobile/handset/{0}'.format(param[0]), 'N', D03_analyser),
    'D04': ('POST', 'sfapismb/esbapi/smbonline/inventory{0}'.format('?code=' + param[1] if param[1] != '' else ''), 'N', D04_analyser),

    'P01': ('GET', 'fapismb/esbapi/smbonline/promotions', 'N', P01_analyser),
    'P02': ('GET', 'fapismb/esbapi/smbonline/promotions', 'N', P02_analyser),
    'P03': ('GET', 'fapismb/esbapi/smbonline/promotions/{0}/{1}'.format(param[0], param[1]), 'N', P03_analyser),
    'P04': ('GET', 'fapismb/esbapi/smbonline/products/{0}/plans'.format(param[0]), 'N', P04_analyser),
    'P05': ('GET', 'sfapismb/esbapi/smbonline/products', 'Y', P05_analyser),
    'P06': ('GET', 'fapismb/esbapi/smbonline/products/{0}/plans{1}'.format(param[0], '/'+param[1] if param[1] and param[1].upper() != 'NA' else ''), 'N', P06_analyser),
    'P07': ('GET', 'sfapismb/esbapi/smbonline/products/{0}'.format(param[2]), 'Y', P07_analyser),
    'P08': ('GET', 'sfapismb/esbapi/smbonline/vas/recommended?type=mobile&customerType=BRN', 'Y', P08_analyser),


    'G02': ('GET', 'sfapismb/esbapi/smbonline/numbers', 'N', G02_analyser),
    'G03': ('GET', 'sfapismb/esbapi/smbonline/numbers/{0}'.format(param[0]), 'N', dummy_analyser),
    'G04': ('GET', 'sfapismb/esbapi/smbonline/eligibility?name=aodirectory', 'Y', G04_analyser),
    'G05': ('POST', 'sfapismb/esbapi/smbonline/brneligibility/smartsharecheck', 'Y', G05_analyser),
    'G06': ('POST', 'sfapismb/esbapi/smbonline/recontract/changeplan/mobile/{0}/ebg'.format(param[2]), 'Y', G06_analyser),
    'G07': ('POST', 'sfapismb/esbapi/smbonline/batchrecontract/mobile/{0}/ebg{1}'.format(param[2], '?type=' + param[3] if param[3] != '' else ''), 'Y', dummy_analyser),
    'G08': ('POST', 'sfapismb/esbapi/smbonline/brneligibility/aocheck?aoEmailId={0}'.format(param[2]), 'Y', G08_analyser),

    'H01': ('POST', 'sfapismb/esbapi/smbonline/new/mobile/ebg?mode={0}&signupCount={1}&basket=true'.format(param[2].lower(), param[3]), 'Y', H01_analyser),
    'H02': ('POST', 'sfapismb/esbapi/smbonline/recontract/mobile/{0}/ebg'.format(param[2]), 'Y', H02_analyser),

    'J01': ('POST', 'fapismb/esbapi/smbonline/address', 'N', J01_analyser),
    'J02': ('GET', 'fapismb/esbapi/smbonline/address/coveragecheck', 'N', J02_analyser),

    'K01': ('GET', 'sfapismb/esbapi/smbonline/tray/vouchers', 'Y', K01_analyser),

    'L01': ('GET', 'sfapismb/esbapi/smbonline/brnappointments/{0}?root=Mobile'.format(param[2]), 'Y', L01_analyser),
    'L02': ('POST', 'sfapismb/esbapi/smbonline/brnappointments', 'Y', L02_analyser),
    'L03': ('DELETE', 'sfapismb/esbapi/smbonline/brnappointments/{0}'.format(param[2]), 'Y', L03_analyser),

    'M16': ('PUT', 'sfapismb/esbapi/smbonline/basket/existingcomponents', 'Y', dummy_analyser),

    'O13': ('GET', 'sfapismb/esbapi/smbonline/contractdocs/status?shoppingCartNumber={0}'.format(param[2]), 'Y', dummy_analyser),
    'O14': ('GET', 'sfapismb/esbapi/smbonline/contractdocs/download/orderID={0}'.format(param[2]), 'Y', dummy_analyser),
   
    'R01': ('GET', 'sfapismb/esbapi/smbonline/login/order.json?id={0}'.format(param[2]), 'Y', dummy_analyser),

    'S04': ('OTHERS', '', 'N', dummy_analyser),
    'S05': ('OTHERS', '', 'N', dummy_analyser),
    'S06': ('OTHERS', '', 'N', dummy_analyser),
    'S09': ('OTHERS', '', 'N', dummy_analyser),
    'S99': ('OTHERS', '', 'N', dummy_analyser),

    'X00': ('OTHERS', '', 'N', dummy_analyser),
    'X01': ('OTHERS', '', 'N', dummy_analyser),
    'X02': ('POST', 'fapismb/esbapi/smbonline/login/enterprise', 'N', X02_analyser),
    'X03': ('POST', 'sfapismb/esbapi/smbonline/authtoken', 'Y', dummy_analyser),
    'X04': ('GET', 'sfapismb/esbapi/smbonline/profile/getUserInfo', 'Y', X04_analyser),
    'X05': ('POST', 'sfapismb/esbapi/smbonline/login/verifyBRN', 'Y', X05_analyser),
    
    '99': ('GET', '{0}'.format(param[0]), 'N', dummy_analyser),
  }
  # Get the respective API request method and resource name from switcher dictionary
  return switcher.get(id)


def get_end_point(tc_id):
    switcher = {
    }
    # Get the TC specific end point from switcher dictionary to process the request
    end_point = switcher.get(tc_id, CONTEXT['end_point'][0])
    return end_point

def get_headers(tc_id):
    switcher = {
      'A09': {'X-User-Agent': 'starhub/online/smb'},

      'D01': {'X-User-Agent': 'starhub/online/smb'},
      'D02': {'X-User-Agent': 'starhub/online/smb'},
      'D03': {'X-User-Agent': 'starhub/online/smb'},

      'P01': {'X-User-Agent': 'starhub/online/smb'},
      'P02': {'X-User-Agent': 'starhub/online/smb'},
      'P03': {'X-Content-Type': 'application/json', 'X-User-Agent': 'starhub/online/smb'},
      'P04': {'X-User-Agent': 'starhub/online/smb'},
      'P06': {'X-User-Agent': 'starhub/online/smb'},

      'J01': {'X-User-Agent': 'starhub/online/smb'},
      'J02': {'X-User-Agent': 'starhub/online/smb'},

      'X02': {'X-User-Agent': 'starhub/online/smb', 'X-Requested-With': 'XMLHttpRequest', 'Referer': 'https://onlinestore-uat.business.starhub.com/business/store/mobile.html',
              'Host': 'onlinestore-uat.business.starhub.com', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36'},
    }
    # Get the function name from switcher dictionary to process the request
    headers = deepcopy(HEADERS)
    header = switcher.get(tc_id, {})
    headers.update(header)
    return headers

def query_str_fl(tc_id):
    switcher = {
      'A07': False,
      'A08': False,
      'A09': False,

      'B02': False,
      'B07': False,
      'B12': False,
      'B13': False,
      'B15': False,

      'D04': False,

      'G05': False,

      'H01': False,

      'J01': False,

      'L02': False,

      'X02': False,
      'X03': False,
      'X05': False,
    }
    flag = switcher.get(tc_id, True)
    return flag


# Dictionary Mapping for Functions to access the respective payload templates
def get_payload(arg, context, query_str_fl):
    switcher = {
        'A01': A01_payload,
        'A05': A05_payload,
        'A07': A07_payload,
        'A08': A08_payload,
        'A09': A09_payload,
        'A10': A10_payload,

        'B01': B01_payload,
        'B02': B02_payload,
        'B07': B07_payload,
        'B10': B10_payload,
        'B12': B12_payload,
        'B13': B13_payload,
        'B15': B15_payload,
        'B17': B17_payload,

        'D01': D01_payload,
        'D02': D02_payload,
        'D03': D03_payload,
        'D04': D04_payload,

        'G02': G02_payload,
        'G05': G05_payload,

        'H01': H01_payload,

        'J01': J01_payload,
        'J02': J02_payload,

        'L02': L02_payload,

        'M16': M16_payload,

        'P01': P01_payload,
        'P02': P02_payload,
        'P03': P03_payload,
        'P04': P04_payload,
        'P05': P05_payload,
        'P06': P06_payload,
        'P07': P07_payload,
        'P08': P08_payload,

        'X02': X02_payload,
        'X03': X03_payload,
        'X04': X04_payload,
        'X05': X05_payload,
    }
    # Get the paylaod template name from switcher dictionary
    tmpl_name = switcher.get(arg, dummy_payload)
    # return by executing the payload template function
    return tmpl_name(context, query_str_fl)


def R01_func(tc_id, cxt, p_list, verbose):
  context = cxt.copy()
  context["end_point"] = "https://onlinestore-uat.business.starhub.com/content/smb/en/dev/"
  common_func(tc_id, context, p_list, verbose)

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
    'A00': A00_worker,
    'S04': TS_worker,
    'S05': TS_worker,
    'S06': TS_worker,
  }
  return switcher.get(tc_id, common_worker)

# get end point of environment
def get_ip_addr(env):
  switcher = {
    'UAT':   ['https://onlinestore-uat.business.starhub.com/'],
  }
  return switcher.get(env)


# dummy pseudo TC for demo purpose.
def S99_worker(T_LOG, url, headers, payload, method, params):
  p_list = params.split(',')
  context = {'end_point': url, 'ua':CONTEXT['ua'], 'u_flag':True, 'debug':False, 'etag':None, 't_log':T_LOG, 'l_log':CONTEXT['l_log']}
  S99_func(p_list[0], context, p_list[1:], False)


def TS_worker(req, res, headers, payload, method, log, tc_id, param_list, retry=True, a_p="N", think_t=0):
  get_func(tc_id, CONTEXT, param_list[:-1], False, suppress=True, req=req, think_time=think_t, prefix=a_p)
  with RedirectStdStreams(stdout=devnull, stderr=devnull):
    common_func('B04', CONTEXT, param_list[:2], verbose=0, req=req)
  return

def common_worker(req, res, headers, payload, method, log, tc_id, param_list, retry=True, a_p="N", think_t=0):
  for i in range(Tries):
    r = req.submit_req(res, method, headers, payload, query_str_fl(tc_id), TC=tc_id, INPUT=';'.join(param_list[:-1]), A_P=a_p)
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
    if TaskQueue.empty():
      return

    item_x = TaskQueue.get()
    tc_id = item_x.split(',')[0].lstrip().rstrip()
    headers = get_headers(tc_id)
    retry = get_202_retry(tc_id)
    do_work = get_do_worker(tc_id)
    param_list = item_x.split(',')[1:]

    method, res, auth, analyser = get_res_n_met(tc_id, param_list) # get respective request method, resource name and auth flag
    payload = None

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

    req = Comm_req(log, get_end_point(tc_id), proxies=PROXIES)
    if auth == 'Y':
      if CONTEXT['u_flag'] or isToken(param_list[1]):
        u_token = param_list[1]
      else:
        u_token = X00_login(tc_id, CONTEXT, param_list, verbose=0)
        param_list[1] = u_token
      headers['authorization'] = u_token
      if u_token is None:
        TaskQueue.task_done()
        continue

    if method: # if method is None, it means pseudo TC
      payload = get_payload(tc_id, param_list, query_str_fl(tc_id)) # get respective TC payload
      url = get_end_point(tc_id) + res

    param_list.append(1) # param used as a flip and flap switch to some TCs.
    if lFlag: # control by duration
      while True:
        current = time.time()
        if current < ending:
          time.sleep(float(pacing_time))
          param_list[-1] ^= 1
          do_work(req, res, headers, payload, method, log, tc_id, param_list, retry, a_p, think_t)
        else:
          break
    else:
      for i in range(cnt):
        time.sleep(float(pacing_time))
        param_list[-1] ^= 1
        do_work(req, res, headers, payload, method, log, tc_id, param_list, retry, a_p, think_t)
    TaskQueue.task_done()

# Define a main() function
def main():
  ###############################
  global CONTEXT
  A_flag = False
  S_flag = False
  s_flag = False
  t_flag = False
  L_flag = False
  M_flag = False
  R_flag = False
  verbose = 0
  ENV = 'UAT'
  DT_ID = None
  #keys = 'id:code:name:status:type:start'
  pacing_time = 0
  THREADS = 0
  RAMPUP = None
  M_CNT = 1
  DELAY_START = 1 # postponning some sec before reading item from a queue, give producer some time to prepare the queue
  ending = time.time() + 60
 
  if len(sys.argv) == 1:
    usage(os.path.basename(sys.argv[0]))
    sys.exit(0)

  # parse command line options
  try:
    opts, args = getopt.getopt(sys.argv[1:], "A:e:k:f:s:w:B:L:p:M:c:D:V:RShdvtU")
  except getopt.GetoptError as err:
    # print help information and exit:
    logger.error(err)
    usage(os.path.basename(sys.argv[0]))
    sys.exit(2)
  fn = None
  for o, a in opts:
    if o == "-e":
      CONTEXT['end_point'] = get_ip_addr(a) # get end point
      ENV = a
    elif o == "-L":
      L_flag = True
      ending = time.time() + float(int(a) * 60) # set estimated ending time.
    elif o == "-D":
      DT_ID = a # Dynatrace id
    elif o == "-p":
      CONTEXT['passwd'] = a
    elif o == "-w":
      pacing_time = a
    elif o == "-c":
      M_CNT = int(a)
    elif o == "-R":
      R_flag = True
    elif o == "-t":
      t_flag = True
    elif o == "-U":
      CONTEXT['u_flag'] = True
    elif o == "-B":
      RAMPUP = a
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
      verbose = int(a)
    elif o == "-S":
      S_flag = True
    elif o == "-A":
      A_flag = True
      fn = a  # json input file name
    elif o == "-k":
      keys = a
    elif o == "-s":
      s_flag = True
      tc_id = a  # TC id
      param_list = []
      if len(args) == 1:
        param_list = args[0].split(",")
      else:
        param_list = args[0:] # TC params
      if '+a' in param_list:
        index = param_list.index('+a')
        param_list = param_list[:index]
    else:
      assert False, "unhandled option"
      sys.exit(1)

  logger.info(' - {0} {1} starts with params: {2}.'.format(os.path.basename(sys.argv[0]), version, sys.argv[1:]))
  if verbose:
    print('{0} starts at {1}'.format(os.path.basename(sys.argv[0]), datetime.datetime.now().strftime('%Y%m%d %H:%M:%S')))
  # main body, branch 1: taking TC ids and TC contexts from an input file; branch 2: taking TC id and TC context params from command line.
  if S_flag:
    dump_sce()
    exit()
  elif A_flag:
    ana_json(fn, False if len(args) > 0 and args[0].upper() == "N" else True)
    exit()
  elif R_flag:
    payload = {'versionbuild': '1', 'versionmajor': '1', 'versionmilestone': '1', 'versionminor': '1', 'versionrevision': '1',
               'marker': '1', 'platform': '1', 'category': 'webapi', 'additionalmetadata': {}}
    url = 'https://10.199.24.137:8021/api/v1/profiles/StarHub_{0}/testruns'.format(ENV)
    HEADERS = {'content-type':'application/json', 'accept': 'application/json'}
    with RedirectStdStreams(stdout=devnull, stderr=devnull):
      r = requests.post(url, verify=False, auth=('local-test-auto', 'local-test-auto'), json=payload, headers=HEADERS)
    if r.status_code == 201:
      ID = r.json()['id']
      print('\nRegistration ID: {0}'.format(ID))
    exit()
  elif fn != None: # with -f option
  ##########################################
    if M_flag == False:
      while True:
        # open the file and keep the file handle in variable fh.
        # iterate through the file to fetch TC id as well as TC context params
        with open(fn, 'r') as fh:
          for line0 in fh:
            line = line0.rstrip('\n').lstrip() + '#'
            if line.startswith('#') or not line:
              continue
            line = line.split('#')[0].strip('\r')
            tc_id = line.split(',')[0].lstrip().rstrip()
            param_list = line.split(',')[1:] if len(line.split(',')) > 1 else []
            if '+a' in param_list:
              index = param_list.index('+a')
              param_list = param_list[:index]

            get_func(tc_id, CONTEXT, param_list, verbose)

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
      m_start = datetime.datetime.now()
      ts = m_start.strftime('%Y%m%d%H%M%S')
      t_log_name = myApp + '_M' + str(THREADS) + '.' + ts
      print('Program started with multi-threading, checking log file for prograss: {0}'.format(t_log_name))
      t_log = thread_logger(myApp, THREADS, ts) # get thread logger
      CONTEXT['t_log'] = t_log
      while True:
        # stuff work items on the queue (in this case, just a tuple of TC id and param list).
        with open(fn, 'r') as fh:
          for line in fh:
            line = line.rstrip('\n').lstrip()
            if line.startswith('#') or not line:
              continue
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
      m_end = datetime.datetime.now()
      logger.info(' - Elapsed time: {0:.3f}'.format((m_end-m_start).total_seconds()))
      print('Elapsed time: {0:.3f} sec.'.format((m_end-m_start).total_seconds()))
    ################################# end of multi-threads processing
  elif s_flag:  # with -s option
    get_func(tc_id, CONTEXT, param_list, verbose)
  else:
    usage(os.path.basename(sys.argv[0]))
    sys.exit()
    
  if verbose:
    print('{0} ends at {1}'.format(os.path.basename(sys.argv[0]), datetime.datetime.now().strftime('%Y%m%d %H:%M:%S')))
  logger.info(' - {} ends.'.format(os.path.basename(sys.argv[0])))

# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
  main()
