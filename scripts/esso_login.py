#!/usr/bin/python2.7 -tt
# -*- coding: utf-8 -*-

# AUTHOR:       Gu Jian Min
# DATE:         02/09/2020
# PROGRAM:      esso_login.py
# PURPOSE:
#               esso login class.
#
# HISTORY:
#       version 1.0     02/09/2020              --- program initial
#       version 1.1     08/09/2020              --- introduced SMB OLS ESSO login.
#
version = 'v1.1'


import re
import datetime
import time
import requests
from lxml import etree, html
import urllib
import base64
import json

class login(object):
  '''
  The login class supports below listed 3 types of login:
    1) MSA login
    2) OLS login
    3) OLS login2
    4) SMB OLS login
  '''
  def __strip_ns(self, content):
    content = re.sub(r' *= *', '=', content)
    content = re.sub(r' xmlns:[^ ,>]*', '', content)
    content = re.sub(r'<[a-zA-Z0-9]+:', '<', content)
    content = re.sub(r'</[a-zA-Z0-9]+:', '</', content)
    content = re.sub('<IR[^>]+', '<IR', content, count=1)
    return content

  def __init__(self, hub_id, password, verbose=False):
    self.proxies = {'https':'proxy.starhubsg.sh.inc:8080', 'http':'proxy.starhubsg.sh.inc:8080'}

    # reserved for SMB OLS login
    self.smQueryData = '-SM-hsHzTBwmAzObAc1f6j%2bJcLRoZkXheFRImGNYitxCHCZxxREN292JXYb1FaWEJo%2fBtqkjTZZKsW5QmxLnILv7bWGpiS6%2b8YDZZEBTzb85HOg1KTuXnPmSq8PXabSBUmo%2bZKCY8vCBt7pGAFuVNnoYlhtNxWBgWEtmoKs4NvzEktvAyIazQ%2f8f0M6HSXioAHpYoxwHn1rIZG3Y0AgNiNeUSU1t87kvEZZD33EhL69mIbi2E5FelUv%2bU6jcM0ZOq9lJjrdr4Y7lailV5Jx9nuTzOYdP1ZrrgfmMVBh%2b62NlECTWefzI3oklqbwd68yuRI44XFIVV7hkl2BZzdT4T6F4ZcMaJWnF6S8M%2ft2EsOIGuYborPrztdi1ri4phZ8YeZmSibCN4Ex5mtrFSgoguaDRPH1dNWfAu94NZCHSx2B7ZWcyCRjSwQYf%2fAhSGp1Y7pbF4veasrzbfghasO8%2f5pTQ1EM5NenFcKLAjYWpt2fGKcR10%2bdS3CfacxPvwQA0wnxcW5oMekmIsF4bVQsfMkPfrNRjDGmlscSBZ1bsshCTMw%2fxYB909HdcelMH2p2LB7JO'
    self.smQueryData_unquote = requests.utils.unquote(self.smQueryData)
    self.sm_serversessionid_obj = re.compile(r'^SM_SERVERSESSIONID:(.+)$')
    self.eid_brn_list_obj = re.compile(r'^EID_BRN_LIST:(.+)$')

    self.txnid = datetime.datetime.now().strftime('SHG%Y%m%d%H%M%S%f')[:-3]
    self.vctk3_url_obj = re.compile(r'^.*vctk3=(.*)$')
    self.vctk3_obj = re.compile(r'^.*cookie=\"vctk3=([^;]+);.*$')
    self.acvctk_obj = re.compile(r'^.*acvctk=(.+)$')
    self.headers_msa = {'content-type':'application/json'}
    self.headers_login = {'content-type': 'text/xml', 'accept': 'text/xml', 'user-agent': '2f9318642700f42d629225044b26762e', 'x-forwarded-proto': 'https'}
    self.headers_login2 = {
      'upgrade-insecure-requests': '1',
      'content-type': 'application/x-www-form-urlencoded',
      'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36',
      'Referer': 'https://login.dev.starhubgee.com.sg/sso/HubidLogin?view=mobile&txnid={0}'.format(self.txnid),
      'origin': 'https://login.dev.starhubgee.com.sg'
    }

    # reserved for SMB OLS login
    self.headers_eid = {
      'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
      'content-type': 'application/x-www-form-urlencoded',
      'Host': 'enterpriseiduat.business.starhub.com',
      'Origin': 'https://enterpriseiduat.business.starhub.com',
      'Referer': 'https://enterpriseiduat.business.starhub.com/auth/eidlogin.jsp?SMQUERYDATA={0}'.format(self.smQueryData),
      'upgrade-insecure-requests': '1',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36'
    }
    self.headers_eid_cb = {
      'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
      'Referer': 'https://onlinestore-uat.business.starhub.com/business/store/mobile.html',
      'Connection': 'keep-alive',
      'Host': 'onlinestore-uat.business.starhub.com',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'same-origin',
      'Sec-Fetch-User': '?1',
      'upgrade-insecure-requests': '1',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36'
    }

    self.hub_id = hub_id
    self.password = password
    self.verbose = verbose

    self.ols_login2_url = 'https://login.dev.starhubgee.com.sg/eam/login2'
    self.ols_login_url = 'https://login.dev.starhubgee.com.sg/eam/login'
    self.msa_login_url = 'https://login.dev.starhubgee.com.sg/msso/mapp/api/login'
    self.aes_gen_url = 'https://login.dev.starhubgee.com.sg/msso/aesGen'
    self.status_url = 'https://uat.starhub.com/content/starhub/en/dev/login/status.json'

    # reserved for SMB OLS login
    self.eid_login_url = 'https://enterpriseiduat.business.starhub.com/siteminderagent/forms/login.fcc'
    self.eid_session_id_url = 'https://onlinestore-uat.business.starhub.com/content/smb/en/dev/login/status.txt'

    self.session = requests.Session()


  def msa_login(self):
    # call API to get encrypted password.
    payload = {'payload': '{0}_{1}'.format(self.password, str(int(time.time() * 1000))), 'key': 'Ufinity2016', 'salt': 'a277944f11d53c09'}
    resp = self.session.get(self.aes_gen_url, params=payload, proxies=self.proxies)
    if resp.status_code == 200:
      encrypted_passwd = resp.json()['ret_msg']
      print('BBB', encrypted_passwd)
    else:
      if self.verbose:
        print('Failed to encrypt password')
      return None
    
    # login through esso
    payload = {'user_id': self.hub_id, 'user_password': encrypted_passwd, 'site_id': 'mystarhub'}
    payload = json.dumps(payload)
    resp = self.session.post(self.msa_login_url, data=payload, headers=self.headers_msa, proxies=self.proxies)

    if self.verbose:
      req_obj = resp.request
      print('{0}\n{1}\n{2}\n\n{3}\n{4}'.format(
            '\n-----------raw HTTP request-----------',
            req_obj.method + ' ' + req_obj.url,
            '\n'.join('{0}: {1}'.format(k, v) for k, v in req_obj.headers.items()),
            req_obj.body,
            '-----------raw HTTP request ends------\n'))

    if resp.status_code == 200 and resp.json()['ret_code'] == 1000:
      vctk3 = resp.json()['user_token']
      if self.verbose:
        print('vctk3: {0}'.format(vctk3))
      return vctk3
    else:
      if self.verbose:
        print('msa failed login')
      return None


  def ols_login(self):
    payload = {
      'cb': 'https://uat.starhub.com/content/starhub/en/dev/login/auth.html?back64={0}&olsBack=true&back='.format(base64.b64encode('https://uat.starhub.com/content/starhub/en/personal/store/mobile/browse.html')),
      'cberr': 'https://login.dev.starhubgee.com.sg/sso/HubidLogin?view=mobile&txnid={0}'.format(self.txnid),
      'form_fake_uid': self.hub_id,
      'password': self.password,
      'checker': 'on',
      'view': 'mobile',
      'txnid': self.txnid,
      'CsrfSnKey': None,
      'vcid': 'icare',
      'uid': '{0}@uuid'.format(self.hub_id),
      'domain': 'uuid'
    }
    resp = self.session.post(self.ols_login_url, params=payload, headers=self.headers_login, proxies=self.proxies)

    if self.verbose:
      req_obj = resp.request
      print('{0}\n{1}\n{2}\n\n{3}\n{4}'.format(
            '\n-----------raw HTTP request-----------',
            req_obj.method + ' ' + req_obj.url,
            '\n'.join('{0}: {1}'.format(k, v) for k, v in req_obj.headers.items()),
            req_obj.body,
            '-----------raw HTTP request ends------\n'))

    if resp.status_code != 200:
      if self.verbose:
        print('esso login failed')
      return None
    vctk3 = self.vctk3_url_obj.match(resp.url)
    if not vctk3:
      if self.verbose:
        print('esso login failed')
      return None
    else:
      vctk3 = vctk3.group(1)
    if self.verbose:
      print('vctk3: {0}'.format(vctk3))

    return vctk3


  def ols_login2(self):
    payload = {
      'cb': 'https://uat.starhub.com/content/starhub/en/dev/login/auth.html?back64={0}&olsBack=true&back='.format(base64.b64encode('https://uat.starhub.com/content/starhub/en/personal/store/mobile/browse.html')),
      'cberr': 'https://login.dev.starhubgee.com.sg/sso/HubidLogin?view=mobile&txnid={0}'.format(self.txnid),
      'form_fake_uid': self.hub_id,
      'password': self.password,
      'checker': 'on',
      'view': 'mobile',
      'txnid': self.txnid,
      'CsrfSnKey': None,
      'vcid': 'icare',
      'uid': '{0}@uuid'.format(self.hub_id),
      'domain': 'uuid'
    }
    #payload = json.dumps(payload)
    resp = self.session.post(self.ols_login2_url, data=payload, headers=self.headers_login2, proxies=self.proxies)
      
    if self.verbose:
      req_obj = resp.request
      print('{0}\n{1}\n{2}\n\n{3}\n{4}'.format(
            '\n-----------raw HTTP request-----------',
            req_obj.method + ' ' + req_obj.url,
            '\n'.join('{0}: {1}'.format(k, v) for k, v in req_obj.headers.items()),
            req_obj.body,
            '-----------raw HTTP request ends------\n'))

    print(resp.text)
    if resp.status_code != 200:
      if self.verbose:
        print('esso login failed')
      return None, None
    acvctk = self.acvctk_obj.match(resp.url).group(1)
    vctk3 = self.vctk3_obj.match(str(resp.content.decode()).replace('\n', ''))
    if not vctk3:
      if self.verbose:
        print('esso login failed')
      return None, None
    else:
      vctk3 = vctk3.group(1)
    if self.verbose:
      print('vctk3: {0}; acvctk: {1}'.format(vctk3, acvctk))

    return vctk3, acvctk


  def login_status(self, acvctk):
    resp = self.session.get(self.status_url, headers=self.headers_login2)
    if resp.status_code != 200:
      return None
    return resp.text


  # SMB OLS login
  def eid_login(self):
    # step 1: submit esso loginform
    payload = {
      'USER': self.hub_id,
      'PASSWORD': self.password,
      'SMQUERYDATA': self.smQueryData_unquote,
      'Submit': 'Submit'
    }
    params = {'SMQUERYDATA': self.smQueryData_unquote}

    resp = self.session.post(self.eid_login_url, data=payload, params=params, headers=self.headers_eid, proxies=self.proxies, allow_redirects=False)
    if self.verbose:
      req = requests.Request('POST', self.eid_login_url, data=payload, params=params, headers=self.headers_eid)
      prepared = req.prepare()
      print('{}\n{}\n{}\n\n{}\n{}'.format(
            '\n-----------raw HTTP request-----------',
            prepared.method + ' ' + prepared.url,
            '\n'.join('{}: {}'.format(k, v) for k, v in prepared.headers.items()),
            prepared.body,
            '-----------raw HTTP request ends------\n'))

    if resp.status_code == 302:
      smsession = self.session.cookies.get_dict().get('SMSESSION')
    else:
      if self.verbose:
        print('Failed login')
      return None
    if self.verbose:
      print('\nlogin succeeded for user: {0}'.format(self.hub_id))
      print('Response ststus_code: {0}'.format(resp.status_code))
      print('SMSESSION: {0}\n'.format(smsession))

    # step 2: get session id
    resp = self.session.get(self.eid_session_id_url, headers=self.headers_eid_cb, proxies=self.proxies)

    if self.verbose:
      req_obj = resp.request
      print('{0}\n{1}\n{2}\n\n{3}\n{4}'.format(
            '\n-----------raw HTTP request-----------',
            req_obj.method + ' ' + req_obj.url,
            '\n'.join('{0}: {1}'.format(k, v) for k, v in req_obj.headers.items()),
            req_obj.body,
            '-----------raw HTTP request ends------\n'))

    ret = {}
    for line in resp.text.split('\n'):
      if self.sm_serversessionid_obj.match(line):
        ret['SM_SERVERSESSIONID'] = self.sm_serversessionid_obj.match(line).group(1)
      elif self.eid_brn_list_obj.match(line):
        ret['EID_BRN_LIST'] = self.eid_brn_list_obj.match(line).group(1).split(',')

    if self.verbose:
      print('\nResponse ststus_code: {0}'.format(resp.status_code))
      print('Response: {0}'.format(resp.text))
      print('\n==> SM_SERVERSESSIONID: {0}; EID_BRN_LIST: {1}\n'.format(ret.get('SM_SERVERSESSIONID'), ret.get('EID_BRN_LIST')))

    return ret



if __name__ == '__main__':
  hub_id = raw_input('please enter your login id:')
  password = raw_input('please enter your password:')

  login = login(hub_id, password, verbose=True)
  login.eid_login()

#  acvctk = None
#  login = login(hub_id, password, verbose=True)
#  #vctk3 = login.ols_login()
#  vctk3, acvctk = login.ols_login2()
#
#  print(vctk3)
#  if acvctk:
#    status = login.login_status(acvctk)
#    print(status)
