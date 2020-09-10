#!/usr/bin/python2.7 -tt

# AUTHOR:       Gu Jian Min
# DATE:         05/03/2020
# PROGRAM:      new_comm_req.py
# PURPOSE:
#               create a generic class to handle HTTP request and log statistics..
#
# HISTORY:
#       version 1.0     05/03/2020              --- program initial

import sys
import os
import time
import requests
import json

class Stats(object):
  '''
  provide method to dump statistics into log file.
  method show_stats accepts three addtional params to be logged together with statistics: TC - Test case id; INPUT - TC's input params; a_p - additional params
  '''
  log = None
  url_root = None

  @classmethod
  def show_stats(cls, func):
    def wrapper_func(*args, **kwargs):
      start = time.time()
      start_str = time.strftime("%H:%M:%S.{}".format(int(start*1000)%1000), time.localtime(start))
      resp = func(*args, **kwargs)
      end = time.time()
      end_str = time.strftime("%H:%M:%S.{}".format(int(end*1000)%1000), time.localtime(end))
      dur = '{0:.3f}'.format(end-start)
      TC = kwargs.get("TC", "")
      input_str = kwargs.get("INPUT", "")
      a_p = kwargs.get("A_P", "")
      if Stats.log:
        Stats.log.debug('{0},{1},{2},{3},{4},{5},{6},{7},--{8}'.format(start_str, end_str, dur, len(resp.content), resp.status_code, TC, a_p, resp.request.url.replace(Stats.url_root, ""), input_str.replace(",", ";")))
      return resp
    return wrapper_func

  @classmethod
  def stats(cls):
    def foo(func):
      return Stats.show_stats(func)
    return foo


class Comm_req(object):
  '''
  communication class used to send requests to server, augmented with logs and stats. 
  '''
  def __init__(self, log, url_root, proxies=None, cookies=None, verify=True):
    Stats.log = log
    Stats.url_root = url_root
    self._url_root = url_root
    self.proxies = proxies
    self._cookies = cookies
    self.verify = verify
    self.session = requests.Session()
    self.request = {"GET": self.session.get, "POST": self.session.post, "PUT": self.session.put, "DELETE": self.session.delete, "OPTIONS": self.session.options}


  @property
  def cookies(self):
    return self._cookies

  @cookies.setter
  def cookies(self, val):
    self._cookies = val

  @property
  def url_root(self):
    return self._url_root

  @url_root.setter
  def url_root(self, val):
    self._url_rool = val
    Stats.url_root = val

  @Stats.stats()
  def submit_req(self, uri, method, headers, **kw):
    request = self.request.get(method)
    url = self._url_root + uri
    data = json.dumps(kw.get('data')) if isinstance(kw.get('data'), dict) else kw.get('data')
    res = request(url, headers=headers, data=data, params=kw.get('params'), files=kw.get('files'), proxies=self.proxies, cookies=self._cookies, verify=self.verify)
    return res


class Comm_req2(object):
  '''
  class Comm_req2 is similar to class Comm_req, except for log and stats.
  '''
  def __init__(self, url_root, proxies=None, cookies=None, verify=True):
    self._url_root = url_root
    self.proxies = proxies
    self._cookies = cookies
    self.verify = verify
    self.session = requests.Session()
    self.request = {"GET": self.session.get, "POST": self.session.post, "PUT": self.session.put, "DELETE": self.session.delete, "OPTIONS": self.session.options}

  @property
  def cookies(self):
    return self._cookies

  @cookies.setter
  def cookies(self, val):
    self._cookies = val

  @property
  def url_root(self):
    return self._url_root

  @url_root.setter
  def url_root(self, val):
    self._url_rool = val

  def submit_req(self, uri, method, headers, **kw):
    request = self.request.get(method)
    url = self._url_root + uri
    data = json.dumps(kw.get('data')) if isinstance(kw.get('data'), dict) else kw.get('data')
    res = request(url, data=data, params=kw.get('params'), files=kw.get('files'), headers=headers, proxies=self.proxies, cookies=self._cookies, verify=self.verify)
    return res
