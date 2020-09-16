#!/usr/bin/python2.7 -tt

# AUTHOR:       Gu Jian Min
# DATE:         19/12/2018
# PROGRAM:      stats.py
# PURPOSE:
#
# HISTORY:
#       version 1.0     19/12/2018              --- program initial
#       version 1.1     18/01/2019              --- treated response status_code 304 as pass
#

import sys
import os
from datetime import datetime
import getopt
import csv
import numpy as np
import pandas as pd

# global variables
version = 'v1.1'


def usage(arg):
  out_string = '''
Statistics analysis of performance testing results.

Usage 1: {0} -f in_file -s sce_id params
Usage 2: {0} -S

where
         -S: a flag instructing program to list the supported scenarios.
         -f: specify hereafter input file from where to conduct statistics analysis
    in_file: an input file name, usually it is performance testing log file name.
         -s: a flag instructing program to execute s scenario given by hereafter sce_id.
     params: list of parameters in the context of scenario, run program with -S option to see supported scenarios and respective parameters.

Note:

'''.format(arg)
  print(out_string)

# dump scenarios' descriptions
def dump_sce():
  out_string = '''
  TC 100: general performance test statistics, segregating by TC.
          Params required: 1) percentile e.g. 95 (optional) default to 90; 2) filter out Thread id list, e.g. T01:T03:T07, see Note [1].
          Note: [1] if filter criteria specified, the transactions meet filter criteria will be excluded from statistics report.

  TC 101: general performance test statistics, segregating by threads and TC.
          Params required: 1) percentile e.g. 95 (optional) default to 90

  TC 102: general performance test statistics, segregating by threads, TC and additional param.
          Params required: 1) percentile e.g. 95 (optional) default to 90

  TC 103: general performance test statistics, segregating by resource URL.
          Params required: 1) percentile e.g. 95 (optional) default to 90

  TC 104: general performance test statistics, segregating by resource URL and appitional param.
          Params required: 1) percentile e.g. 95 (optional) default to 90

'''
  print(out_string)

def stats_100(param_list, in_file):
  filter_list = []
  percentile = 90

  if len(param_list) > 0 and param_list[0].isdigit(): 
    percentile = int(param_list[0])

  if len(param_list) > 1:
    filter_list = param_list[1].split(":") 

  #f = lambda x: float(datetime.strptime(x, '%H:%M:%S.%f').strftime("%s.%f"))
  names = ["THREAD", "S_TIME", "E_TIME", "DUR", "BANDWIDTH", "STA_CODE", "API"]
  columns = ["THREAD", "S_TIME", "E_TIME", "DUR", "BANDWIDTH", "STA_CODE", "API"]
  df = pd.read_csv(in_file, header=None, names=names, usecols=columns, parse_dates=["S_TIME", "E_TIME"])

  if len(filter_list) > 0:
    df = df.loc[~df["THREAD"].isin(filter_list)]

  df["STA_CODE"] = df.apply(lambda row: 1 if row["STA_CODE"] <= 202 or row["STA_CODE"] == 304 else 0, axis=1)

  df1 = pd.pivot_table(df, index=["API"], values=["DUR", "S_TIME", "E_TIME", "STA_CODE"],
                       aggfunc={"DUR":[np.min, np.max, np.mean, np.std, lambda x: np.percentile(x, percentile)],
                                "STA_CODE": [np.sum, 'count'], "S_TIME": [np.min], "E_TIME": [np.max]})

  df1["TPS"] = df1.apply(lambda row: row[("STA_CODE", "count")] / (row[("E_TIME", "amax")] - row[("S_TIME", "amin")]).total_seconds(), axis=1)
  df1.drop([("E_TIME", "amax"), ("S_TIME", "amin")], axis=1, inplace=True)

  #print(df1.columns.tolist())
  #print(df1.head())

  # general summy
  start_time = df["S_TIME"].min().strftime('%H:%M:%S')
  end_time = df["E_TIME"].max().strftime('%H:%M:%S')
  dur = int((df["E_TIME"].max() - df["S_TIME"].min()).total_seconds())
  throughput = df["BANDWIDTH"].sum()
  tps = df1["TPS"].sum()
  threads = len(df["THREAD"].unique())

  # dropping pivot table index, rename the columns and followed by re-ordering the columns
  df1.reset_index(inplace=True)
  df1.columns = ["API", "{0} Percentile".format(str(percentile)), "Max.(sec.)",
                 "Min.(sec.)", "Ave.(sec.)", "Std. Dev.", "Fail", "Pass", "TPS"]
  df1 = df1.reindex(columns=["API", "Min.(sec.)", "Max.(sec.)", "Ave.(sec.)",
                             "Std. Dev.", "{0} Percentile".format(str(percentile)), "Pass", "Fail", "TPS"])
  df1["Fail"] = df1.apply(lambda row: row["Fail"] - row["Pass"], axis=1)
  df1 = df1.round(3) # round to 3 decimal places.

  print("\n,,Start Time,End Time,Duration in sec.,Throughput (MB),TPS (total),,Multi Threads,Pacing Time (sec.)")
  print(",,{0},{1},{2},{3},{4:.3f},,{5}\n\n".format(start_time, end_time, dur, throughput/1000000, tps, threads))

  print(df1.to_csv(sep=",", index=False, encoding="utf-8"))


def stats_101(param_list, in_file):
  if len(param_list) > 0: 
    percentile = int(param_list[0])
  else:
    percentile = 90

  names = ["THREAD", "S_TIME", "E_TIME", "DUR", "BANDWIDTH", "STA_CODE", "API"]
  columns = ["THREAD", "S_TIME", "E_TIME", "DUR", "BANDWIDTH", "STA_CODE", "API"]
  df = pd.read_csv(in_file, header=None, names=names, usecols=columns, parse_dates=["S_TIME", "E_TIME"])

  df["STA_CODE"] = df.apply(lambda row: 1 if row["STA_CODE"] <= 202 or row["STA_CODE"] == 304 else 0, axis=1)

  df1 = pd.pivot_table(df,index=["THREAD", "API"], values=["DUR", "S_TIME", "E_TIME", "STA_CODE"],
                       aggfunc={"DUR":[np.min, np.max, np.mean, np.std, lambda x: np.percentile(x, percentile)],
                                "STA_CODE": [np.sum, 'count'], "S_TIME": [np.min], "E_TIME": [np.max]})
  #print(df1.columns.tolist())
  #print(df1.head())

  df1["TPS"] = df1.apply(lambda row: row[("STA_CODE", "count")] / (row[("E_TIME", "amax")] - row[("S_TIME", "amin")]).total_seconds(), axis=1)
  df1.drop([("E_TIME", "amax"), ("S_TIME", "amin")], axis=1, inplace=True)


  # general summy
  start_time = df["S_TIME"].min().strftime('%H:%M:%S')
  end_time = df["E_TIME"].max().strftime('%H:%M:%S')
  dur = int((df["E_TIME"].max() - df["S_TIME"].min()).total_seconds())
  throughput = df["BANDWIDTH"].sum()
  tps = df1["TPS"].sum()
  threads = len(df["THREAD"].unique())


  # dropping pivot table index, rename the columns and followed by reordering the columns
  df1.reset_index(inplace=True)
  df1.columns = ["Thread", "API", "{0} Percentile".format(str(percentile)), "Max.(sec.)",
                 "Min.(sec.)", "Ave.(sec.)", "Std. Dev.", "Fail", "Pass", "TPS"]
  df1 = df1.reindex(columns=["Thread", "API", "Min.(sec.)", "Max.(sec.)", "Ave.(sec.)",
                             "Std. Dev.", "{0} Percentile".format(str(percentile)), "Pass", "Fail", "TPS"])
  df1["Fail"] = df1.apply(lambda row: row["Fail"] - row["Pass"], axis=1)
  df1 = df1.round(3)

  print("\n,,Start Time,End Time,Duration in sec.,Throughput (MB),TPS (total),,Multi Threads,Pacing Time (sec.)")
  print(",,{0},{1},{2},{3},{4:.3f},,{5}\n\n".format(start_time, end_time, dur, throughput/1000000, tps, threads))

  print(df1.to_csv(sep=",", index=False, encoding="utf-8"))

def stats_102(param_list, in_file):
  if len(param_list) > 0: 
    percentile = int(param_list[0])
  else:
    percentile = 90

  names = ["THREAD", "S_TIME", "E_TIME", "DUR", "BANDWIDTH", "STA_CODE", "API", "AP", "URL", "PARAM"]
  columns = ["THREAD", "S_TIME", "E_TIME", "DUR", "BANDWIDTH", "STA_CODE", "API", "AP"]
  df = pd.read_csv(in_file, header=None, names=names, usecols=columns, parse_dates=["S_TIME", "E_TIME"])

  df["STA_CODE"] = df.apply(lambda row: 1 if row["STA_CODE"] <= 202 or row["STA_CODE"] == 304 else 0, axis=1)

  df1 = pd.pivot_table(df,index=["THREAD", "API", "AP"], values=["DUR", "S_TIME", "E_TIME", "STA_CODE"],
                       aggfunc={"DUR":[np.min, np.max, np.mean, np.std, lambda x: np.percentile(x, percentile)],
                                "STA_CODE": [np.sum, 'count'], "S_TIME": [np.min], "E_TIME": [np.max]})
  #print(df1.columns.tolist())
  #print(df1.head())

  # [('E_TIME', 'amax'), ('DUR', '<lambda>'), ('DUR', 'amax'), ('DUR', 'amin'), ('DUR', 'mean'), ('DUR', 'std'), ('STA_CODE', 'count'), ('STA_CODE', 'sum'), ('S_TIME', 'amin')]
  df1["TPS"] = df1.apply(lambda row: row[("STA_CODE", "count")] / (row[("E_TIME", "amax")] - row[("S_TIME", "amin")]).total_seconds(), axis=1)
  df1.drop([("E_TIME", "amax"), ("S_TIME", "amin")], axis=1, inplace=True)


  # general summy
  start_time = df["S_TIME"].min().strftime('%H:%M:%S')
  end_time = df["E_TIME"].max().strftime('%H:%M:%S')
  dur = int((df["E_TIME"].max() - df["S_TIME"].min()).total_seconds())
  throughput = df["BANDWIDTH"].sum()
  tps = df1["TPS"].sum()
  threads = len(df["THREAD"].unique())

  # dropping pivot table index, rename the columns and followed by reordering the columns
  df1.reset_index(inplace=True)
  df1.columns = ["Thread", "API", "AP", "{0} Percentile".format(str(percentile)), "Max.(sec.)",
                 "Min.(sec.)", "Ave.(sec.)", "Std. Dev.", "Fail", "Pass", "TPS"]
  df1 = df1.reindex(columns=["Thread", "API", "AP", "Min.(sec.)", "Max.(sec.)", "Ave.(sec.)",
                             "Std. Dev.", "{0} Percentile".format(str(percentile)), "Pass", "Fail", "TPS"])
  df1["Fail"] = df1.apply(lambda row: row["Fail"] - row["Pass"], axis=1)
  df1 = df1.round(3)

  print("\n,,Start Time,End Time,Duration in sec.,Throughput (MB),TPS (total),,Multi Threads,Pacing Time (sec.)")
  print(",,{0},{1},{2},{3},{4:.3f},,{5}\n\n".format(start_time, end_time, dur, throughput/1000000, tps, threads))

  print(df1.to_csv(sep=",", index=False, encoding="utf-8"))

def stats_103(param_list, in_file):
  filter_list = []
  percentile = 90

  if len(param_list) > 0 and param_list[0].isdigit(): 
    percentile = int(param_list[0])

  if len(param_list) > 1:
    filter_list = param_list[1].split(":") 

  #f = lambda x: float(datetime.strptime(x, '%H:%M:%S.%f').strftime("%s.%f"))
  names = ["THREAD", "S_TIME", "E_TIME", "DUR", "BANDWIDTH", "STA_CODE", "API", "AP", "URL", "PARAM"]
  columns = ["THREAD", "S_TIME", "E_TIME", "DUR", "BANDWIDTH", "STA_CODE", "URL"]
  df = pd.read_csv(in_file, header=None, names=names, usecols=columns, parse_dates=["S_TIME", "E_TIME"])

  if len(filter_list) > 0:
    df = df.loc[~df["THREAD"].isin(filter_list)]

  df["STA_CODE"] = df.apply(lambda row: 1 if row["STA_CODE"] <= 202 or row["STA_CODE"] == 304 else 0, axis=1)

  df1 = pd.pivot_table(df, index=["URL"], values=["DUR", "S_TIME", "E_TIME", "STA_CODE"],
                       aggfunc={"DUR":[np.min, np.max, np.mean, np.std, lambda x: np.percentile(x, percentile)],
                                "STA_CODE": [np.sum, 'count'], "S_TIME": [np.min], "E_TIME": [np.max]})

  df1["TPS"] = df1.apply(lambda row: row[("STA_CODE", "count")] / (row[("E_TIME", "amax")] - row[("S_TIME", "amin")]).total_seconds(), axis=1)
  df1.drop([("E_TIME", "amax"), ("S_TIME", "amin")], axis=1, inplace=True)

  #print(df1.columns.tolist())
  #print(df1.head())

  # general summy
  start_time = df["S_TIME"].min().strftime('%H:%M:%S')
  end_time = df["E_TIME"].max().strftime('%H:%M:%S')
  dur = int((df["E_TIME"].max() - df["S_TIME"].min()).total_seconds())
  throughput = df["BANDWIDTH"].sum()
  tps = df1["TPS"].sum()
  threads = len(df["THREAD"].unique())

  # dropping pivot table index, rename the columns and followed by re-ordering the columns
  df1.reset_index(inplace=True)
  df1.columns = ["URL", "{0} Percentile".format(str(percentile)), "Max.(sec.)",
                 "Min.(sec.)", "Ave.(sec.)", "Std. Dev.", "Fail", "Pass", "TPS"]
  df1 = df1.reindex(columns=["URL", "Min.(sec.)", "Max.(sec.)", "Ave.(sec.)",
                             "Std. Dev.", "{0} Percentile".format(str(percentile)), "Pass", "Fail", "TPS"])
  df1["Fail"] = df1.apply(lambda row: row["Fail"] - row["Pass"], axis=1)
  df1 = df1.round(3) # round to 3 decimal places.

  print("\n,,Start Time,End Time,Duration in sec.,Throughput (MB),TPS (total),,Multi Threads,Pacing Time (sec.)")
  print(",,{0},{1},{2},{3},{4:.3f},,{5}\n\n".format(start_time, end_time, dur, throughput/1000000, tps, threads))

  print(df1.to_csv(sep=",", index=False, encoding="utf-8"))


def stats_104(param_list, in_file):
  filter_list = []
  percentile = 90

  if len(param_list) > 0 and param_list[0].isdigit(): 
    percentile = int(param_list[0])

  if len(param_list) > 1:
    filter_list = param_list[1].split(":") 

  #f = lambda x: float(datetime.strptime(x, '%H:%M:%S.%f').strftime("%s.%f"))
  names = ["THREAD", "S_TIME", "E_TIME", "DUR", "BANDWIDTH", "STA_CODE", "API", "AP", "URL", "PARAMS"]
  columns = ["THREAD", "S_TIME", "E_TIME", "DUR", "BANDWIDTH", "STA_CODE", "URL", "AP"]
  df = pd.read_csv(in_file, header=None, names=names, usecols=columns, parse_dates=["S_TIME", "E_TIME"])

  if len(filter_list) > 0:
    df = df.loc[~df["THREAD"].isin(filter_list)]

  ok_set = (0, 200, 201, 202, 304)
  #df["STA_CODE"] = df.apply(lambda row: 1 if row["STA_CODE"] <= 202 or row["STA_CODE"] == 304 else 0, axis=1)
  df["STA_CODE"] = df.apply(lambda row: 1 if row["STA_CODE"] in ok_set else 0, axis=1)

  df1 = pd.pivot_table(df, index=["URL", "AP"], values=["DUR", "S_TIME", "E_TIME", "STA_CODE"],
                       aggfunc={"DUR":[np.min, np.max, np.mean, np.std, lambda x: np.percentile(x, percentile)],
                                "STA_CODE": [np.sum, 'count'], "S_TIME": [np.min], "E_TIME": [np.max]})

  #print(df1.columns.tolist())
  #print(df1.head())
  
  df1["TPS"] = df1.apply(lambda row: row[("STA_CODE", "count")] / (row[("E_TIME", "amax")] - row[("S_TIME", "amin")]).total_seconds(), axis=1)
  df1.drop([("E_TIME", "amax"), ("S_TIME", "amin")], axis=1, inplace=True)

  #print(df1.columns.tolist())
  #print(df1.head())

  # general summy
  start_time = df["S_TIME"].min().strftime('%H:%M:%S')
  end_time = df["E_TIME"].max().strftime('%H:%M:%S')
  dur = int((df["E_TIME"].max() - df["S_TIME"].min()).total_seconds())
  throughput = df["BANDWIDTH"].sum()
  tps = df1["TPS"].sum()
  threads = len(df["THREAD"].unique())

  # dropping pivot table index, rename the columns and followed by re-ordering the columns
  df1.reset_index(inplace=True)
  df1.columns = ["URL", "AP", "{0} Percentile".format(str(percentile)), "Max.(sec.)",
                 "Min.(sec.)", "Ave.(sec.)", "Std. Dev.", "Fail", "Pass", "TPS"]
  df1 = df1.reindex(columns=["URL", "AP", "Min.(sec.)", "Max.(sec.)", "Ave.(sec.)",
                             "Std. Dev.", "{0} Percentile".format(str(percentile)), "Pass", "Fail", "TPS"])
  df1["Fail"] = df1.apply(lambda row: row["Fail"] - row["Pass"], axis=1)
  df1 = df1.round(3) # round to 3 decimal places.

  print("\n,,Start Time,End Time,Duration in sec.,Throughput (MB),TPS (total),,Multi Threads,Pacing Time (sec.)")
  print(",,{0},{1},{2},{3},{4:.3f},,{5}\n\n".format(start_time, end_time, dur, throughput/1000000, tps, threads))

  print(df1.to_csv(sep=",", index=False, encoding="utf-8"))


def stats_explore(param_list, in_file):
  filter_list = []
  percentile = 90

  if len(param_list) > 0 and param_list[0].isdigit(): 
    percentile = int(param_list[0])

  if len(param_list) > 1:
    filter_list = param_list[1].split(":") 

  names = ["THREAD", "S_TIME", "E_TIME", "DUR", "BANDWIDTH", "STA_CODE", "API", "PARAMS", "URL"]
  df = pd.read_csv(in_file, header=None, names=names, parse_dates=["S_TIME", "E_TIME"])

  if len(filter_list) > 0:
    df = df.loc[~df["THREAD"].isin(filter_list)]

  df["STA_CODE"] = df.apply(lambda row: 1 if row["STA_CODE"] <= 202 or row["STA_CODE"] == 304 else 0, axis=1)

  df1 = pd.pivot_table(df, index=["API"], values=["DUR", "S_TIME", "E_TIME", "STA_CODE"],
                       aggfunc={"DUR":[np.min, np.max, np.mean, np.std, lambda x: np.percentile(x, percentile)],
                                "STA_CODE": [np.sum, 'count'], "S_TIME": [np.min], "E_TIME": [np.max]})

  df1["TPS"] = df1.apply(lambda row: row[("STA_CODE", "count")] / (row[("E_TIME", "amax")] - row[("S_TIME", "amin")]).total_seconds(), axis=1)
  #df1["TPS"] = df1[("STA_CODE", "count")] / pd.to_numeric(df1[("E_TIME", "amax")] - df1[("S_TIME", "amin")])*1000000000
  df1.drop([("E_TIME", "amax"), ("S_TIME", "amin")], axis=1, inplace=True)

  #print(df1.columns.tolist())
  #print(df1.head())

  # high level summy
  start_time = df["S_TIME"].min().strftime('%H:%M:%S')
  end_time = df["E_TIME"].max().strftime('%H:%M:%S')
  dur = int((df["E_TIME"].max() - df["S_TIME"].min()).total_seconds())
  throughput = df["BANDWIDTH"].sum()
  tps = df1["TPS"].sum()
  threads = len(df["THREAD"].unique())

  #print('\nStart Time: {0}'.format(start_time))
  #print('End Time: {0}'.format(end_time))
  #print('Duration: {0} in sec.'.format(dur))
  #print('Throughput: {0}(MB)'.format(throughput/1000000))
  #print('Multi Threads: {0}'.format(threads))
  #print("TPS (total): {0:.3f}\n".format(tps))

  # dropping pivot table index, rename the columns and followed by reordering the columns
  df1.reset_index(inplace=True)
  df1.columns = ["API", "{0} Percentile".format(str(percentile)), "Max.(sec.)",
                 "Min.(sec.)", "Ave.(sec.)", "Std. Dev.", "Fail", "Pass", "TPS"]
  df1 = df1.reindex(columns=["API", "Min.(sec.)", "Max.(sec.)", "Ave.(sec.)",
                             "Std. Dev.", "{0} Percentile".format(str(percentile)), "Pass", "Fail", "TPS"])
  df1["Fail"] = df1.apply(lambda row: row["Fail"] - row["Pass"], axis=1)
  df1 = df1.round(3)

  print("\n,,Start Time,End Time,Duration in sec.,Throughput (bytes),TPS (total),,Multi Threads,Pacing Time (sec.)")
  print(",,{0},{1},{2},{3},{4:.3f},,{5}\n\n".format(start_time, end_time, dur, throughput/1000000, tps, threads))

  print(df1.to_csv(sep=",", index=False, encoding="utf-8"))


# search and dispatch to respective handlers
def dispatcher(arg):
    switcher = {
        '100': stats_100,
        '101': stats_101,
        '102': stats_102,
        '103': stats_103,
        '104': stats_104,
        '999': stats_explore,
    }
    handler_name = switcher.get(arg)
    return handler_name


# Define a main() function
def main():
  ###############################
  S_flag = False
  fn = None
 
  if len(sys.argv) == 1:
    usage(os.path.basename(sys.argv[0]))
    sys.exit(0)

  # parse command line options
  try:
    opts, args = getopt.getopt(sys.argv[1:], "f:s:S")
  except getopt.GetoptError as err:
    # print help information and exit:
    logger.error(err)
    usage(os.path.basename(sys.argv[0]))
    sys.exit(2)
  for o, a in opts:
    if o == "-f":
      if os.path.isfile(a):
        fn = a  # input file name
      else:
        print("File: {} doesn't exist.".format(a))
        sys.exit(2)
    elif o == "-s":
      s_flag = True
      sce_id = a
      param_list = args[0:]
    elif o == "-S":
      S_flag = True
    else:
      assert False, "unhandled option"
      sys.exit(1)

  if S_flag:
    dump_sce()
    sys.exit()

  if s_flag:
    # call dispatcher to get respective handler
    handler = dispatcher(sce_id)
    handler(param_list, fn)

# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
  main()
