#!/usr/bin/python

import argparse
import smtplib
from email.mime.text import MIMEText
import logging
import os
import csv
import socket
import subprocess
import sys
import traceback
import ConfigParser
from logging.handlers import TimedRotatingFileHandler
from logging.handlers import SysLogHandler 
from logging.handlers import SMTPHandler
from datetime import datetime
from pprint import pprint

def send_email(email_subj, email_dest, body):
  global smtp_server

  msg = MIMEText(str(body))

  msg['Subject'] = email_subj
  msg['From'] = email_dest
  msg['To'] = email_dest

  s = smtplib.SMTP(smtp_server)

  # IT mail server will set from as noreply@salesforce.com
  s.sendmail(email_dest, email_dest,msg.as_string())

cfg = None
mfg = None
cp = None
log = logging.getLogger('pre-config')
base_config = {}
base_section_list = ['base','alert','email','syslog destination','monitor']
monitor_file = None
threshold = None
throttle_time = None

dateformat = '%m-%d-%YT%H:%M:%S.%f'
threshold_default = 5
throttle_default = 60*60

def config_dump(cg):
  for s in cg.sections():
    print 'section: %s' % s
    for o in cg.options(s):
      print '\t%s => %s' % (o, cg.get(s,o))

''' init loggers
1) file
2) email 
3) syslog for log aggregation
'''
def init_handlers():
  global log

  # for local file logging
  log_header = base_config['base']['log_header']
  log_folder = base_config['base']['folder']
  log_name = base_config['base']['log_name']

  # validate path exists
  if log_folder and os.path.exists(log_folder):
    file_name = os.path.join(log_folder, log_name)
  else:
    file_name = os.path.join(os.path.dirname(__file__), log_name)

  # for email
  email_dest = base_config['email']['email']
  email_subj = base_config['email']['subject']
  smtp_server = base_config['email']['smtp_server']

  # for syslog
  syslog_server = base_config['syslog destination']['syslog_server']
  syslog_port = int(base_config['syslog destination']['syslog_port'])

  # set up primary handler
  log = logging.getLogger(log_header)
  log.setLevel(logging.DEBUG)

  # log to file
  fh = TimedRotatingFileHandler(file_name, when='d', interval=4, backupCount=14)
  fh.setLevel(logging.DEBUG)
  fhformat = logging.Formatter('%(asctime)s %(name)s[%(process)d]: log_level=%(levelname)s function=%(funcName)s message="%(message)s"',
                                datefmt='%m/%d/%YT%H:%M:%S%z')
  fh.setFormatter(fhformat)

  # email
  # IT SMTP servers will mask email sender as 'noreply@salesforce.com'
  eh = SMTPHandler(mailhost=smtp_server,
                    fromaddr=email_dest,
                    toaddrs=email_dest,
                    subject=email_subj)
  eh.setLevel(logging.INFO)

  # syslog
  sh = logging.handlers.SysLogHandler(address=(syslog_server, syslog_port), facility=logging.handlers.SysLogHandler.LOG_NOTICE)
  sh.setLevel(logging.INFO)
  sysformat = logging.Formatter('%(name)s[%(process)d]: %(message)s', datefmt='%m/%d/%YT%H:%M:%S%z')
  sh.setFormatter(sysformat)

  #sh.createLock()

  log.addHandler(fh)
  log.addHandler(eh)
  log.addHandler(sh)


def init_alert():
  global threshold, throttle_time

  throttle_str = base_config['alert'].get('throttle')
  threshold_str = base_config['alert'].get('threshold')

  # hourly in seconds
  if throttle_str == 'hourly':
    throttle_time = 60*60
  else:
    log.error('unknown throttle value: %s; setting to default' % throttle_str)
    throttle_time = 60*60

  # set threshold for minimum to trigger alert
  try:
    threshold = int(threshold_str)
  except:
    # threshold default
    threshold = threshold_default

def init_config(cfg_filename):
  global cfg
  try:
    cfg = ConfigParser.SafeConfigParser()
    cp = cfg.read(cfg_filename)

    # validate the sections we need
    for i in base_section_list:
      if i not in cfg.sections():
        print 'section %s not found in settings?!' % i
        raise
      if not cfg.options(i):
        print 'section %s has no options?!' % i
        raise

      # add values
      base_config[i] = {}
      for j in cfg.options(i):
        base_config[i][j] = cfg.get(i,j)
    
    init_handlers()
    init_alert()
  except Exception, e:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    print 'ERROR: read failed: %r\ntraceback: %r' \
      % (repr(e), repr(traceback.format_exception(exc_type, exc_value, exc_traceback)))

def getIP(host):
  try:
    ip = socket.gethostbyname(host)
    return ip
  except socket.error:
    return 0

''' check monitor status for host
    if this is triggered, then either update monitor entry

    input: host, curr timestamp
    output: if anything to alert, return alert str

    alert only if:
      counter > threshold (don't want to email for every single outage; we check every 5min anyways)
      only once within an hour

    latest => time of last alert
    counter => # times cannot connect to host (within hour)

    update:
    if curr timestamp within 60min of earliest:
      counter++
      if counter == threshold:
        alert
        set latest = curr
    if curr timestamp > 60min of earliest (outside of timewindow):
      reset counter = 1
      reset latest = empty
      if counter < threshold (never hit threshold, simply reset all):
        reset earliest = curr timestamp
      if counter == threshold (already alerted, reset to alert timestamp):
        reset earliest = latest timestamp

'''
def check_monitor_status(host, time_str):
  try:
    etime_str = mfg.get(host, 'earliest')
    ltime_str = mfg.get(host, 'latest')
    counter_str = mfg.get(host, 'counter')

    # convert from string
    time = datetime.strptime(time_str, dateformat)

    # no counter value set, init counter
    if not counter_str or not etime_str:
      mfg.set(host, 'counter', str(1))
      mfg.set(host, 'earliest', time.strftime(dateformat))
      mfg.set(host, 'latest', '')

      with open(monitor_file, 'wb') as mfg_filename:
        mfg.write(mfg_filename)

      return None

    if counter_str:
      try:
        counter = int(counter_str)
      except:
        log.error('invalid value for counter: %s' % counter_str)
    # default
    else:
      counter = 1

    # time formats may not match. if not, consider monitor status invalid and start over
    try:
      etime = datetime.strptime(etime_str, dateformat)
      #etime = datetime.strptime(etime_str, '%m/%d/%Y %H:%M:%S.%f')
    # not properly formatted
    except:
      etime = None 
    # time format for latest may not be set
    try:
      ltime = datetime.strptime(ltime_str, dateformat)
    except:
      ltime = None

    delta = None

    # only do a delta comparison if earliest time is set
    if etime:
      delta = time - etime

    # timedelta tuple format => days, seconds, microseconds
    if etime and delta.days == 0 and delta.seconds < throttle_time:
      counter = counter + 1

      mfg.set(host, 'latest', time.strftime(dateformat))
      mfg.set(host, 'counter', str(counter))

      log.info('updating for host %s earliest: %s latest: %s counter: %s' % 
        (host, mfg.get(host, 'earliest'), time.strftime(dateformat), str(counter)))

      # alert
      if counter == threshold:
        log.debug('alert threshold hit for host: %s counter: %s' % (str(host), str(counter)))
        return '%s cannot connect to host (%s)' % (time.strftime(dateformat), str(host))

    # if earliest time is not set properly, always presume new start
    else:
      # clear latest timestamp, counter
      mfg.set(host, 'latest', '')
      mfg.set(host, 'counter', str(1))

      # just in case, check delta for latest time as well
      # NOTICE: we're importing datetime from datetime (not root library)
      ldelta = time - ltime if (ltime and isinstance(ltime, datetime)) else None

      mfg.set(host, 'earliest', time.strftime(dateformat))
      
      if ldelta and ldelta.days == 0 and ldelta.seconds < throttle_time:
        mfg.set(host, 'earliest', ltime.strftime(dateformat))

      log.info('resetting for host %s earliest: %s latest: NULL counter: %s' % (host, time.strftime(dateformat), str(counter)))

  except Exception, e:
    log.error('Failed checking monitor status for host: %s' % host)
  finally:
    with open(monitor_file, 'wb') as mfg_filename:
      mfg.write(mfg_filename)
  

''' if monitor file does not exist:
      create file
      populate sections with the host names from list
      create empty earliest, latest timestamps and counter

    if monitor file exists:
      validate all host name sections are there
      check earliest, latest time stamps, counter cfg fields exist (not necc set)

    input: host_list = array of dict tuple: ip, collector (hostname)
'''
def validate_monitor(host_list):
  global mfg, monitor_file

  try:
    log_folder = base_config['base'].get('folder')
    monitor_file = base_config['monitor'].get('file')

    # validate path exists
    if log_folder and os.path.exists(log_folder):
      file_name = os.path.join(log_folder, monitor_file)
    else:
      file_name = os.path.join(os.path.dirname(__file__), monitor_file)

    # if file exists, we read file and check. if not, we create.
    if os.path.exists(file_name):
      file_exists = True
    else:
      file_exists = False

    mfg = ConfigParser.SafeConfigParser()

    # validate fields if file exists
    if file_exists:
      mp = mfg.read(file_name)

      for host_item in list(host_list):
        host = str(host_item['collector'])
        # populate with empty monitor fields
        if host not in mfg.sections():
          mfg.add_section(host)
          mfg.set(host, 'earliest', '')
          mfg.set(host, 'latest', '')
          mfg.set(host, 'counter', '')

        # if exists, check for fields present
        else:
          if not mfg.has_option(host, 'earliest'):
            mfg.set(host, 'earliest', '')
          if not mfg.has_option(host, 'latest'):
            mfg.set(host, 'latest', '')
          if not mfg.has_option(host, 'counter'):
            mfg.set(host, 'counter', '')

    # create from scratch
    else:
      for host_item in list(host_list):
        host = str(host_item['collector'])
        # populate with empty monitor fields
        mfg.add_section(host)
        mfg.set(host, 'earliest', '')
        mfg.set(host, 'latest', '')
        mfg.set(host, 'counter', '')

    with open(file_name, 'wb') as mfg_filename:
      mfg.write(mfg_filename)

    # save for future use
    monitor_file = file_name
  except Exception, e:
    log.error('monitor file check failed: %r' % repr(e))
    exc_type, exc_value, exc_traceback = sys.exc_info()
    print 'ERROR: read failed: %r\ntraceback: %r' \
      % (repr(e), repr(traceback.format_exception(exc_type, exc_value, exc_traceback)))

  return

def sendAlert(host_errors, warnings):
  error_count = len(host_errors)
  errors = list()
  warning_count = len(warnings)
  warning_body = ''

  if warning_count > 0:
    warning_body = 'Warnings:\n' + '\n'.join(warnings) + '\n\n'

  if error_count > 0:
    for e in host_errors:
      err = check_monitor_status(e['hostname'], e['date'])
      
      if err:
        errors.append(err)

  if len(errors) > 0:
    error_body = warning_body + 'Errors:\n' + '\n'.join(errors) + '\n\n\tTotal failed hosts: ' + str(error_count)
    log.error(error_body)
  elif warning_count > 0:
    log.info(warnings)


def sendHeartbeats(hosts):
  global log_header
  myhost = socket.gethostname()
  mydate = datetime.now().strftime(dateformat)
  host_errors = []
  warnings = []

  # create or update monitor file with hosts
  validate_monitor(hosts)

  for host in hosts:
    hostname = host['collector']
    ip = host['ip']

    try:
      attempt_date = datetime.now().strftime(dateformat)
      res = getIP(hostname)

      if ip != res:
        warnings.append('%s host (%s) ip mismatch from list:\n\t%s (from list) %s (resolved)' % (attempt_date, hostname, ip, res))

      # send over tcp to test connection and validate with a return code 
      # (b/c udp is connectionless, will always be successful)
      cmd = "/usr/bin/nc -w0 %s 514 <<< \"<46>%s %s %s: COLLECTOR HEARTBEAT TEST\"" % (hostname, mydate, myhost, log_header)

      try:        
        subprocess.check_call(cmd, shell=True)

      except subprocess.CalledProcessError, c:

        # return code non-zero, something is wrong
        if c.returncode > 0:
          # generate all possible connectivity errors then process alerts after
          host_errors.append({'date': attempt_date, 'hostname': hostname})

    except:
      host_errors.append({'date': attempt_date, 'hostname': hostname})

  # process alerts only after aggregating all errata
  sendAlert(host_errors, warnings)

def extractHosts():
  global log_header
  host_list = []
  try:
    if not cfg.has_option('base', 'host_list'):
      log.error('Monitor file setting not found. Validate settings for collector heartbeat.')
      raise

    log_header = base_config['base'].get('log_header')
    log_folder = base_config['base'].get('folder')
    log_name = base_config['base'].get('host_list')

    # validate path exists
    if log_folder and os.path.exists(log_folder):
      base_folder = log_folder
    # if not specified, check same folder as this file
    else:
      base_folder = os.path.dirname(__file__)

    file_name = os.path.join(base_folder, log_name)

    if not log_name:
      log.error('Host list file not specified; Validate file')
      raise

    if not os.path.exists(file_name):
      log.error('Host list file (%s) does not exist; Validate file.' % log_name)
      raise

    input_file = csv.DictReader(open(file_name))

    for row in input_file:
      host = {}
      host['collector'] = row['collector']
      host['ip'] = row['ip']
      
      host_list.append(host)

  except Exception, e:
    raise

  return host_list

def main ():
  try:
    start_time = datetime.now()
    parser = argparse.ArgumentParser(description='Generate heartbeat messages to syslog collectors',
      epilog = 'usage (with options): collector.heartbeat.py <file> ' \
                '[-smtp <>]')

    parser.add_argument('file', help='specify csv file of it log collectors')
    parser.add_argument('-smtp', '-s', help='specify smtp server')

    args = parser.parse_args()  

    log.debug('Initiating program at: %s' % start_time.strftime(dateformat))

    # set up log handlers
    init_config(args.file)

    # get list of hosts/ips
    host_list = extractHosts()

    if len(host_list) == 0:
      log.error('Read host list fail')
      raise

    sendHeartbeats(host_list)

  except Exception, e:
    log.error(repr(e),exc_info=1)

  finally:
      final_time = datetime.now()
      delta = final_time - start_time
      log.debug('Finalizing program at: %s\t# hosts: %i\tTotal duration: %s.%s sec' 
          % (final_time.strftime(dateformat), len(host_list), delta.seconds, delta.microseconds))

if __name__ == "__main__":
  main()
