#!/usr/bin/python

import argparse
import smtplib
from email.mime.text import MIMEText
import logging
import csv
import socket
import subprocess
from logging.handlers import TimedRotatingFileHandler
from logging.handlers import SysLogHandler 
from logging.handlers import SMTPHandler
from datetime import datetime

log_header = 'sfdc_collector_heartbeat'

file_name = 'sfdc.collector.heartbeat.log'

email_dest = 'hcanivel@salesforce.com'
email_subj = 'Validate: IT log collectors down'

smtp_server = 'mail.internal.salesforce.com'
syslog_server = 'sfm0sednrllp003'
syslog_port = 514

''' init loggers
1) file
2) email 
3) syslog for log aggregation
'''

log = logging.getLogger(log_header)
log.setLevel(logging.INFO)

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

log.addHandler(fh)
log.addHandler(eh)
log.addHandler(sh)

sh.createLock()

def send_email(email_subj, email_dest, body):
  global smtp_server

  msg = MIMEText(str(body))

  msg['Subject'] = email_subj
  msg['From'] = email_dest
  msg['To'] = email_dest

  s = smtplib.SMTP(smtp_server)

  # IT mail server will set from as noreply@salesforce.com
  s.sendmail(email_dest, email_dest,msg.as_string())

def getIP(host):
  try:
    ip = socket.gethostbyname(host)
    return ip
  except socket.error:
    return 0

def sendHeartbeats(hosts):
  myhost = socket.gethostname()
  mydate = datetime.now().strftime('%m-%d-%YT%H:%M:%S')
  errors = []
  warnings = []

  for host in hosts:
    hostname = host['collector']
    ip = host['ip']

    try:
      attempt_date = datetime.now().strftime('%m-%d-%YT%H:%M:%S')
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
          errors.append('%s cannot connect to host (%s)' % (attempt_date, hostname))

    except:
      errors.append('%s failed: %s' % (attempt_date, hostname))

  error_count = len(errors)
  warning_count = len(warnings)
  warning_body = ''

  if warning_count > 0:
    warning_body = 'Warnings:\n' + '\n'.join(warnings) + '\n\n'

  if error_count > 0:
    error_body = warning_body + 'Errors:\n' + '\n'.join(errors) + '\n\n\tTotal failed hosts: ' + str(error_count)
    log.error(error_body)
  elif warning_count > 0:
    log.error(warnings)


def extractHosts(file_name):
  host_list = []
  try:
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

    log.debug('Initiating program at: %s' % start_time.strftime('%m/%d/%Y %H:%M:%S.%f'))

    # get list of hosts/ips
    host_list = extractHosts(args.file)

    if len(host_list) == 0:
      log.error('Read host list fail')
      raise

    sendHeartbeats(host_list)

  except Exception, e:
    log.error(repr(e),exc_info=1)

  finally:
      final_time = datetime.now()
      delta = final_time - start_time
      log.debug('Finalizing program at: %s\tTotal duration: %s.%s sec' 
          % (final_time.strftime('%m/%d/%Y %H:%M:%S.%f'), delta.seconds, delta.microseconds))

if __name__ == "__main__":
  main()
