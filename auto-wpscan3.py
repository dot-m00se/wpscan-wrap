#!/usr/bin/python
import multiprocessing
import traceback
from subprocess import *
import shlex
import re
from datetime import datetime
import configparser
import os, sys

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'settings.ini'))

wp_sites = config.items('wp_sites_to_scan')
false_positive_strings = config.items('fp')
log_file = r'./wpwatcher.log'

#Main function that runs wpscan against sites and writes results to logfile
def main(sites):
    print("[INFO] Starting scans on configured sites")

    sites = sites.strip()

    try:
       print("[INFO] Scanning '%s'" % sites)
       result = Popen(['wpscan', '--url', sites, '--follow-redirection'], stdout=PIPE, shell=False)
       output = result.stdout.read()
       output1 = output.decode("utf-8")
       print(output1)
    except CalledProcessError as exc:
       print("[ERROR]", exc.returncode, exc.output)

    (warnings, alerts) = parse_results(output1)
    if output:
        try:
            with open(log_file, 'a') as log:
                for warning in warnings:
                    log.write("%s %s WARNING: %s\n" % (get_timestamp(), sites, warning))
                for alert in alerts:
                    log.write("%s %s ALERT: %s\n" % (get_timestamp(), sites, alert))
        except Exception as e:
            traceback.print_exc()
            print("[ERROR] Cannot write to log file")

#Parse the results from wpscan and seperate into Warning/Alert
def parse_results(output1):
    warnings = []
    alerts = []
    warning_on = False
    alert_on = False
    last_message = ""

    # Parse the lines
    for line in output1.splitlines():

        # Remove colorization
        line = re.sub('(\x1b|\[[0-9][0-9]?m)', '', str(line))

        # Empty line = end of message
        if line == "" or line.startswith("[+]"):
            if warning_on:
                if not is_false_positive(warning):
                    warnings.append(warning)
                warning_on = False
            if alert_on:
                if not is_false_positive(alert):
                    alerts.append(alert)
                alert_on = False

        # Add to warning/alert
        if warning_on:
            warning += " / %s" % line.lstrip(" ")
        if alert_on:
            alert += " / %s" % line.lstrip(" ")

        # Start Warning/Alert
        if line.startswith("[i]"):
            # Warning message
            warning = "%s / %s" % (last_message, line)
            warning_on = True
        if line.startswith("[!]"):
            # Warning message
            alert = line
            alert_on = True

        # Store last message
        last_message = line

    return (warnings, alerts)

#Detect faulse positives
def is_false_positive(string):
    for key, fp_string in false_positive_strings:
        if fp_string in string:
            # print fp_string, string
            return 1
    return 0

#Time stamp
def get_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    run_scan()


if __name__ == '__main__':

    with open(sys.argv[1], 'r') as f:
        hosts = f.readlines()

    p = multiprocessing.Pool(processes=8)
    p.map_async(main, hosts)
    p.close()
    p.join()

    exit()





