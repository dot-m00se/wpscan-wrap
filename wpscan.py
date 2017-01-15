#!/usr/bin/python
import traceback
from subprocess import *
import shlex
import re
from datetime import datetime
import configparser
import os

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'settings.ini'))

wp_sites = ['http://www.example.com']
#wp_sites = config.items('wp_sites_to_scan')
#false_positive_strings = config.items('main', 'false_posotive_strings')
false_positive_strings = ['XML-RPC', 'GHOST vulnerability']

log_file = r'./wpwatcher.log'


def main():
    print "[INFO] Starting scans on configured sites"
    for sites in wp_sites:

        try:
            print "[INFO] Scanning '%s'" % sites
            result = Popen(['ruby', '/usr/bin/wpscan/wpscan.rb', '--disable-tls-checks', '--url', sites], stdout=PIPE, shell=False)
            output = result.stdout.read()
            print output
        except CalledProcessError as exc:
            print "[ERROR]", exc.returncode, exc.output

        (warnings, alerts) = parse_results(output)
        if output:
            try:
                with open(log_file, 'a') as log:
                    for warning in warnings:
                        log.write("%s %s WARNING: %s\n" % (get_timestamp(), sites, warning))
                    for alert in alerts:
                        log.write("%s %s ALERT: %s\n" % (get_timestamp(), sites, alert))
            except Exception, e:
                traceback.print_exc()
                print "[ERROR] Cannot write to log file"


def parse_results(output):
    warnings = []
    alerts = []
    warning_on = False
    alert_on = False
    last_message = ""

    # Parse the lines
    for line in output.splitlines():

        # Remove colorization
        line = re.sub(r'(\x1b|\[[0-9][0-9]?m)', '', line)

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


def is_false_positive(string):
    # False Positive Detection
    for fp_string in false_positive_strings:
        if fp_string in string:
            # print fp_string, string
            return 1
    return 0


def get_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    run_scan()


if __name__ == '__main__':
    main()
