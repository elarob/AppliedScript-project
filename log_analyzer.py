#!/usr/bin/env python3
#Log Analyzer - to analyze logs and count logins

import sys # for sys.exit
import os 	# file- and catalog management
import re
from collections import defaultdict, Counter


def read_logfile(filepath):


    #reads a logfile and return all lines

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
        
    except FileNotFoundError:
        print(f"Error: cannot locate file {filepath}")
        sys.exit(1)


def main():

    if len(sys.argv) < 2:
        print(line + "\n")
        print("Usage: python log_analyzer.py <logfile>\n")
        print("     -Please provide a log file to analyze-")
        print("\nExample: python log_analyzer.py test-log.txt\n")
        sys.exit(1)


    logfile = sys.argv[1]      
    log_lines = read_logfile(logfile)

    total = count_login_attempts(log_lines)
    failed = count_failed_logins(log_lines)

    user_stats = logins_per_user(log_lines)
    ip_counts = logins_per_ip(log_lines)

    suspicious = find_suspicious_ips(ip_counts)
    export_suspicious_ips(suspicious)

    print("Total logins:", total)
    print("Failed logins:", failed)
    print("Suspicious IPs:", suspicious)



# log analysis features

def count_login_attempts(log_lines):
    count = 0
    for line in log_lines:
        if "login" in line.lower():
            count += 1

    return count

    # counts total login attempts


def count_failed_logins(log_lines):
    count = 0

    for line in log_lines:
        if "failed" in line.lower():
            count += 1

    return count

    # counts failed logins per user


def logins_per_user(log_lines):

    # counts login attempts per user

    pass


def logins_per_ip(log_lines):

    # counts login attempts per IP address

    pass

def find_suspicious_ips(ip_counts, threshold=5):

    # finds IPs with more than threshold login attempts

    pass


def export_suspicious_ips(suspicious_ips, filename="suspicious_ips.txt"):

    # exports suspicious IPs to a textfile

    pass






if __name__ == "__main__":
    main()
