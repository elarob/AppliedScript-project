#!/usr/bin/env python3
#Log Analyzer - to analyze logs and count logins

import sys # for sys.exit
import os 	# file- and catalog management
import re
from collections import defaultdict, Counter



threshold = 5 # amount of logins tolerated as not suspicious


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
        print("Usage: python log_analyzer.py <logfile>")
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
    

    # counts total login attempts

    pass


def count_failed_logins(log_lines):

    # counts failed logins per user

    pass


def logins_per_user(log_lines):

    # counts login attempts per user

    pass


def logins_per_ip(log_lines):

    # counts login attempts per IP address

    pass

def find_suspicious_ips(ip_counts):
    suspicious = {} # empty dict for suspicious IP:s

    for ip, count in ip_counts.items():
        if count > threshold:
            suspicious[ip] = count

    return suspicious
    # finds IPs with more than threshold login attempts



def export_suspicious_ips(suspicious_ips, filename="suspicious_ips.txt"):
    with open(filename, "w") as f:
        if not suspicious_ips:
            f.write("No suspicious IPs found.\n")
        else:
            for ip, count in suspicious_ips.items():
                f.write(f"{ip}: {count} attempts\n")

    print(f"* Suspicious IPs saved as {filename}")

    # exports suspicious IPs to a textfile

    pass






if __name__ == "__main__":
    main()
