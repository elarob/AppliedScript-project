#!/usr/bin/env python3
#Log Analyzer - to analyze logs and count logins

import sys # for sys.exit
import os 	# file- and catalog management
import re
from collections import defaultdict, Counter
from datetime import datetime, timezone


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

def find_suspicious_ips(ip_counts, threshold=5):

    # finds IPs with more than threshold login attempts

    pass


def export_suspicious_ips(suspicious_ips, filename="suspicious_ips.txt"):

    # exports suspicious IPs to a textfile

    pass


def export_report(total, failed, suspicious_ips, filename="report.txt"): # exports a full analysis report
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("Log Analysis Report\n")
        f.write(line + "\n")
        f.write(f"Generated: {timestamp}\n\n")

        f.write(f"Total login attempts: {total}\n")
        f.write(f"Failed login attempts: {failed}\n\n")

        f.write(f"Suspicious IP addresses:\n")
        if not suspicious_ips:
            f.wrifinte("None\n")

        else:
            for ip, count in suspicious_ips.items():
                f.write(f" - {ip}: {count} attempts\n")

    print(line)
    print(f"* Report saved as {filename}")
    






if __name__ == "__main__":
    main()
