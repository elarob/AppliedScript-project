#!/usr/bin/env python3
#Log Analyzer - Security Analysis Tool for detecting suspicious login patterns

"""

Parse log files to identify brute force attacks via failed login attempts and suspicious IP patterns.
Generates detailed reports, suspicious IP lists and visualizations

"""


import sys # for sys.exit/exit the program and handle command line arguments
import os # file- and catalog management and clearing the screen
import re # regular expressions - used to find patterns in text
from collections import defaultdict, Counter
from datetime import datetime, timezone
import matplotlib.pyplot as plt


# text color - ANSI codes for terminal output (Linux/Mac/Windows compatible)
bold = "\033[1m"
magenta = "\033[35m"
red = "\033[31m"
yellow = "\033[33m"
green = "\033[32m"
reset = "\033[0m"


threshold = 5 # amount of logins tolerated as not suspicious
line = magenta + bold + "-" * 50 + reset



#read a log file with UTF-8 fallback and comprehensive error handling
def read_logfile(filepath):

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()

    except FileNotFoundError:
        print(f"Error: cannot locate file {filepath}")
        sys.exit(1)

    except Exception as e:
        print(f"Unexpected error while reading {filepath}: {e}")
        sys.exit(1)

def clear_screen():
    if os.name == 'possix': # for Linux/MacOS
        os.system('clear')
    elif os.name == 'nt': # for Windows
        os.system('cls')



def main(): # main analysis workflow: parse -> analyze -> report -> visualize
    clear_screen()

    print(line + "\n")
    print(magenta + bold + "    LOG ANALYZER - Security Analysis Tool" + reset)

    # validate CLI arguments
    if len(sys.argv) < 2:
        print(line +  "\n")
        print("Usage: python log_analyzer.py <logfile>\n")
        print(red + "     -Please provide a log file to analyze-" + reset)
        print("Make sure to be located in the same directory as the script and log file.")
        print(" *  Please check your current location: pwd (for location), ls(to see files)  *")
        print("\n" + yellow + "HOW TO USE: python log_analyzer <filename>" + reset)
        print("\n" + green + "----> Example: python log_analyzer.py test-log.txt" + reset + "\n")
        sys.exit(1)


    logfile = sys.argv[1]
    log_lines = read_logfile(logfile)

    print(f"{yellow}       Analyzing {logfile}...{reset}\n")


    # calls different functions to analyze the log
    total = count_login_attempts(log_lines)
    failed = count_failed_logins(log_lines)

    user_stats = logins_per_user(log_lines)
    ip_counts = logins_per_ip(log_lines)

    suspicious = find_suspicious_ips(ip_counts)

    # export structured output
    export_report(total, failed, suspicious)
    export_suspicious_ips(suspicious)

    # display summary
    print(line)
    print("Analysis Results:")
    print("Total logins:", total)
    print("Failed logins:", failed)
    print(f"\n{red}Suspicious IPs (>{threshold} attempts):{reset}")

    if suspicious:
        for ip, count in suspicious.items():
            print(f" * IP {ip}: {count} attempts")

    else:
        print(" None detected")


    # create visual output - graph of suspicious IPs
    if suspicious:
        ips = list(suspicious.keys())
        counts = list(suspicious.values())


        plt.figure(figsize=(10,6))
        plt.bar(ips, counts, color="red", alpha=0.7)
        plt.title("Suspicious IP-addresses ( Threshold > 5 login attempts.)")
        plt.xlabel("IP-addresses")
        plt.ylabel("Number of login attempts")
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig("possible_attack.png") # saves pic
        print(f"\nPicture saved av possible_attack.png")
        plt.show() # shows diagram

    print("\n" + line)
    print(green + bold + "\n          ¤   Analysis complete!   ¤\n" + reset)
    print(line + "\n")




# === log analysis functions/features ===


# count total lines containing 'login' keyword (case-insesitive)
def count_login_attempts(log_lines):
    count = 0
    for line in log_lines:
        if "login" in line.lower():
            count += 1

    return count


# count total failed login attempts
def count_failed_logins(log_lines):
    count = 0

    for line in log_lines:
        if "failed" in line.lower():
            count += 1

    return count


# count login attempts per user
def logins_per_user(log_lines):
    user_stats = {}


    for line in log_lines:
        user_match = re.search(r"user=(\w+)", line) # use regular expression to find "user=something" 
        status_match = re.search(r"status=(\w+)", line) # to find "status=something"


        if user_match and status_match:
            user = user_match.group(1)
            status = status_match.group(1)

            if user not in user_stats:
                user_stats[user] = {"success": 0, "failed": 0}

            if status in ("success", "failed"):
                user_stats[user][status] += 1

    return user_stats


# count login attempts per IP address
def logins_per_ip(log_lines):
    ip_counts = Counter()

    for line in log_lines:
        match = re.search(r'ip=([\d\.]+)', line)
        if match:
            ip_counts[match.group(1)] += 1


    return dict(ip_counts)



# identify IPs exceeding security threshold
def find_suspicious_ips(ip_counts):
    suspicious = {} # empty dict for suspicious IP:s

    for ip, count in ip_counts.items():
        if count > threshold:
            suspicious[ip] = count

    return suspicious



# exports suspicious IPs to a text file
def export_suspicious_ips(suspicious_ips, filename="suspicious_ips.txt"):
    with open(filename, "w") as f:
        if not suspicious_ips:
            f.write("No suspicious IPs found.\n")
        else:
            for ip, count in suspicious_ips.items():
                f.write(f"{ip}: {count} attempts\n")

    print(f"* Suspicious IPs saved as {filename}")



# generate timestamped analysis report
def export_report(total, failed, suspicious_ips, filename="report.txt"):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("Log Analysis Report\n")
        f.write("-" * 50 + "\n")
        f.write(f"Generated: {timestamp}\n\n")

        f.write(f"Total login attempts: {total}\n")
        f.write(f"Failed login attempts: {failed}\n\n")

        f.write(f"Suspicious IP addresses:\n")
        if not suspicious_ips:
            f.write("None\n")

        else:
            for ip, count in suspicious_ips.items():
                f.write(f" - {ip}: {count} attempts\n")

    print(f"* Report saved as {filename}")





if __name__ == "__main__":
    main()

