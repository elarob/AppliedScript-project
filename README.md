## Log Analyzer - Security Analysis Tool



### Purpose

The Log Analyzer is a python based script designed to analyze log files and identify
potential security threats from failed login attempts.
The tool parses log files to detect suspicious login patterns, count failed login attempts, 
and visualize potential attacks through automated reporting and graphical representations.


### Function/Features

* Login Analysis: _Count total login attempts and failed login attempts_
* User Statistics: _Track login attempts per user with success/failed breakdowns_
* IP Address Monitoring: _Identifies suspicious IP addresses with excessive login attempts_
* Threat Detection: _Flags suspicious IPs exceeding a configurable threshold (default:5 attempts)_
* Export Capabilities: _Creates detailed reports and suspicious IP lists in text format_
* Visual Reporting: _Generates a bar charts visualizing suspicious IP addresses_



### System Requirements
**Operating System:** Any system with Python 3 installed.
**Python libraries:**
        - **matplotlib** for chart plotting
        - **re** for regular expressions
        - **collections** for counting
        - **datetime** for handling timestamps

__Ensure that you have the required libraries by running:__
pip install matplotlib


### Usage Instructions

1. ** Clone the repository:**
```bash
git clone https://github.com/elarob/AppliedScript-project.git
cd AppliedScript-project```


2. **Test with included sample logs(or use your own):**
python log_analyzer test-log.txt
__**or**__
python log_analyzer normal-log.txt


3. **Use your own log file:**
Place your log file in the same directory as log_analyzer.py.
Ensure the log contains login attempt entries in the following format:
>user=<username>, status=<success|failed>, ip=<IP'address>

4. **Run the script:**
```python log_analyzer.py <logfile>```
__Replace <logfile> with the name of your own log file._

###Example Output:
When you run:

```python log_analyzer test-log.txt```

The script will display the results in the terminal and saves:
* report.txt: Full analysis report
* suspicious_ips.txt: List of suspicious IPs
* possible_attack.png: Bar chart of suspicious IPs

### Screenshot/video



### Flowchart



### Additional Notes
* **Threshold for Suspicious IPs:**
        - The threshold for identifying suspicious IPs is set to 5 login attempts by default. 
        - You can adjust this value in the script if needed.
* **Output files:** 
        - The script saves three output files:
                * report.txt(full analysis report), 
                * suspicious_ips.txt(list of suspicious IPs)
                * possible_attack.png(a visual output with suspicious IPs).

> **Note**: Always ensure you have proper authorization before analysing log files.
> This tool should only be used on systems you own or have explicit permission to audit.
