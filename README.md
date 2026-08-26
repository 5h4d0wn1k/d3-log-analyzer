# D3 — Log Analyzer

Centralized log parsing and timeline reconstruction for incident response.

## Overview

This project implements a log analysis tool that:
- Parses multiple log formats (syslog, Apache, Nginx, auth logs)
- Builds attack timelines from log entries
- Detects anomalies and suspicious patterns
- Extracts IoCs (Indicators of Compromise)
- Generates HTML reports

## Features

- **Multi-format support**: Syslog, Apache, Nginx, auth logs
- **Anomaly detection**: Brute force, SQL injection, XSS, directory scanning
- **IoC extraction**: IPs, domains, hashes, URLs
- **Timeline reconstruction**: Build event sequences
- **HTML reports**: Visual analysis output

## Installation

```bash
pip install python-magic
```

## Usage

```bash
# Analyze syslog
python3 log_analyzer.py -i /var/log/syslog -o report.html

# Analyze Apache logs
python3 log_analyzer.py -i /var/log/apache2/access.log -o apache_report.html

# Analyze auth logs
python3 log_analyzer.py -i /var/log/auth.log -o auth_report.html
```

## Example Output

```
=== D3 — Log Analyzer ===
Input: /var/log/auth.log

Loading logs from /var/log/auth.log...
Loaded 12345 entries

Detecting anomalies...
Found 5 anomalies

Extracting IoCs...
Found 23 IoCs

Building timeline...
Timeline contains 12345 events

==================================================
ANALYSIS COMPLETE
==================================================

Total entries: 12345
Anomalies: 5
IoCs: 23

Top anomalies:
  [HIGH] 47 failed login attempts from 192.168.1.100
  [MEDIUM] 234 404 errors - possible directory scanning
  [MEDIUM] Potential privilege escalation command
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission before analyzing logs
- Unauthorized access to system logs is illegal under federal and state laws
- This tool should ONLY be used on systems you own or have written authorization to analyze

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Privacy Laws**: Log data may contain personally identifiable information
- **State Laws**: Many states have additional computer crime and privacy statutes
- **GDPR/CCPA**: Log data may be subject to privacy regulations

### Acceptable Use
- Analyzing logs on your own systems
- Authorized incident response with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Accessing logs without authorization
- Sharing sensitive log data
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
