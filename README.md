# D3 — Log Analyzer

Multi-format log parsing, timeline reconstruction, IOC extraction, anomaly detection.

## IMPORTANT: Read before use.

This tool is for **authorized educational and blue-team analysis only**. Analyze logs on systems you own or have explicit written permission to examine. Never use for unauthorized access.

## Features

- **Multi-format parsing**: syslog, nginx combined, auth.log, JSONL
- **Anomaly detection**: brute-force SSH, SQL injection, XSS, directory scanning
- **IOC extraction**: IPs, domains, hashes (MD5/SHA1/SHA256)
- **Timeline reconstruction**: chronological ordering of all events
- **JSON report output**: structured analysis results
- **Directory input**: auto-detect format from filename

## Quick Start

```bash
# Run demo on built-in fixtures
python3 cli.py --demo

# Analyze a log file
python3 cli.py --input /var/log/syslog --output reports/report.json

# Analyze a directory of mixed logs
python3 cli.py --input /var/log --output reports/report.json
```

## Parsed Formats

| Format | Example Source | Fields Extracted |
|--------|---------------|------------------|
| syslog | rsyslog, syslog-ng | timestamp, hostname, service, pid, message |
| nginx combined | nginx access.log | ip, timestamp, method, url, status, size |
| auth.log | PAM, sshd | type (login_success/login_failure), method, user, ip |
| JSONL | structured logs | all JSON fields |

## Testing

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

1. Run `python3 cli.py --demo` — should exit 0 and print analysis report
2. Run `python3 -m unittest discover -s tests` — all tests pass
3. Verify `reports/d3_report.json` contains anomalies and IOCs

## Metrics

- Formats parsed: 4 (syslog, nginx, auth.log, JSONL)
- Anomaly types detected: 4 (brute_force, sql_injection, xss_attempt, directory_scan)
- Test count: 10
- Demo exit code: 0

## Legal

This software is provided for educational purposes only. See LICENSE for full terms.

## License

MIT License — see [LICENSE](LICENSE).
