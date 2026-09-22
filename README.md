> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# D3 — Log Analyzer

D3 is a **DFIR log analysis** tool for **incident response**: it parses
multi-format logs, correlates events into timelines, extracts **IOCs**, and
flags anomalies such as brute-force, SQL injection, and directory scanning.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/d3-log-analyzer)](https://github.com/5h4d0wn1k/d3-log-analyzer)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/d3-log-analyzer)](https://github.com/5h4d0wn1k/d3-log-analyzer)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/d3-log-analyzer)](https://github.com/5h4d0wn1k/d3-log-analyzer)

## Why D3

After an incident, the first thing an **incident response** team needs is
signal in a noisy log pile. D3 ingests syslog, nginx, auth, and JSONL logs,
auto-detects the format from the filename, and produces a correlation-ready
timeline with extracted attacker artifacts (IPs, domains, hashes) and
anomaly labels — so analysts can pivot from "lots of logs" to "here is what
happened". Analyze only logs from systems you own or are authorized to
examine; this is a **digital forensics** education and blue-team companion.

## Features

- **Multi-format parsing** — syslog, nginx combined, `auth.log`, JSONL (auto-detected from filename)
- **Anomaly detection** — brute-force SSH, SQL injection, XSS attempts, directory scanning
- **IOC extraction** — IPs, domains, and hashes (MD5/SHA1/SHA256)
- **Timeline reconstruction** — chronological ordering of every parsed event
- **Directory input** — analyze a whole tree of mixed-format logs
- **JSON reports** — structured output for downstream tooling

## Quickstart

```bash
# Offline demo on bundled fixtures
python3 cli.py --demo

# Analyze a single log file
python3 cli.py --input /var/log/syslog --output reports/report.json

# Analyze a directory of mixed logs
python3 cli.py --input /var/log --output reports/report.json

# Tests
python3 -m unittest discover -s tests
```

## Examples

- `tests/fixtures/` — synthetic `syslog.txt`, `nginx_access.log`, `auth.log`, `events.jsonl` covering every format and anomaly type

## Project structure

- `cli.py` — thin CLI entrypoint
- `firmware/log_analyzer.py` — parsing, correlation, and reporting engine
- `tests/` — format parsers, anomaly rules, IOC extraction, fixture generation

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).

## Legal

- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md) · [SECURITY.md](SECURITY.md)