#!/usr/bin/env python3
"""
D3 — Log Analyzer
Multi-format log parsing, timeline reconstruction, IOC extraction, anomaly detection.
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime


class LogAnalyzer:
    def __init__(self, input_path, output_path=None):
        self.input_path = input_path
        self.output_path = output_path
        self.entries = []
        self.anomalies = []
        self.iocs = {}

    def parse_syslog(self, line):
        m = re.match(
            r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)',
            line,
        )
        if m:
            msg = m.group(5)
            entry = {
                "timestamp": m.group(1),
                "hostname": m.group(2),
                "service": m.group(3),
                "pid": m.group(4),
                "message": msg,
                "raw": line,
                "format": "syslog",
            }
            if "Failed password" in msg:
                entry["type"] = "login_failure"
                fm = re.search(r'for\s+(\S+)\s+from\s+(\S+)', msg)
                if fm:
                    entry["user"] = fm.group(1)
                    entry["ip"] = fm.group(2)
            elif "Accepted" in msg:
                entry["type"] = "login_success"
                fm = re.search(r'for\s+(\S+)\s+from\s+(\S+)', msg)
                if fm:
                    entry["user"] = fm.group(1)
                    entry["ip"] = fm.group(2)
            return entry
        return None

    def parse_nginx(self, line):
        m = re.match(
            r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)',
            line,
        )
        if m:
            return {
                "ip": m.group(1),
                "timestamp": m.group(2),
                "method": m.group(3),
                "url": m.group(4),
                "status": int(m.group(5)),
                "size": int(m.group(6)),
                "raw": line,
                "format": "nginx",
            }
        return None

    def parse_auth(self, line):
        if "Accepted" in line:
            m = re.search(r'Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)', line)
            if m:
                return {
                    "type": "login_success",
                    "method": m.group(1),
                    "user": m.group(2),
                    "ip": m.group(3),
                    "raw": line,
                    "format": "auth",
                }
        if "Failed" in line:
            m = re.search(r'Failed\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)', line)
            if m:
                return {
                    "type": "login_failure",
                    "method": m.group(1),
                    "user": m.group(2),
                    "ip": m.group(3),
                    "raw": line,
                    "format": "auth",
                }
        return None

    def parse_jsonl(self, line):
        try:
            obj = json.loads(line)
            obj["raw"] = line
            obj["format"] = "jsonl"
            return obj
        except (json.JSONDecodeError, ValueError):
            return None

    def detect_format(self, filepath):
        basename = os.path.basename(filepath).lower()
        if "auth" in basename or "secure" in basename:
            return "auth"
        if "nginx" in basename or "access" in basename:
            return "nginx"
        if filepath.endswith(".jsonl") or filepath.endswith(".json"):
            return "jsonl"
        return "syslog"

    def parse_file(self, filepath):
        fmt = self.detect_format(filepath)
        entries = []
        parsers = {
            "syslog": self.parse_syslog,
            "nginx": self.parse_nginx,
            "auth": self.parse_auth,
            "jsonl": self.parse_jsonl,
        }
        parser = parsers[fmt]
        with open(filepath, "r", errors="ignore") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                entry = parser(line)
                if entry:
                    entry["line_num"] = i
                    entry["source_file"] = os.path.basename(filepath)
                    entries.append(entry)
        return entries

    def load(self, path=None):
        target = path or self.input_path
        if os.path.isdir(target):
            for fname in sorted(os.listdir(target)):
                fpath = os.path.join(target, fname)
                if os.path.isfile(fpath) and not fname.startswith("."):
                    self.entries.extend(self.parse_file(fpath))
        else:
            self.entries = self.parse_file(target)
        return len(self.entries)

    def detect_anomalies(self):
        anomalies = []
        failed_logins = [e for e in self.entries if e.get("type") == "login_failure"]
        if failed_logins:
            by_ip = defaultdict(list)
            for entry in failed_logins:
                by_ip[entry["ip"]].append(entry)
            for ip, attempts in by_ip.items():
                if len(attempts) >= 5:
                    anomalies.append({
                        "type": "brute_force",
                        "ip": ip,
                        "count": len(attempts),
                        "severity": "HIGH",
                        "description": "%d failed login attempts from %s" % (len(attempts), ip),
                    })

        sqli_patterns = ["union", "select", "insert", "drop", "delete", "update", "' or", "1=1"]
        xss_patterns = ["<script", "javascript:", "onerror=", "onload="]
        for entry in self.entries:
            url = (entry.get("url") or entry.get("path") or "").lower()
            for p in sqli_patterns:
                if p in url:
                    anomalies.append({
                        "type": "sql_injection",
                        "ip": entry.get("ip", "unknown"),
                        "url": entry.get("url") or entry.get("path", ""),
                        "severity": "CRITICAL",
                        "description": "Potential SQL injection: %s" % p,
                    })
                    break
            for p in xss_patterns:
                if p in url:
                    anomalies.append({
                        "type": "xss_attempt",
                        "ip": entry.get("ip", "unknown"),
                        "url": entry.get("url") or entry.get("path", ""),
                        "severity": "HIGH",
                        "description": "Potential XSS: %s" % p,
                    })
                    break

        scan_404 = [e for e in self.entries if e.get("status") == 404]
        if len(scan_404) > 3:
            anomalies.append({
                "type": "directory_scan",
                "count": len(scan_404),
                "severity": "MEDIUM",
                "description": "%d 404 errors - possible directory scanning" % len(scan_404),
            })

        for entry in self.entries:
            msg = entry.get("message") or entry.get("command") or ""
            if any(w in msg.lower() for w in ["sudo", "su ", "passwd", "chown", "chmod"]):
                anomalies.append({
                    "type": "privilege_escalation",
                    "message": msg[:200],
                    "severity": "MEDIUM",
                    "description": "Potential privilege escalation command",
                })

        self.anomalies = anomalies
        return anomalies

    def extract_iocs(self):
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        md5_pattern = re.compile(r'\b[a-f0-9]{32}\b')
        sha1_pattern = re.compile(r'\b[a-f0-9]{40}\b')
        sha256_pattern = re.compile(r'\b[a-f0-9]{64}\b')

        iocs = {"ips": set(), "domains": set(), "hashes": set(), "urls": set()}
        for entry in self.entries:
            text = entry.get("raw", "")
            iocs["ips"].update(ip_pattern.findall(text))
            iocs["hashes"].update(md5_pattern.findall(text.lower()))
            iocs["hashes"].update(sha1_pattern.findall(text.lower()))
            iocs["hashes"].update(sha256_pattern.findall(text.lower()))
            url = entry.get("url") or entry.get("path")
            if url:
                iocs["urls"].add(url)
            msg = entry.get("message") or entry.get("command") or ""
            domain_matches = re.findall(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-z]{2,})\b', msg)
            for d in domain_matches:
                if d not in ("com", "net", "org", "html", "css", "js"):
                    iocs["domains"].add(d)

        self.iocs = {k: sorted(v) for k, v in iocs.items()}
        return self.iocs

    def build_timeline(self):
        return sorted(self.entries, key=lambda x: x.get("timestamp", ""))

    def generate_report(self, output_path):
        self.detect_anomalies()
        self.extract_iocs()
        report = {
            "input": self.input_path,
            "total_entries": len(self.entries),
            "anomalies": self.anomalies,
            "iocs": self.iocs,
            "timeline_count": len(self.entries),
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        return report

    def print_summary(self):
        print("=" * 60)
        print("  D3 — Log Analyzer — Analysis Report")
        print("=" * 60)
        print("  Input: %s" % self.input_path)
        print("  Total entries: %d" % len(self.entries))
        fmt_counts = Counter(e.get("format", "unknown") for e in self.entries)
        print("  Formats: %s" % dict(fmt_counts))
        print("  Anomalies: %d" % len(self.anomalies))
        for a in self.anomalies[:10]:
            print("    [%s] %s: %s" % (a["severity"], a["type"], a["description"]))
        total_iocs = sum(len(v) for v in self.iocs.values())
        print("  IOCs: %d" % total_iocs)
        if self.iocs.get("ips"):
            print("    IPs: %s" % ", ".join(self.iocs["ips"][:10]))
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="D3 — Log Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python3 cli.py --input /var/log --output reports/report.json",
    )
    parser.add_argument("--input", "-i", help="Log file or directory to analyze")
    parser.add_argument("--output", "-o", help="JSON output report path")
    parser.add_argument("--demo", action="store_true", help="Run demo on built-in fixtures")
    args = parser.parse_args()

    if args.demo:
        base = os.path.dirname(os.path.abspath(sys.argv[0]))
        if os.path.basename(base) == "firmware":
            base = os.path.dirname(base)
        fixture_dir = os.path.join(base, "tests", "fixtures")
        if not os.path.isdir(fixture_dir):
            print("[ERROR] Fixtures not found at %s" % fixture_dir)
            sys.exit(1)
        analyzer = LogAnalyzer(fixture_dir)
        n = analyzer.load()
        analyzer.detect_anomalies()
        analyzer.extract_iocs()
        out_dir = os.path.join(base, "reports")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "d3_report.json")
        analyzer.generate_report(out_path)
        analyzer.print_summary()
        print("Report written to %s" % out_path)
        sys.exit(0)

    if not args.input:
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(args.input):
        print("ERROR: File not found: %s" % args.input)
        sys.exit(1)

    analyzer = LogAnalyzer(args.input, args.output)
    analyzer.load()
    analyzer.detect_anomalies()
    analyzer.extract_iocs()
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        analyzer.generate_report(args.output)
        print("Report written to %s" % args.output)
    analyzer.print_summary()
    sys.exit(0)


if __name__ == "__main__":
    main()
