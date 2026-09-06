#!/usr/bin/env python3
"""Tests for D3 Log Analyzer."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "firmware"))
from log_analyzer import LogAnalyzer

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


class TestSyslogParsing(unittest.TestCase):
    def setUp(self):
        self.a = LogAnalyzer(os.path.join(FIXTURE_DIR, "syslog.txt"))
        self.a.load()

    def test_entry_count(self):
        self.assertGreater(len(self.a.entries), 0)

    def test_syslog_fields(self):
        for e in self.a.entries:
            self.assertIn("timestamp", e)
            self.assertIn("hostname", e)
            self.assertIn("service", e)
            self.assertIn("message", e)

    def test_brute_force_detected(self):
        self.a.detect_anomalies()
        brute = [a for a in self.a.anomalies if a["type"] == "brute_force"]
        self.assertGreater(len(brute), 0)
        self.assertEqual(brute[0]["ip"], "203.0.113.50")
        self.assertGreaterEqual(brute[0]["count"], 5)


class TestNginxParsing(unittest.TestCase):
    def setUp(self):
        self.a = LogAnalyzer(os.path.join(FIXTURE_DIR, "nginx_access.log"))
        self.a.load()

    def test_entry_count(self):
        self.assertGreater(len(self.a.entries), 0)

    def test_nginx_fields(self):
        for e in self.a.entries:
            self.assertIn("ip", e)
            self.assertIn("url", e)
            self.assertIn("status", e)
            self.assertIn("method", e)

    def test_sqli_detected(self):
        self.a.detect_anomalies()
        sqli = [a for a in self.a.anomalies if a["type"] == "sql_injection"]
        self.assertGreater(len(sqli), 0)

    def test_xss_detected(self):
        self.a.detect_anomalies()
        xss = [a for a in self.a.anomalies if a["type"] == "xss_attempt"]
        self.assertGreater(len(xss), 0)

    def test_404_scan_detected(self):
        self.a.detect_anomalies()
        scans = [a for a in self.a.anomalies if a["type"] == "directory_scan"]
        self.assertGreater(len(scans), 0)


class TestAuthParsing(unittest.TestCase):
    def setUp(self):
        self.a = LogAnalyzer(os.path.join(FIXTURE_DIR, "auth.log"))
        self.a.load()

    def test_login_failures_found(self):
        failures = [e for e in self.a.entries if e.get("type") == "login_failure"]
        self.assertGreater(len(failures), 0)

    def test_brute_force_from_203(self):
        self.a.detect_anomalies()
        brute = [a for a in self.a.anomalies if a["type"] == "brute_force"]
        self.assertGreater(len(brute), 0)
        ips = [a["ip"] for a in brute]
        self.assertIn("203.0.113.50", ips)


class TestJsonlParsing(unittest.TestCase):
    def setUp(self):
        self.a = LogAnalyzer(os.path.join(FIXTURE_DIR, "events.jsonl"))
        self.a.load()

    def test_entry_count(self):
        self.assertEqual(len(self.a.entries), 8)

    def test_jsonl_fields(self):
        for e in self.a.entries:
            self.assertIn("timestamp", e)
            self.assertIn("source", e)
            self.assertIn("type", e)


class TestIOCs(unittest.TestCase):
    def setUp(self):
        self.a = LogAnalyzer(os.path.join(FIXTURE_DIR, "syslog.txt"))
        self.a.load()

    def test_ips_extracted(self):
        iocs = self.a.extract_iocs()
        self.assertIn("203.0.113.50", iocs["ips"])
        self.assertIn("198.51.100.22", iocs["ips"])


class TestDirectoryInput(unittest.TestCase):
    def test_load_directory(self):
        a = LogAnalyzer(FIXTURE_DIR)
        n = a.load()
        self.assertGreater(n, 10)


class TestCLIHelp(unittest.TestCase):
    def test_help_exits_zero(self):
        import subprocess
        cli = os.path.join(os.path.dirname(__file__), "..", "cli.py")
        r = subprocess.run([sys.executable, cli, "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("Log Analyzer", r.stdout)


class TestCLIDemo(unittest.TestCase):
    def test_demo_exits_zero(self):
        import subprocess
        cli = os.path.join(os.path.dirname(__file__), "..", "cli.py")
        r = subprocess.run([sys.executable, cli, "--demo"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
