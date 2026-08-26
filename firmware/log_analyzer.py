#!/usr/bin/env python3
"""
D3 — Log Analyzer
Centralized log parsing and timeline reconstruction

Features:
- Parse multiple log formats (syslog, Apache, Nginx, etc.)
- Build attack timelines
- Detect anomalies and patterns
- Extract IoCs (Indicators of Compromise)
- Generate HTML reports

Usage:
    python3 log_analyzer.py --input /var/log/syslog --output report.html

WARNING: Educational use only. Analyze logs on systems you own.
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import html

class LogAnalyzer:
    def __init__(self, input_path, output_path=None):
        self.input_path = input_path
        self.output_path = output_path
        self.entries = []
        self.anomalies = []
        self.iocs = []
        self.timeline = []
        self.stats = {}
        
        print(f"\n=== D3 — Log Analyzer ===")
        print(f"Input: {input_path}")
        print(f"Output: {output_path or 'None'}")
        print("=" * 30)
    
    def parse_syslog(self, line):
        """Parse syslog format"""
        # Format: Jan  1 12:34:56 hostname service[pid]: message
        pattern = r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)'
        match = re.match(pattern, line)
        
        if match:
            return {
                'timestamp': match.group(1),
                'hostname': match.group(2),
                'service': match.group(3),
                'pid': match.group(4),
                'message': match.group(5),
                'raw': line
            }
        return None
    
    def parse_apache(self, line):
        """Parse Apache access log"""
        # Format: IP - - [timestamp] "method url protocol" status size
        pattern = r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'
        match = re.match(pattern, line)
        
        if match:
            return {
                'ip': match.group(1),
                'timestamp': match.group(2),
                'method': match.group(3),
                'url': match.group(4),
                'status': int(match.group(5)),
                'size': int(match.group(6)),
                'raw': line
            }
        return None
    
    def parse_auth(self, line):
        """Parse auth.log / secure"""
        # Successful login
        if 'Accepted' in line:
            pattern = r'Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)'
            match = re.search(pattern, line)
            if match:
                return {
                    'type': 'login_success',
                    'method': match.group(1),
                    'user': match.group(2),
                    'ip': match.group(3),
                    'raw': line
                }
        
        # Failed login
        if 'Failed' in line or 'authentication failure' in line:
            pattern = r'Failed\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)'
            match = re.search(pattern, line)
            if match:
                return {
                    'type': 'login_failure',
                    'method': match.group(1),
                    'user': match.group(2),
                    'ip': match.group(3),
                    'raw': line
                }
        
        return None
    
    def load_logs(self):
        """Load and parse log file"""
        print(f"\nLoading logs from {self.input_path}...")
        
        try:
            with open(self.input_path, 'r', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Try different parsers
                    entry = None
                    
                    # Check filename for format
                    filename = os.path.basename(self.input_path)
                    
                    if 'auth' in filename or 'secure' in filename:
                        entry = self.parse_auth(line)
                    elif 'access' in filename:
                        entry = self.parse_apache(line)
                    else:
                        entry = self.parse_syslog(line)
                    
                    if entry:
                        entry['line_num'] = line_num
                        self.entries.append(entry)
            
            print(f"Loaded {len(self.entries)} entries")
            return True
            
        except Exception as e:
            print(f"ERROR: {e}")
            return False
    
    def detect_anomalies(self):
        """Detect anomalous patterns"""
        print("\nDetecting anomalies...")
        
        anomalies = []
        
        # Check for brute force attempts
        failed_logins = [e for e in self.entries if e.get('type') == 'login_failure']
        if failed_logins:
            # Group by IP
            by_ip = defaultdict(list)
            for entry in failed_logins:
                by_ip[entry['ip']].append(entry)
            
            for ip, attempts in by_ip.items():
                if len(attempts) >= 5:
                    anomalies.append({
                        'type': 'brute_force',
                        'ip': ip,
                        'count': len(attempts),
                        'severity': 'HIGH',
                        'description': f'{len(attempts)} failed login attempts from {ip}'
                    })
        
        # Check for suspicious URLs (SQL injection, XSS)
        if any(e.get('url') for e in self.entries):
            sqli_patterns = ["union", "select", "insert", "drop", "delete", "update", "' or", "1=1"]
            xss_patterns = ["<script", "javascript:", "onerror=", "onload="]
            
            for entry in self.entries:
                url = entry.get('url', '').lower()
                
                for pattern in sqli_patterns:
                    if pattern in url:
                        anomalies.append({
                            'type': 'sql_injection',
                            'ip': entry.get('ip', 'unknown'),
                            'url': entry.get('url', ''),
                            'severity': 'CRITICAL',
                            'description': f'Potential SQL injection: {pattern}'
                        })
                        break
                
                for pattern in xss_patterns:
                    if pattern in url:
                        anomalies.append({
                            'type': 'xss_attempt',
                            'ip': entry.get('ip', 'unknown'),
                            'url': entry.get('url', ''),
                            'severity': 'HIGH',
                            'description': f'Potential XSS: {pattern}'
                        })
                        break
        
        # Check for unusual status codes
        if any(e.get('status') for e in self.entries):
            status_counter = Counter(e['status'] for e in self.entries if e.get('status'))
            
            # Many 404s could indicate scanning
            if status_counter.get(404, 0) > 100:
                anomalies.append({
                    'type': 'directory_scan',
                    'count': status_counter[404],
                    'severity': 'MEDIUM',
                    'description': f'{status_counter[404]} 404 errors - possible directory scanning'
                })
        
        # Check for privilege escalation attempts
        for entry in self.entries:
            message = entry.get('message', '').lower()
            if any(word in message for word in ['sudo', 'su ', 'passwd', 'chown', 'chmod']):
                anomalies.append({
                    'type': 'privilege_escalation',
                    'message': entry.get('message', ''),
                    'severity': 'MEDIUM',
                    'description': 'Potential privilege escalation command'
                })
        
        self.anomalies = anomalies
        print(f"Found {len(anomalies)} anomalies")
        
        return anomalies
    
    def extract_iocs(self):
        """Extract Indicators of Compromise"""
        print("\nExtracting IoCs...")
        
        iocs = {
            'ips': set(),
            'domains': set(),
            'hashes': set(),
            'urls': set()
        }
        
        # IP pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        for entry in self.entries:
            # Extract IPs
            text = entry.get('raw', '')
            ips = re.findall(ip_pattern, text)
            iocs['ips'].update(ips)
            
            # Extract URLs
            if entry.get('url'):
                iocs['urls'].add(entry['url'])
            
            # Extract hashes (MD5, SHA1, SHA256)
            md5_pattern = r'\b[a-f0-9]{32}\b'
            sha1_pattern = r'\b[a-f0-9]{40}\b'
            sha256_pattern = r'\b[a-f0-9]{64}\b'
            
            iocs['hashes'].update(re.findall(md5_pattern, text.lower()))
            iocs['hashes'].update(re.findall(sha1_pattern, text.lower()))
            iocs['hashes'].update(re.findall(sha256_pattern, text.lower()))
        
        # Convert sets to lists
        for key in iocs:
            iocs[key] = list(iocs[key])
        
        self.iocs = iocs
        print(f"Found {sum(len(v) for v in iocs.values())} IoCs")
        
        return iocs
    
    def build_timeline(self):
        """Build attack timeline"""
        print("\nBuilding timeline...")
        
        # Sort entries by timestamp (simplified)
        self.timeline = sorted(self.entries, key=lambda x: x.get('timestamp', ''))
        
        print(f"Timeline contains {len(self.timeline)} events")
        
        return self.timeline
    
    def generate_html_report(self):
        """Generate HTML report"""
        if not self.output_path:
            return
        
        print(f"\nGenerating HTML report...")
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Log Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; }}
        .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
        .anomaly {{ background: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .critical {{ background: #f8d7da; }}
        .high {{ background: #fff3cd; }}
        .medium {{ background: #d1ecf1; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f5f5f5; }}
    </style>
</head>
<body>
    <h1>Log Analysis Report</h1>
    <p>Generated: {datetime.now().isoformat()}</p>
    
    <h2>Summary</h2>
    <div class="summary">
        <p>Total entries: {len(self.entries)}</p>
        <p>Anomalies detected: {len(self.anomalies)}</p>
        <p>IoCs extracted: {sum(len(v) for v in self.iocs.values())}</p>
    </div>
    
    <h2>Anomalies ({len(self.anomalies)})</h2>
"""
        
        for anomaly in self.anomalies[:20]:
            severity = anomaly['severity'].lower()
            html_content += f"""
    <div class="anomaly {severity}">
        <strong>{anomaly['type'].upper()}</strong> - {anomaly['description']}
    </div>
"""
        
        html_content += """
    <h2>Indicators of Compromise</h2>
    <h3>IP Addresses</h3>
    <ul>
"""
        
        for ip in self.iocs.get('ips', [])[:50]:
            html_content += f"        <li>{html.escape(ip)}</li>\n"
        
        html_content += """
    </ul>
    
    <h3>URLs</h3>
    <ul>
"""
        
        for url in self.iocs.get('urls', [])[:50]:
            html_content += f"        <li>{html.escape(url)}</li>\n"
        
        html_content += """
    </ul>
    
    <h2>Log Entries (First 100)</h2>
    <table>
        <tr><th>Line</th><th>Timestamp</th><th>Message</th></tr>
"""
        
        for entry in self.entries[:100]:
            html_content += f"""
        <tr>
            <td>{entry.get('line_num', '')}</td>
            <td>{html.escape(str(entry.get('timestamp', '')))}</td>
            <td>{html.escape(str(entry.get('message', entry.get('raw', '')))[:200])}</td>
        </tr>
"""
        
        html_content += """
    </table>
    
</body>
</html>
"""
        
        with open(self.output_path, 'w') as f:
            f.write(html_content)
        
        print(f"Report saved to: {self.output_path}")
    
    def analyze(self):
        """Main analysis function"""
        # Load logs
        if not self.load_logs():
            return False
        
        # Detect anomalies
        self.detect_anomalies()
        
        # Extract IoCs
        self.extract_iocs()
        
        # Build timeline
        self.build_timeline()
        
        # Generate report
        if self.output_path:
            self.generate_html_report()
        
        # Print summary
        self.print_summary()
        
        return True
    
    def print_summary(self):
        """Print analysis summary"""
        print(f"\n{'=' * 50}")
        print(f"ANALYSIS COMPLETE")
        print(f"{'=' * 50}")
        
        print(f"\nTotal entries: {len(self.entries)}")
        print(f"Anomalies: {len(self.anomalies)}")
        print(f"IoCs: {sum(len(v) for v in self.iocs.values())}")
        
        if self.anomalies:
            print(f"\nTop anomalies:")
            for anomaly in self.anomalies[:5]:
                print(f"  [{anomaly['severity']}] {anomaly['description']}")
        
        print(f"\n{'=' * 50}")

def main():
    parser = argparse.ArgumentParser(description='D3 — Log Analyzer')
    parser.add_argument('--input', '-i', required=True, help='Log file to analyze')
    parser.add_argument('--output', '-o', help='HTML output report')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"ERROR: File not found: {args.input}")
        sys.exit(1)
    
    analyzer = LogAnalyzer(args.input, args.output)
    analyzer.analyze()

if __name__ == '__main__':
    main()
