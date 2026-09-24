#!/usr/bin/env python3
"""
parse_syslog.py — Linux syslog / messages / auth.log parser.

Handles both legacy BSD syslog format (RFC 3164):
  Jan  1 00:00:00 host prog[pid]: message
and ISO-8601 format (systemd journal text export / rsyslog):
  2024-01-01T00:00:00.000000+00:00 host prog[pid]: message

Output CSV columns (consumed by collection.js):
  timestampColumns : Timestamp
  descriptionColumns: Program, Message
  sourceColumn      : Program
"""
import sys
import os
import re
import csv
import argparse
from datetime import datetime, timezone

FIELDNAMES = ['Timestamp', 'HostName', 'Program', 'Pid', 'Message',
              'Severity', 'SourceFile']

# ISO-8601 line (systemd/rsyslog with timestamp)
ISO_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
    r'(\S+)\s+([\w\-\.\/]+?)(?:\[(\d+)\])?:\s+(.*)$'
)
# BSD syslog: "Mon DD HH:MM:SS host prog[pid]: msg"
BSD_RE = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(\S+)\s+([\w\-\.\/]+?)(?:\[(\d+)\])?:\s+(.*)$'
)
BSD_MONTHS = {m: i+1 for i, m in enumerate(
    ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'])}

SEVERITY_KEYWORDS = {
    'crit': 'critical', 'critical': 'critical', 'emerg': 'critical',
    'alert': 'high',
    'err': 'high', 'error': 'high',
    'warn': 'medium', 'warning': 'medium',
    'notice': 'low',
    'info': 'info', 'debug': 'info',
}

TARGET_FILES = {'syslog', 'messages', 'auth.log', 'secure', 'kern.log',
                'daemon.log', 'user.log', 'cron', 'mail.log'}


def bsd_to_iso(s):
    """Convert 'Jan  1 12:34:56' to ISO-8601 (current year, UTC assumed)."""
    try:
        parts = s.split()
        mon = BSD_MONTHS.get(parts[0], 1)
        day = int(parts[1])
        h, mi, sec = map(int, parts[2].split(':'))
        year = datetime.now(tz=timezone.utc).year
        return datetime(year, mon, day, h, mi, sec, tzinfo=timezone.utc).isoformat()
    except Exception:
        return ''


def iso_normalise(s):
    try:
        s = s.replace(' ', 'T')
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        return datetime.fromisoformat(s).astimezone(timezone.utc).isoformat()
    except Exception:
        return s


def detect_severity(msg):
    low = msg.lower()
    for kw, sev in SEVERITY_KEYWORDS.items():
        if kw in low:
            return sev
    return 'info'


def parse_file(path):
    records = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.rstrip('\r\n')
                if not line:
                    continue
                ts = host = prog = pid = msg = ''
                m = ISO_RE.match(line)
                if m:
                    ts   = iso_normalise(m.group(1))
                    host = m.group(2)
                    prog = m.group(3)
                    pid  = m.group(4) or ''
                    msg  = m.group(5)
                else:
                    m = BSD_RE.match(line)
                    if m:
                        ts   = bsd_to_iso(m.group(1))
                        host = m.group(2)
                        prog = m.group(3)
                        pid  = m.group(4) or ''
                        msg  = m.group(5)
                    else:
                        continue
                records.append({
                    'Timestamp':  ts,
                    'HostName':   host,
                    'Program':    prog,
                    'Pid':        pid,
                    'Message':    msg[:500],
                    'Severity':   detect_severity(msg),
                    'SourceFile': path,
                })
    except OSError as e:
        print(f'ERROR reading {path}: {e}', file=sys.stderr)
    return records


def parse_dir(base):
    records = []
    for root, _dirs, files in os.walk(base):
        for name in sorted(files):
            # Accept target filenames and rotated variants (syslog.1, syslog.2.gz stripped)
            base_name = name.split('.')[0].lower()
            if base_name in TARGET_FILES or name.lower() in TARGET_FILES:
                fpath = os.path.join(root, name)
                if name.endswith('.gz'):
                    continue   # skip compressed — user should gunzip first
                records.extend(parse_file(fpath))
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--dir', required=True, help='Directory containing syslog files')
    ap.add_argument('--csv', required=True, help='Output directory')
    ap.add_argument('--csvf', default='syslog_results.csv', help='Output CSV filename')
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        print(f'ERROR: Directory not found: {args.dir}', file=sys.stderr)
        sys.exit(1)
    os.makedirs(args.csv, exist_ok=True)
    records = parse_dir(args.dir)
    out_path = os.path.join(args.csv, args.csvf)
    with open(out_path, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(records)
    print(f'Parsed {len(records)} syslog entries -> {out_path}')


if __name__ == '__main__':
    main()
