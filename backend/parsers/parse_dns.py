#!/usr/bin/env python3
"""
parse_dns.py — name-resolution artifacts: the hosts file and DNS cache dumps.

- hosts (\\System32\\drivers\\etc\\hosts): static IP↔host overrides; malicious
  entries redirect/blackhole traffic (T1565.001 / defense evasion).
- DNS cache dumps (output of `ipconfig /displaydns`, when collected to a .txt):
  resolved domains a host contacted (C2 pivot).

No per-line timestamps → file mtime is used as a coarse anchor.

Output CSV columns (consumed by collection.js):
  timestampColumns : Timestamp
  descriptionColumns: Entry
  sourceColumn      : Type
"""

import sys
import os
import re
import csv
import argparse
from datetime import datetime, timezone

FIELDNAMES = ['Timestamp', 'Entry', 'Type', 'SourceFile', 'ComputerName']


def file_mtime_iso(path):
    try:
        return datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc).isoformat()
    except OSError:
        return ''


def parse_hosts(path):
    out = []
    ts = file_mtime_iso(path)
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith('#'):
                    continue
                parts = s.split()
                if len(parts) < 2:
                    continue
                ip = parts[0]
                for host in parts[1:]:
                    if host.startswith('#'):
                        break
                    out.append({'Timestamp': ts, 'Entry': f'{ip} → {host}', 'Type': 'hosts', 'SourceFile': path, 'ComputerName': ''})
    except OSError:
        pass
    return out


REC_NAME_RE = re.compile(r'Record Name[ .]*:\s*(.+)', re.I)
A_REC_RE    = re.compile(r'(?:A|AAAA) \(Host\) Record[ .]*:\s*([0-9a-f:.]+)', re.I)


def parse_displaydns(path):
    out = []
    ts = file_mtime_iso(path)
    cur = None
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                m = REC_NAME_RE.search(line)
                if m:
                    cur = m.group(1).strip()
                    continue
                a = A_REC_RE.search(line)
                if a and cur:
                    out.append({'Timestamp': ts, 'Entry': f'{cur} → {a.group(1).strip()}', 'Type': 'dns-cache', 'SourceFile': path, 'ComputerName': ''})
    except OSError:
        pass
    return out


def parse_dir(base):
    records = []
    for root_dir, _dirs, files in os.walk(base):
        for name in files:
            low = name.lower()
            path = os.path.join(root_dir, name)
            if low == 'hosts' and 'etc' in root_dir.lower():
                records += parse_hosts(path)
            elif 'displaydns' in low or ('dns' in low and 'cache' in low):
                records += parse_displaydns(path)
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--dir', required=True, help='Directory to walk')
    ap.add_argument('--csv', required=True, help='Output directory')
    ap.add_argument('--csvf', default='dns_results.csv', help='Output CSV filename')
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
    print(f'Parsed {len(records)} DNS/hosts entries -> {out_path}')


if __name__ == '__main__':
    main()
