#!/usr/bin/env python3
"""
parse_pwsh_history.py — PowerShell command history (PSReadLine).

ConsoleHost_history.txt records every command typed in PowerShell, per user. The
file has no per-line timestamps, so each command inherits the file's last-modified
time as a coarse timeline anchor. The value is the command content itself
(T1059.001) — it feeds the PowerShell-abuse detections.

Output CSV columns (consumed by collection.js):
  timestampColumns : Timestamp
  descriptionColumns: Command
  sourceColumn      : UserName
"""

import sys
import os
import re
import csv
import argparse
from datetime import datetime, timezone

FIELDNAMES = ['Timestamp', 'Command', 'UserName', 'SourceFile', 'ComputerName']
USER_RE = re.compile(r'[\\/]users[\\/]([^\\/]+)[\\/]', re.I)


def file_mtime_iso(path):
    try:
        return datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc).isoformat()
    except OSError:
        return ''


def parse_dir(base):
    records = []
    for root_dir, _dirs, files in os.walk(base):
        for name in files:
            if name.lower() != 'consolehost_history.txt':
                continue
            path = os.path.join(root_dir, name)
            ts = file_mtime_iso(path)
            m = USER_RE.search(path)
            user = m.group(1) if m else ''
            try:
                with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                    for line in fh:
                        cmd = line.rstrip('\r\n')
                        if cmd.strip():
                            records.append({
                                'Timestamp': ts,
                                'Command': cmd,
                                'UserName': user,
                                'SourceFile': path,
                                'ComputerName': '',
                            })
            except OSError:
                continue
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--dir', required=True, help='Directory to walk')
    ap.add_argument('--csv', required=True, help='Output directory')
    ap.add_argument('--csvf', default='pwsh_history_results.csv', help='Output CSV filename')
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
    print(f'Parsed {len(records)} PowerShell history commands -> {out_path}')


if __name__ == '__main__':
    main()
