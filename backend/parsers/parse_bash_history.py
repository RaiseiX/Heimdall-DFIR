#!/usr/bin/env python3
"""
parse_bash_history.py — bash / zsh history parser.

Handles two formats:
  1. Plain (no timestamps):  one command per line.
  2. Extended HISTTIMEFORMAT: alternating lines of `#<epoch>` then command.
     bash: set by HISTTIMEFORMAT env var
     zsh:  set by EXTENDED_HISTORY (adds ': <epoch>:<elapsed>;<cmd>')

Output CSV columns (consumed by collection.js):
  timestampColumns : Timestamp  (empty string when unavailable)
  descriptionColumns: Command
  sourceColumn      : UserName
"""
import sys
import os
import re
import csv
import argparse
from datetime import datetime, timezone

FIELDNAMES = ['Timestamp', 'UserName', 'Shell', 'Command', 'SourceFile']

# zsh extended_history: ": 1700000000:0;sudo rm -rf /"
ZSH_RE = re.compile(r'^:\s*(\d+):\d+;(.*)$')

TARGET_NAMES = {
    '.bash_history', '.zsh_history', '.zhistory', 'bash_history', 'zsh_history',
}


def epoch_to_iso(s):
    try:
        return datetime.fromtimestamp(int(s), tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        return ''


def detect_shell(filename):
    lname = os.path.basename(filename).lower()
    if 'zsh' in lname or lname in ('.zsh_history', '.zhistory'):
        return 'zsh'
    return 'bash'


def parse_file(path):
    records = []
    shell = detect_shell(path)
    # Heuristic: infer username from path component like /home/<user>/
    username = ''
    parts = path.replace('\\', '/').split('/')
    if 'home' in parts:
        idx = parts.index('home')
        if idx + 1 < len(parts):
            username = parts[idx + 1]

    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
    except OSError as e:
        print(f'ERROR reading {path}: {e}', file=sys.stderr)
        return records

    i = 0
    pending_ts = ''
    while i < len(lines):
        line = lines[i].rstrip('\r\n')
        i += 1
        if not line:
            continue

        # zsh extended history
        zm = ZSH_RE.match(line)
        if zm:
            ts  = epoch_to_iso(zm.group(1))
            cmd = zm.group(2)
            records.append({'Timestamp': ts, 'UserName': username, 'Shell': shell,
                            'Command': cmd, 'SourceFile': path})
            continue

        # bash extended history: timestamp line
        if line.startswith('#') and len(line) > 1 and line[1:].isdigit():
            pending_ts = epoch_to_iso(line[1:])
            continue

        # plain command (possibly following a #epoch line)
        records.append({'Timestamp': pending_ts, 'UserName': username, 'Shell': shell,
                        'Command': line, 'SourceFile': path})
        pending_ts = ''

    return records


def parse_dir(base):
    records = []
    for root, _dirs, files in os.walk(base):
        for name in sorted(files):
            if name.lower() in TARGET_NAMES:
                records.extend(parse_file(os.path.join(root, name)))
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--dir', required=True, help='Directory to scan for history files')
    ap.add_argument('--csv', required=True, help='Output directory')
    ap.add_argument('--csvf', default='bash_history_results.csv', help='Output CSV filename')
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
    print(f'Parsed {len(records)} history entries -> {out_path}')


if __name__ == '__main__':
    main()
