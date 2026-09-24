#!/usr/bin/env python3
"""
parse_unified_log.py — macOS Unified Log parser.

Accepts files exported from a .logarchive via:
  log show --style json   --output unified.json
  log show --style syslog --output unified.txt

Auto-detects format per file. Walks a directory for *.json / *.log / *.txt
that look like Unified Log exports.

Output CSV columns (consumed by collection.js):
  timestampColumns : Timestamp
  descriptionColumns: ProcessName, Message
  sourceColumn      : ProcessName
"""
import sys
import os
import re
import csv
import json
import argparse
from datetime import datetime, timezone

FIELDNAMES = ['Timestamp', 'HostName', 'ProcessName', 'ProcessID',
              'Subsystem', 'Category', 'Level', 'Message', 'SourceFile']

# Text/syslog format: "2024-01-01 00:00:00.000000+0000 host proc[pid] <Level>: msg"
TEXT_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+[+-]\d{4})\s+'
    r'(\S+)\s+([\w\-\.\/\(\)]+?)(?:\[(\d+)\])?\s+<(\w+)>:\s+(.*)$'
)

LEVEL_SEV = {
    'Fault':   'critical',
    'Error':   'high',
    'Default': 'medium',
    'Info':    'low',
    'Debug':   'info',
}


def ts_normalise(s):
    """Normalise 'YYYY-MM-DD HH:MM:SS.ffffff±HHMM' → ISO-8601."""
    try:
        s = s.strip()
        # Insert colon in timezone offset if missing: +0000 → +00:00
        s = re.sub(r'([+-])(\d{2})(\d{2})$', r'\1\2:\3', s)
        s = s.replace(' ', 'T', 1)
        return datetime.fromisoformat(s).astimezone(timezone.utc).isoformat()
    except Exception:
        return s


def parse_json_file(path):
    """Parse log show --style json output."""
    records = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            return records
        for entry in data:
            if not isinstance(entry, dict):
                continue
            raw_ts  = entry.get('timestamp', '')
            ts      = ts_normalise(raw_ts) if raw_ts else ''
            proc    = (entry.get('processImagePath') or '').split('/')[-1]
            if not proc:
                proc = str(entry.get('senderImagePath', '')).split('/')[-1]
            pid     = str(entry.get('processID', ''))
            host    = entry.get('hostName', entry.get('machineID', ''))
            sub     = entry.get('subsystem', '')
            cat     = entry.get('category', '')
            lvl     = entry.get('messageType', 'Default')
            msg     = entry.get('eventMessage', '')
            records.append({
                'Timestamp':   ts,
                'HostName':    host,
                'ProcessName': proc,
                'ProcessID':   pid,
                'Subsystem':   sub,
                'Category':    cat,
                'Level':       lvl,
                'Message':     str(msg)[:500],
                'SourceFile':  path,
            })
    except (json.JSONDecodeError, OSError) as e:
        print(f'ERROR parsing JSON {path}: {e}', file=sys.stderr)
    return records


def parse_text_file(path):
    """Parse log show --style syslog output."""
    records = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.rstrip('\r\n')
                if not line or line.startswith('---') or line.startswith('Filtering'):
                    continue
                m = TEXT_RE.match(line)
                if not m:
                    continue
                records.append({
                    'Timestamp':   ts_normalise(m.group(1)),
                    'HostName':    m.group(2),
                    'ProcessName': m.group(3),
                    'ProcessID':   m.group(4) or '',
                    'Subsystem':   '',
                    'Category':    '',
                    'Level':       m.group(5),
                    'Message':     m.group(6)[:500],
                    'SourceFile':  path,
                })
    except OSError as e:
        print(f'ERROR reading {path}: {e}', file=sys.stderr)
    return records


def is_unified_log_json(path):
    """Peek at file to decide if it's a JSON array of log entries."""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            head = fh.read(256).lstrip()
        return head.startswith('[') and 'timestamp' in head
    except OSError:
        return False


def parse_dir(base):
    records = []
    for root, _dirs, files in os.walk(base):
        for name in sorted(files):
            lname = name.lower()
            fpath = os.path.join(root, name)
            if lname.endswith('.json'):
                if is_unified_log_json(fpath):
                    records.extend(parse_json_file(fpath))
            elif lname.endswith(('.log', '.txt')):
                records.extend(parse_text_file(fpath))
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--dir', required=True,
                    help='Directory containing exported Unified Log files')
    ap.add_argument('--csv',  required=True, help='Output directory')
    ap.add_argument('--csvf', default='unified_log_results.csv',
                    help='Output CSV filename')
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
    print(f'Parsed {len(records)} Unified Log entries -> {out_path}')


if __name__ == '__main__':
    main()
