#!/usr/bin/env python3
"""
parse_userassist.py — UserAssist (GUI program execution evidence) from NTUSER.DAT.

Reads Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist via
dissect.regf (pure Python, no Windows DLLs). Value names are ROT13-encoded; the
binary data (v5, Win7+) carries the run count and the last-executed FILETIME.

Output CSV columns (consumed by collection.js):
  timestampColumns : LastExecuted
  descriptionColumns: ProgramName, RunCount
  sourceColumn      : ProgramName
"""

import sys
import os
import csv
import codecs
import struct
import argparse
from datetime import datetime, timedelta, timezone

try:
    from dissect.regf import regf
except ImportError as _e:
    print(f'ERROR: dissect.regf not installed — run: pip3 install "dissect.regf>=3" ({_e})', file=sys.stderr)
    sys.exit(2)

FIELDNAMES = ['LastExecuted', 'ProgramName', 'RunCount', 'FocusCount', 'UserName', 'ComputerName']
UA_PATH = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"


def filetime_iso(ft):
    if not ft:
        return ''
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft / 10)).isoformat()
    except (OverflowError, ValueError):
        return ''


def parse(path):
    records = []
    try:
        hive = regf.RegistryHive(open(path, 'rb'))
    except Exception as e:
        print(f'ERROR: cannot open hive: {e}', file=sys.stderr)
        return records
    try:
        ua = hive.open(UA_PATH)
    except Exception:
        return records  # key absent → nothing to do

    for guid in ua.subkeys():
        try:
            count = guid.subkey('Count')
        except Exception:
            continue
        if count is None:
            continue
        for v in count.values():
            try:
                name = codecs.decode(v.name, 'rot_13')
            except Exception:
                name = v.name
            if not name or name.startswith('UEME_CTL'):
                continue
            run_count = None
            focus_count = None
            last = ''
            try:
                # dissect.regf v3+: v.data may be a typed object; coerce to bytes.
                raw = v.data
                if not isinstance(raw, (bytes, bytearray)):
                    try:
                        raw = bytes(raw)
                    except Exception:
                        raw = b''
                if raw and len(raw) >= 68:
                    run_count = struct.unpack_from('<I', raw, 4)[0]
                    focus_count = struct.unpack_from('<I', raw, 8)[0]
                    ft = struct.unpack_from('<Q', raw, 60)[0]
                    last = filetime_iso(ft)
            except Exception:
                pass
            records.append({
                'LastExecuted': last,
                'ProgramName': name,
                'RunCount': run_count if run_count is not None else '',
                'FocusCount': focus_count if focus_count is not None else '',
                'UserName': '',
                'ComputerName': '',
            })
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--file', required=True, help='Path to NTUSER.DAT')
    ap.add_argument('--csv', required=True, help='Output directory')
    ap.add_argument('--csvf', default='userassist_results.csv', help='Output CSV filename')
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        print(f'ERROR: File not found: {args.file}', file=sys.stderr)
        sys.exit(1)
    os.makedirs(args.csv, exist_ok=True)
    records = parse(args.file)
    out_path = os.path.join(args.csv, args.csvf)
    with open(out_path, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(records)
    print(f'Parsed {len(records)} UserAssist entries -> {out_path}')


if __name__ == '__main__':
    main()
