#!/usr/bin/env python3
"""
parse_usb.py — USB device install history from C:\\Windows\\INF\\setupapi.dev.log.

setupapi.dev.log records every device installation with a precise timestamp.
For USB mass-storage / HID devices this gives the *first-insertion* time, which
the registry (USBSTOR) alone does not provide. Pure text parsing — no dependency.

Output CSV columns (consumed by collection.js):
  timestampColumns : Timestamp
  descriptionColumns: DeviceDescription, DeviceInstanceId
  sourceColumn      : DeviceInstanceId
"""

import sys
import os
import re
import csv
import argparse
from datetime import datetime, timezone

FIELDNAMES = ['Timestamp', 'DeviceDescription', 'DeviceInstanceId', 'Event', 'ComputerName']

# >>>  [Device Install (Hardware initiated) - USB\VID_0781&PID_5567\0123456789ABCDEF]
HEADER_RE = re.compile(r'>>>\s+\[Device Install[^\]]*-\s*(?P<id>[^\]]+)\]')
# >>>  Section start 2024/01/15 10:23:45.123
START_RE  = re.compile(r'>>>\s+Section start\s+(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})')

USB_RE = re.compile(r'USBSTOR|USB\\VID_|WPDBUSENUM|SWD\\WPDBUSENUM', re.I)


def parse(path):
    records = []
    pending_id = None
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                m = HEADER_RE.search(line)
                if m:
                    pending_id = m.group('id').strip()
                    continue
                if pending_id is not None:
                    s = START_RE.search(line)
                    if s:
                        # Only keep storage/portable-device installs (USB exfil relevance).
                        if USB_RE.search(pending_id):
                            try:
                                dt = datetime.strptime(s.group('ts'), '%Y/%m/%d %H:%M:%S').replace(tzinfo=timezone.utc)
                                ts = dt.isoformat()
                            except ValueError:
                                ts = ''
                            desc = pending_id.split('\\')[-2] if '\\' in pending_id else pending_id
                            records.append({
                                'Timestamp': ts,
                                'DeviceDescription': desc,
                                'DeviceInstanceId': pending_id,
                                'Event': 'Device install (setupapi)',
                                'ComputerName': '',
                            })
                        pending_id = None
    except OSError as e:
        print(f'ERROR: {e}', file=sys.stderr)
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--file', required=True, help='Path to setupapi.dev.log')
    ap.add_argument('--csv', required=True, help='Output directory')
    ap.add_argument('--csvf', default='usb_results.csv', help='Output CSV filename')
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
    print(f'Parsed {len(records)} USB device install events -> {out_path}')


if __name__ == '__main__':
    main()
