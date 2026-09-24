#!/usr/bin/env python3
"""
parse_wxtcmd.py — Linux-native Windows Timeline parser (replaces WxTCmd on Linux).

Parses ActivitiesCache.db SQLite databases using Python's built-in sqlite3 module.
WxTCmd.dll cannot run on Linux because it requires SQLite.Interop.dll native library.

Output CSV columns:
  timestampColumns : StartTime, EndTime, LastModifiedTime
  descriptionColumns: AppId, DisplayText, Description
  sourceColumn      : AppId
"""

import sys
import os
import csv
import json
import argparse
import sqlite3
from datetime import datetime, timezone
from glob import glob


def unix_to_iso(ts):
    """Convert Unix timestamp (seconds) to ISO string."""
    if not ts:
        return ''
    try:
        t = int(ts)
        if t <= 0 or t > 4_102_444_800:
            return ''
        return datetime.fromtimestamp(t, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''


def extract_app_name(app_id_json):
    """Extract human-readable app name from AppId JSON array."""
    if not app_id_json:
        return ''
    try:
        entries = json.loads(app_id_json)
        if isinstance(entries, list) and entries:
            return entries[0].get('application', '') or entries[0].get('packageId', '')
    except Exception:
        pass
    return str(app_id_json)[:120]


def extract_display_text(payload_blob):
    """Try to extract display text from Payload (UTF-16 CBOR prefix or plain text)."""
    if not payload_blob:
        return ''
    try:
        # Try decoding as UTF-16-LE after 4-byte CBOR header
        if len(payload_blob) > 4:
            text = payload_blob[4:].decode('utf-16-le', errors='ignore').rstrip('\x00')
            if text and len(text) > 2:
                # Strip control chars, keep printable
                clean = ''.join(c for c in text if c.isprintable() or c in ' \t')
                if clean.strip():
                    return clean.strip()[:256]
    except Exception:
        pass
    return ''


ACTIVITY_TYPE_MAP = {
    1: 'Open',
    2: 'Close',
    3: 'Launch',
    5: 'UserInteraction',
    6: 'SwitchWindow',
    10: 'CopyPaste',
    11: 'InFocus',
    12: 'System',
    15: 'Notification',
    16: 'Copy',
    23: 'MessageInteraction',
}

FIELDNAMES = ['StartTime', 'EndTime', 'LastModifiedTime', 'AppId', 'DisplayText', 'Description',
              'ActivityType', 'SourceFile']


def parse_activities_db(db_path, source_name):
    """Parse a single ActivitiesCache.db and return records list."""
    records = []
    try:
        conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            'SELECT AppId, StartTime, EndTime, LastModifiedTime, ActivityType, Payload '
            'FROM Activity WHERE ActivityStatus != 3 ORDER BY StartTime DESC'
        ).fetchall()
        conn.close()
    except Exception as e:
        return records

    for row in rows:
        try:
            app_name = extract_app_name(row['AppId'])
            display  = extract_display_text(row['Payload'])
            act_type = ACTIVITY_TYPE_MAP.get(row['ActivityType'], str(row['ActivityType'] or ''))
            records.append({
                'StartTime'        : unix_to_iso(row['StartTime']),
                'EndTime'          : unix_to_iso(row['EndTime']),
                'LastModifiedTime' : unix_to_iso(row['LastModifiedTime']),
                'AppId'            : app_name,
                'DisplayText'      : display,
                'Description'      : act_type,
                'ActivityType'     : str(row['ActivityType'] or ''),
                'SourceFile'       : source_name,
            })
        except Exception:
            pass

    return records


def main():
    ap = argparse.ArgumentParser(description='Parse Windows Timeline (ActivitiesCache.db) on Linux')
    ap.add_argument('-d', '--dir',  required=True, help='Directory containing ActivitiesCache.db files (recursive scan)')
    ap.add_argument('--csv',  required=True, help='Output directory for CSV')
    ap.add_argument('--csvf', default='wxtcmd_results.csv', help='Output CSV filename')
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        print(f'ERROR: Directory not found: {args.dir}', file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.csv, exist_ok=True)

    # Find all ActivitiesCache.db files recursively
    db_files = []
    for root, dirs, files in os.walk(args.dir):
        for fname in files:
            if fname.lower() == 'activitiescache.db':
                db_files.append(os.path.join(root, fname))

    all_records = []
    for db_path in db_files:
        recs = parse_activities_db(db_path, os.path.basename(os.path.dirname(db_path)))
        all_records.extend(recs)

    out_path = os.path.join(args.csv, args.csvf)
    with open(out_path, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(all_records)

    print(f'ActivitiesCache.db parsed — {len(all_records)} records from {len(db_files)} database(s) written to {out_path}')


if __name__ == '__main__':
    main()
