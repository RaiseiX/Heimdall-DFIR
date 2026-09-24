#!/usr/bin/env python3
"""
parse_sqle.py — Linux-native browser history parser (replaces SQLECmd on Linux).

SQLECmd.dll cannot run on Linux because it requires SQLite.Interop.dll native library.
This script uses Python's built-in sqlite3 module.

Supported databases:
  - Chromium/Edge History (urls, visits, downloads)
  - Firefox places.sqlite (moz_places, moz_historyvisits, moz_downloads)
  - Any SQLite with 'urls' or 'moz_places' table (heuristic detection)

Output CSV columns:
  timestampColumns : LastVisitDate, VisitDate, StartTime
  descriptionColumns: URL, Title, VisitCount
  sourceColumn      : SourceFile
"""

import sys
import os
import csv
import argparse
import sqlite3
from datetime import datetime, timezone


FIELDNAMES = ['LastVisitDate', 'VisitDate', 'StartTime', 'URL', 'Title',
              'VisitCount', 'SourceType', 'Profile', 'SourceFile']


def webkit_to_iso(wk):
    """Convert WebKit timestamp (microseconds since 1601-01-01) to ISO string."""
    if not wk:
        return ''
    try:
        t = int(wk)
        if t <= 0:
            return ''
        unix_sec = t / 1_000_000 - 11_644_473_600
        if unix_sec <= 0 or unix_sec > 4_102_444_800:
            return ''
        return datetime.fromtimestamp(unix_sec, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''


def prtime_to_iso(prt):
    """Convert Firefox PRTime (microseconds since 1970-01-01) to ISO string."""
    if not prt:
        return ''
    try:
        t = int(prt)
        if t <= 0:
            return ''
        unix_sec = t / 1_000_000
        if unix_sec <= 0 or unix_sec > 4_102_444_800:
            return ''
        return datetime.fromtimestamp(unix_sec, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''


def detect_browser(conn):
    """Return browser type: 'chromium', 'firefox', or None."""
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'urls' in tables and 'visits' in tables:
        return 'chromium'
    if 'moz_places' in tables:
        return 'firefox'
    return None


def parse_chromium(conn, source_file, profile_name):
    """Parse Chromium/Edge History database."""
    records = []
    try:
        rows = conn.execute(
            'SELECT u.url, u.title, u.visit_count, u.last_visit_time '
            'FROM urls u ORDER BY u.last_visit_time DESC'
        ).fetchall()
        for r in rows:
            records.append({
                'LastVisitDate' : webkit_to_iso(r[3]),
                'VisitDate'     : webkit_to_iso(r[3]),
                'StartTime'     : '',
                'URL'           : str(r[0] or ''),
                'Title'         : str(r[1] or ''),
                'VisitCount'    : str(r[2] or ''),
                'SourceType'    : 'Browser_URL',
                'Profile'       : profile_name,
                'SourceFile'    : source_file,
            })
    except Exception:
        pass

    # Downloads
    try:
        rows = conn.execute(
            'SELECT target_path, start_time, total_bytes, state FROM downloads ORDER BY start_time DESC'
        ).fetchall()
        for r in rows:
            records.append({
                'LastVisitDate' : webkit_to_iso(r[1]),
                'VisitDate'     : webkit_to_iso(r[1]),
                'StartTime'     : webkit_to_iso(r[1]),
                'URL'           : str(r[0] or ''),
                'Title'         : f'Download ({r[2] or 0} bytes, state={r[3]})',
                'VisitCount'    : '',
                'SourceType'    : 'Browser_Download',
                'Profile'       : profile_name,
                'SourceFile'    : source_file,
            })
    except Exception:
        pass

    return records


def parse_firefox(conn, source_file, profile_name):
    """Parse Firefox places.sqlite database."""
    records = []
    try:
        rows = conn.execute(
            'SELECT p.url, p.title, p.visit_count, p.last_visit_date '
            'FROM moz_places p ORDER BY p.last_visit_date DESC NULLS LAST'
        ).fetchall()
        for r in rows:
            records.append({
                'LastVisitDate' : prtime_to_iso(r[3]),
                'VisitDate'     : prtime_to_iso(r[3]),
                'StartTime'     : '',
                'URL'           : str(r[0] or ''),
                'Title'         : str(r[1] or ''),
                'VisitCount'    : str(r[2] or ''),
                'SourceType'    : 'Browser_URL',
                'Profile'       : profile_name,
                'SourceFile'    : source_file,
            })
    except Exception:
        pass
    return records


def infer_profile(db_path):
    """Extract profile name from path (e.g. 'Default', 'Profile 1', 'theol')."""
    parts = db_path.replace('\\', '/').split('/')
    # Look for 'Profile *', 'Default', or Users/<name>
    for i, p in enumerate(parts):
        if p.lower().startswith('profile') or p.lower() == 'default':
            return p
    for i, p in enumerate(parts):
        if p.lower() == 'users' and i + 1 < len(parts):
            return parts[i + 1]
    return os.path.basename(os.path.dirname(db_path))


def parse_db(db_path):
    """Parse a single SQLite history file, return list of records."""
    try:
        conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
    except Exception:
        try:
            conn = sqlite3.connect(db_path)
        except Exception:
            return []

    browser = detect_browser(conn)
    if not browser:
        conn.close()
        return []

    profile = infer_profile(db_path)
    src = os.path.basename(db_path)

    if browser == 'chromium':
        records = parse_chromium(conn, src, profile)
    else:
        records = parse_firefox(conn, src, profile)

    conn.close()
    return records


def is_sqlite(path):
    """Check file starts with SQLite magic."""
    try:
        with open(path, 'rb') as f:
            return f.read(6) == b'SQLite'
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description='Parse browser SQLite history databases on Linux')
    ap.add_argument('-d', '--dir',  required=True, help='Collection directory (recursive scan)')
    ap.add_argument('--csv',  required=True, help='Output directory for CSV')
    ap.add_argument('--csvf', default='sqle_results.csv', help='Output CSV filename')
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        print(f'ERROR: Directory not found: {args.dir}', file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.csv, exist_ok=True)

    # Target filenames (Chromium and Firefox history databases)
    TARGET_NAMES = {
        'history', 'places.sqlite', 'cookies', 'web data',
        'formhistory.sqlite', 'downloads.sqlite',
    }

    all_records = []
    db_count = 0

    for root, dirs, files in os.walk(args.dir):
        for fname in files:
            if fname.lower() in TARGET_NAMES:
                full = os.path.join(root, fname)
                if is_sqlite(full):
                    recs = parse_db(full)
                    if recs:
                        all_records.extend(recs)
                        db_count += 1

    out_path = os.path.join(args.csv, args.csvf)
    with open(out_path, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(all_records)

    print(f'Browser history parsed — {len(all_records)} records from {db_count} database(s) written to {out_path}')


if __name__ == '__main__':
    main()
