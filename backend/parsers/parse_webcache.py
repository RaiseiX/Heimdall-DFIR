#!/usr/bin/env python3
"""
parse_webcache.py — IE / legacy-Edge browsing artifacts from WebCacheV01.dat.

WebCacheV01.dat is an ESE database. The `Containers` table maps each container id
to a type (History, Cookies, Content/Cache, iedownload…); each `Container_<id>`
table holds the URLs with access times. Read with dissect.esedb (pure Python).

Output CSV columns (consumed by collection.js):
  timestampColumns : AccessedTime, ModifiedTime
  descriptionColumns: Url
  sourceColumn      : ContainerType
"""

import sys
import os
import csv
import argparse
from datetime import datetime, timedelta, timezone

from dissect.esedb import EseDB

FIELDNAMES = ['AccessedTime', 'ModifiedTime', 'Url', 'ContainerType', 'AccessCount', 'Filename', 'ComputerName']


def to_str(v):
    if v is None:
        return ''
    if isinstance(v, bytes):
        for enc in ('utf-16-le', 'utf-8', 'latin-1'):
            try:
                return v.decode(enc).split('\x00', 1)[0].strip()
            except (UnicodeDecodeError, UnicodeError):
                continue
        return ''
    return str(v).split('\x00', 1)[0].strip()


def filetime_iso(ft):
    try:
        ft = int(ft)
    except (TypeError, ValueError):
        return ''
    if ft <= 0:
        return ''
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft / 10)).isoformat()
    except (OverflowError, ValueError):
        return ''


def container_type(name):
    n = (name or '').lower()
    if n.startswith('mshist') or n == 'history':
        return 'history'
    if 'cookie' in n:
        return 'cookies'
    if 'download' in n:
        return 'download'
    if 'content' in n or 'cache' in n:
        return 'cache'
    if 'dnt' in n or 'domstore' in n:
        return 'domstore'
    return name or 'container'


def parse(path):
    records = []
    try:
        fh = open(path, 'rb')
        db = EseDB(fh)
    except Exception as e:
        print(f'ERROR: cannot open ESE db: {e}', file=sys.stderr)
        return records

    # Map container id -> friendly type.
    id_type = {}
    try:
        for r in db.table('Containers').records():
            cid = r.get('ContainerId')
            if cid is not None:
                id_type[int(cid)] = container_type(to_str(r.get('Name')))
    except Exception:
        pass

    for table in db.tables():
        tname = getattr(table, 'name', '') or ''
        if not tname.startswith('Container_'):
            continue
        try:
            cid = int(tname.split('_', 1)[1])
        except (ValueError, IndexError):
            cid = None
        ctype = id_type.get(cid, 'container')
        try:
            rows = table.records()
        except Exception:
            continue
        for r in rows:
            url = to_str(r.get('Url'))
            if not url:
                continue
            # Strip the "Visited: user@" / "iedownload:" prefixes IE prepends.
            if '@' in url[:40] and ':' in url[:40]:
                url = url.split('@', 1)[-1]
            records.append({
                'AccessedTime': filetime_iso(r.get('AccessedTime')),
                'ModifiedTime': filetime_iso(r.get('ModifiedTime')),
                'Url': url,
                'ContainerType': ctype,
                'AccessCount': to_str(r.get('AccessCount')),
                'Filename': to_str(r.get('Filename')),
                'ComputerName': '',
            })
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--file', required=True, help='Path to WebCacheV01.dat')
    ap.add_argument('--csv', required=True, help='Output directory')
    ap.add_argument('--csvf', default='webcache_results.csv', help='Output CSV filename')
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
    print(f'Parsed {len(records)} WebCache entries -> {out_path}')


if __name__ == '__main__':
    main()
