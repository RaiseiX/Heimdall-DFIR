#!/usr/bin/env python3
"""
parse_srum.py — Linux-native Windows SRUM parser (replaces SrumECmd on Linux).

Uses dissect.esedb which reads ESE (Extensible Storage Engine) databases in
pure Python, without Windows DLLs.

Output CSV columns match SrumECmd output so collection.js timestamp/description
extraction works unchanged:
  timestampColumns : Timestamp, ConnectStartTime
  descriptionColumns: ExeInfo, AppId, SidType
  sourceColumn      : ExeInfo

SRUM tables parsed:
  {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}  Application Resource Usage
  {973F5D5C-1D90-4944-BE8E-24B94231A174}  Network Data Usage
  {DD6636C4-8929-4683-974E-22C046A43763}  Connected Network Usage (ConnectStartTime)
"""

import sys
import os
import csv
import struct
import argparse
from datetime import datetime, timedelta, timezone


# SRUM table GUIDs (verified against actual SRUDB.dat column names)
TABLE_APP_RESOURCE  = '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}'  # ForegroundCycleTime, BackgroundCycleTime
TABLE_NET_DATA      = '{973F5D5C-1D90-4944-BE8E-24B94231A174}'  # BytesSent, BytesRecvd
TABLE_CONNECTED_NET = '{DD6636C4-8929-4683-974E-22C046A43763}'  # ConnectedTime, ConnectStartTime
TABLE_ID_MAP        = 'SruDbIdMapTable'

# OADate epoch: days since 1899-12-30
_OADATE_EPOCH = datetime(1899, 12, 30, tzinfo=timezone.utc)


def oadate_to_iso(val):
    """Convert JET_coltyp.DateTime (OLE Automation Date stored as int64 bits) to ISO string."""
    if not val:
        return ''
    try:
        packed = struct.pack('<q', int(val))
        oa_date = struct.unpack('<d', packed)[0]
        if oa_date <= 0 or oa_date > 80000:  # sanity: before 1900 or after ~2119
            return ''
        dt = _OADATE_EPOCH + timedelta(days=oa_date)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''


def filetime_to_iso(ft):
    """Convert Windows FILETIME (100-ns ticks since 1601-01-01) to ISO string."""
    if not ft:
        return ''
    try:
        unix_ts = (int(ft) - 116_444_736_000_000_000) / 10_000_000
        if unix_ts <= 0 or unix_ts > 4_102_444_800:
            return ''
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''


def dt_to_iso(val):
    """Convert a datetime or int to ISO string (tries OADate first, then FILETIME)."""
    if val is None:
        return ''
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    if isinstance(val, int):
        # Try OADate first (JET_coltyp.DateTime stores as IEEE 754 double bits)
        result = oadate_to_iso(val)
        if result:
            return result
        # Fallback: Windows FILETIME
        return filetime_to_iso(val)
    return str(val)


def safe_str(v):
    return '' if v is None else str(v)


def build_id_map(db):
    """Build AppId index → readable name mapping from SruDbIdMapTable."""
    id_map = {}
    try:
        table = db.table(TABLE_ID_MAP)
        for rec in table.records():
            try:
                app_id  = rec.get('IdIndex') or rec.get('AppId') or None
                app_str = rec.get('IdBlob')  or rec.get('ExeInfo') or rec.get('App') or ''
                if isinstance(app_str, (bytes, bytearray)):
                    app_str = app_str.decode('utf-16-le', errors='replace').rstrip('\x00')
                if app_id is not None:
                    id_map[int(app_id)] = str(app_str)
            except Exception:
                pass
    except Exception:
        pass
    return id_map


def parse_app_resource(db, id_map):
    """Parse Application Resource Usage table ({D10CA2FE}) → list of dicts."""
    records = []
    try:
        table = db.table(TABLE_APP_RESOURCE)
    except Exception:
        return records

    for rec in table.records():
        try:
            app_id_raw = rec.get('AppId') or rec.get('AppID') or 0
            app_id_int = int(app_id_raw) if app_id_raw is not None else 0
            exe_info   = id_map.get(app_id_int, safe_str(app_id_raw))

            ts_raw = rec.get('TimeStamp') or rec.get('Timestamp') or None
            ts_iso = dt_to_iso(ts_raw)

            user_id = rec.get('UserId') or rec.get('UserID') or ''

            records.append({
                'Timestamp'                   : ts_iso,
                'AppId'                       : safe_str(app_id_raw),
                'ExeInfo'                     : exe_info,
                'UserId'                      : safe_str(user_id),
                'SidType'                     : '',
                'ForegroundCycleTime'         : safe_str(rec.get('ForegroundCycleTime') or ''),
                'BackgroundCycleTime'         : safe_str(rec.get('BackgroundCycleTime') or ''),
                'ForegroundContextSwitches'   : safe_str(rec.get('ForegroundContextSwitches') or ''),
                'BackgroundContextSwitches'   : safe_str(rec.get('BackgroundContextSwitches') or ''),
                'ForegroundBytesRead'         : safe_str(rec.get('ForegroundBytesRead') or ''),
                'ForegroundBytesWritten'      : safe_str(rec.get('ForegroundBytesWritten') or ''),
                'BackgroundBytesRead'         : safe_str(rec.get('BackgroundBytesRead') or ''),
                'BackgroundBytesWritten'      : safe_str(rec.get('BackgroundBytesWritten') or ''),
                'ConnectStartTime'            : '',
            })
        except Exception:
            pass

    return records


def parse_network_usage(db, id_map):
    """Parse Network Data Usage table ({973F5D5C}) → list of dicts."""
    records = []
    try:
        table = db.table(TABLE_NET_DATA)
    except Exception:
        return records

    for rec in table.records():
        try:
            app_id_raw = rec.get('AppId') or rec.get('AppID') or 0
            app_id_int = int(app_id_raw) if app_id_raw is not None else 0
            exe_info   = id_map.get(app_id_int, safe_str(app_id_raw))

            ts_raw = rec.get('TimeStamp') or rec.get('Timestamp') or None

            records.append({
                'Timestamp'                   : dt_to_iso(ts_raw),
                'AppId'                       : safe_str(app_id_raw),
                'ExeInfo'                     : exe_info,
                'UserId'                      : safe_str(rec.get('UserId') or ''),
                'SidType'                     : '',
                'ForegroundCycleTime'         : '',
                'BackgroundCycleTime'         : '',
                'ForegroundContextSwitches'   : '',
                'BackgroundContextSwitches'   : '',
                'ForegroundBytesRead'         : safe_str(rec.get('BytesSent') or ''),
                'ForegroundBytesWritten'      : safe_str(rec.get('BytesRecvd') or ''),
                'BackgroundBytesRead'         : '',
                'BackgroundBytesWritten'      : '',
                'ConnectStartTime'            : '',
            })
        except Exception:
            pass

    return records


def parse_connected_network(db, id_map):
    """Parse Connected Network Usage table ({DD6636C4}) → list of dicts (ConnectStartTime)."""
    records = []
    try:
        table = db.table(TABLE_CONNECTED_NET)
    except Exception:
        return records

    for rec in table.records():
        try:
            app_id_raw = rec.get('AppId') or rec.get('AppID') or 0
            app_id_int = int(app_id_raw) if app_id_raw is not None else 0
            exe_info   = id_map.get(app_id_int, safe_str(app_id_raw))

            ts_raw   = rec.get('TimeStamp') or rec.get('Timestamp') or None
            conn_raw = rec.get('ConnectStartTime') or None

            records.append({
                'Timestamp'                   : dt_to_iso(ts_raw),
                'AppId'                       : safe_str(app_id_raw),
                'ExeInfo'                     : exe_info,
                'UserId'                      : safe_str(rec.get('UserId') or ''),
                'SidType'                     : '',
                'ForegroundCycleTime'         : '',
                'BackgroundCycleTime'         : '',
                'ForegroundContextSwitches'   : '',
                'BackgroundContextSwitches'   : '',
                'ForegroundBytesRead'         : '',
                'ForegroundBytesWritten'      : '',
                'BackgroundBytesRead'         : '',
                'BackgroundBytesWritten'      : '',
                'ConnectStartTime'            : filetime_to_iso(conn_raw),
            })
        except Exception:
            pass

    return records


FIELDNAMES = [
    'Timestamp', 'AppId', 'ExeInfo', 'UserId', 'SidType',
    'ForegroundCycleTime', 'BackgroundCycleTime',
    'ForegroundContextSwitches', 'BackgroundContextSwitches',
    'ForegroundBytesRead', 'ForegroundBytesWritten',
    'BackgroundBytesRead', 'BackgroundBytesWritten',
    'ConnectStartTime',
]


def main():
    ap = argparse.ArgumentParser(description='Parse Windows SRUM database on Linux')
    ap.add_argument('-f', '--file',   required=True, help='Path to SRUDB.dat')
    ap.add_argument('-r', '--system', help='Path to SYSTEM registry hive (optional, ignored)')
    ap.add_argument('--csv',  required=True, help='Output directory for CSV')
    ap.add_argument('--csvf', default='srum_results.csv', help='Output CSV filename')
    args = ap.parse_args()

    try:
        from dissect.esedb import EseDB
    except ImportError:
        print('ERROR: dissect.esedb not installed — run: pip3 install dissect.esedb', file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.file):
        print(f'ERROR: File not found: {args.file}', file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.csv, exist_ok=True)

    try:
        with open(args.file, 'rb') as fh:
            db = EseDB(fh)
            id_map  = build_id_map(db)
            records = parse_app_resource(db, id_map)
            records += parse_network_usage(db, id_map)
            records += parse_connected_network(db, id_map)

    except Exception as e:
        print(f'ERROR parsing SRUDB.dat: {e}', file=sys.stderr)
        sys.exit(1)

    out_path = os.path.join(args.csv, args.csvf)
    with open(out_path, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(records)

    print(f'SRUDB.dat parsed — {len(records)} records written to {out_path}')


if __name__ == '__main__':
    main()
