#!/usr/bin/env python3
"""
parse_prefetch.py — Linux-native Windows Prefetch parser (replaces PECmd on Linux).

Priority:
  1. dissect.target.Prefetch — pure Python, handles ALL versions incl. Win10/11 v30/v31
     MAM (LZXPRESS Huffman) decompression + format parsing.
  2. pyscca (python3-libscca) — fallback for v17/v23/v26 if dissect unavailable.

Output CSV columns match PECmd output so collection.js timestamp/description
extraction works unchanged:
  timestampColumns : LastRun, SourceCreated, SourceModified
  descriptionColumns: ExecutableName, RunCount, Hash
  sourceColumn      : SourceFilename
"""

import sys
import os
import csv
import glob
import struct
import argparse
from datetime import datetime, timezone


def dt_to_iso(dt):
    """Convert a datetime object (aware or naive UTC) to ISO string."""
    if dt is None:
        return ''
    try:
        if hasattr(dt, 'tzinfo') and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
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


def parse_one_dissect(pf_path):
    """
    Parse with dissect.target.Prefetch — supports ALL versions including Win10/11 v30/v31
    (handles MAM/LZXPRESS Huffman decompression internally).
    """
    from dissect.target.plugins.os.windows.prefetch import Prefetch
    from io import BytesIO

    with open(pf_path, 'rb') as f:
        data = f.read()

    pf = Prefetch(BytesIO(data))

    # Executable name: at header offset 16, 60 bytes (30 WCHAR, null-terminated)
    pf.fh.seek(16)
    exe_raw = pf.fh.read(60)
    exe_name = exe_raw.decode('utf-16-le', errors='replace').rstrip('\x00')

    # Prefetch hash: at offset 76 (DWORD LE)
    pf.fh.seek(76)
    pf_hash = format(struct.unpack('<I', pf.fh.read(4))[0], '08X')

    # Hash fallback from filename
    if not pf_hash or pf_hash == '00000000':
        base = os.path.basename(pf_path)
        if '-' in base:
            pf_hash = base.rsplit('-', 1)[-1].upper().replace('.PF', '').replace('.pf', '')

    run_count = pf.fn.run_count if pf.fn else 0

    # Timestamps
    last_run = dt_to_iso(pf.latest_timestamp)
    prev_timestamps = pf.previous_timestamps or []
    prev_runs = [dt_to_iso(t) for t in prev_timestamps[:7]]
    while len(prev_runs) < 7:
        prev_runs.append('')

    # File metadata from original .pf file
    source_created = ''
    source_modified = ''
    try:
        stat = os.stat(pf_path)
        source_created  = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        source_modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        pass

    return {
        'SourceFilename' : os.path.basename(pf_path),
        'SourceCreated'  : source_created,
        'SourceModified' : source_modified,
        'SourceAccessed' : '',
        'LastRun'        : last_run,
        'PreviousRun0'   : prev_runs[0],
        'PreviousRun1'   : prev_runs[1],
        'PreviousRun2'   : prev_runs[2],
        'PreviousRun3'   : prev_runs[3],
        'PreviousRun4'   : prev_runs[4],
        'PreviousRun5'   : prev_runs[5],
        'PreviousRun6'   : prev_runs[6],
        'RunCount'       : str(run_count),
        'ExecutableName' : exe_name,
        'Hash'           : pf_hash,
        'Size'           : str(os.path.getsize(pf_path)),
    }


def parse_one_pyscca(pf_path):
    """Fallback: parse with pyscca (python3-libscca). Supports v17/v23/v26 only."""
    try:
        import libscca
    except ImportError:
        import pyscca as libscca

    scca_file = libscca.file()
    scca_file.open(pf_path)

    try:
        exe_name = scca_file.executable_filename or ''
    except Exception:
        exe_name = ''

    try:
        pf_hash = format(scca_file.prefetch_hash, '08X') if scca_file.prefetch_hash else ''
    except Exception:
        pf_hash = ''

    if not pf_hash:
        base = os.path.basename(pf_path)
        if '-' in base:
            pf_hash = base.rsplit('-', 1)[-1].upper().replace('.PF', '').replace('.pf', '')

    try:
        run_count = int(scca_file.run_count or 0)
    except Exception:
        run_count = 0

    run_times_iso = []
    for i in range(8):
        try:
            ft = scca_file.get_last_run_time_as_integer(i)
            run_times_iso.append(filetime_to_iso(ft))
        except Exception:
            try:
                dt = scca_file.get_last_run_time(i)
                run_times_iso.append(dt_to_iso(dt))
            except Exception:
                run_times_iso.append('')

    while len(run_times_iso) > 1 and not run_times_iso[-1]:
        run_times_iso.pop()
    while len(run_times_iso) < 8:
        run_times_iso.append('')

    last_run = run_times_iso[0]
    prev_runs = run_times_iso[1:8]
    scca_file.close()

    source_created = ''
    source_modified = ''
    try:
        stat = os.stat(pf_path)
        source_created  = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        source_modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        pass

    return {
        'SourceFilename' : os.path.basename(pf_path),
        'SourceCreated'  : source_created,
        'SourceModified' : source_modified,
        'SourceAccessed' : '',
        'LastRun'        : last_run,
        'PreviousRun0'   : prev_runs[0],
        'PreviousRun1'   : prev_runs[1],
        'PreviousRun2'   : prev_runs[2],
        'PreviousRun3'   : prev_runs[3],
        'PreviousRun4'   : prev_runs[4],
        'PreviousRun5'   : prev_runs[5],
        'PreviousRun6'   : prev_runs[6],
        'RunCount'       : str(run_count),
        'ExecutableName' : exe_name,
        'Hash'           : pf_hash,
        'Size'           : str(os.path.getsize(pf_path)),
    }


# Check dissect availability once at import time
try:
    from dissect.target.plugins.os.windows.prefetch import Prefetch as _DissectPrefetch
    _HAVE_DISSECT = True
except ImportError:
    _HAVE_DISSECT = False

try:
    try:
        import libscca as _pyscca_mod
    except ImportError:
        import pyscca as _pyscca_mod
    _HAVE_PYSCCA = True
except ImportError:
    _HAVE_PYSCCA = False


def parse_one(pf_path):
    """
    Parse a single .pf file. Tries dissect first (all versions), then pyscca (v17/23/26).
    Returns a dict with PECmd-compatible column names, or None on failure.
    """
    if _HAVE_DISSECT:
        try:
            return parse_one_dissect(pf_path)
        except Exception as e:
            if _HAVE_PYSCCA:
                try:
                    return parse_one_pyscca(pf_path)
                except Exception:
                    pass
            print(f'  skip {os.path.basename(pf_path)}: {e}', file=sys.stderr)
            return None
    elif _HAVE_PYSCCA:
        try:
            return parse_one_pyscca(pf_path)
        except Exception as e:
            print(f'  skip {os.path.basename(pf_path)}: {e}', file=sys.stderr)
            return None
    else:
        print('ERROR: neither dissect nor pyscca available', file=sys.stderr)
        sys.exit(1)


FIELDNAMES = [
    'SourceFilename', 'SourceCreated', 'SourceModified', 'SourceAccessed',
    'LastRun', 'PreviousRun0', 'PreviousRun1', 'PreviousRun2', 'PreviousRun3',
    'PreviousRun4', 'PreviousRun5', 'PreviousRun6',
    'RunCount', 'ExecutableName', 'Hash', 'Size',
]


def main():
    ap = argparse.ArgumentParser(description='Parse Windows Prefetch files on Linux')
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument('-d', '--directory', help='Directory to scan recursively for .pf files')
    grp.add_argument('-f', '--file',      help='Single .pf file to parse')
    ap.add_argument('--csv',  required=True, help='Output directory for CSV')
    ap.add_argument('--csvf', default='prefetch_results.csv', help='Output CSV filename')
    args = ap.parse_args()

    os.makedirs(args.csv, exist_ok=True)

    if args.directory:
        pf_files = []
        for ext in ('*.pf', '*.PF'):
            pf_files.extend(glob.glob(os.path.join(args.directory, '**', ext), recursive=True))
        pf_files = sorted(set(pf_files))
    else:
        pf_files = [args.file]

    if not pf_files:
        print('No prefetch files found', file=sys.stderr)
        sys.exit(0)

    records = []
    for pf_path in pf_files:
        rec = parse_one(pf_path)
        if rec:
            records.append(rec)

    out_path = os.path.join(args.csv, args.csvf)
    with open(out_path, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(records)

    print(f'Processed {len(pf_files)} file(s) — {len(records)} records written to {out_path}')


if __name__ == '__main__':
    main()
