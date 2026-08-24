#!/usr/bin/env python3
"""
parse_registry_full.py — dump EVERY key and value of a registry hive to CSV.

RECmd's curated batch files only extract a subset of keys (e.g. WinSCP sessions
can be missing), while the hive explorer (parse_hive_browse.py) shows the whole
hive. This parser gives the timeline the SAME full coverage as the explorer:
one row per value, walking the entire hive with dissect.regf (pure Python,
already installed in the image).

Usage:
  parse_registry_full.py -f <hive> --csv <output.csv>

CSV columns (aligned with the RECmd schema the pipeline already consumes):
  HivePath, KeyPath, ValueName, ValueType, ValueData, LastWriteTimestamp, Description

Robustness: every per-key / per-value access is guarded — a corrupt key or an
undecodable value never aborts the walk of the rest of the hive (a single
exception used to truncate the CSV and silently drop everything after it,
e.g. the WinSCP keys living deep in the tree).
"""
import sys
import os
import csv
import argparse
from datetime import datetime, timezone

try:
    from dissect.regf import regf
except ImportError as e:
    print(f'ERROR: dissect.regf not installed — run: pip3 install "dissect.regf>=3" ({e})', file=sys.stderr)
    sys.exit(2)

TYPE_NAMES = {
    0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY',
    4: 'REG_DWORD', 5: 'REG_DWORD_BIG_ENDIAN', 6: 'REG_LINK', 7: 'REG_MULTI_SZ',
    8: 'REG_RESOURCE_LIST', 9: 'REG_FULL_RESOURCE_DESCRIPTOR',
    10: 'REG_RESOURCE_REQUIREMENTS_LIST', 11: 'REG_QWORD',
}

# Cap the hex dump of binary values so a pathological value never bloats the CSV.
MAX_DATA = 16384


def fmt_ts(dt):
    if not dt:
        return ''
    try:
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''


def fmt_value(v):
    """Human-readable value data: strings/numbers decoded, binary as hex."""
    try:
        raw = v.data
        if not isinstance(raw, (bytes, bytearray)):
            raw = bytes(raw)
    except Exception:
        raw = b''
    val_type = int(getattr(v, 'type', 0) or 0)
    if val_type in (1, 2, 4, 5, 11, 7):  # SZ / EXPAND_SZ / DWORD / DWORD_BE / QWORD / MULTI_SZ
        try:
            val = v.value
            if isinstance(val, list):
                val = '\n'.join(str(x) for x in val)
            text = str(val)
            # Drop lone surrogates / control chars so csv + utf-8 encoding never
            # raises mid-walk (which used to truncate the CSV at that value).
            text = ''.join(ch for ch in text if ch == '\n' or ch == '\t' or (ord(ch) >= 32 and not 0xD800 <= ord(ch) <= 0xDFFF))
            return text[:MAX_DATA]
        except Exception:
            pass
    return raw[:MAX_DATA].hex()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--file', required=True, help='Path to the registry hive file')
    ap.add_argument('--csv', required=True, help='Output CSV file path')
    args = ap.parse_args()

    try:
        hive = regf.RegistryHive(open(args.file, 'rb'))
    except Exception as e:
        print(f'ERROR: cannot open hive: {e}', file=sys.stderr)
        sys.exit(1)

    hive_name = os.path.basename(args.file)
    rows = 0
    skipped = 0
    try:
        # errors='replace' is belt-and-suspenders on top of fmt_value's filtering.
        with open(args.csv, 'w', newline='', encoding='utf-8', errors='replace') as f:
            w = csv.writer(f)
            w.writerow(['HivePath', 'KeyPath', 'ValueName', 'ValueType', 'ValueData', 'LastWriteTimestamp', 'Description'])

            def walk(node, depth):
                nonlocal rows, skipped
                if depth > 64:  # pathological nesting guard
                    return
                try:
                    ts = fmt_ts(getattr(node, 'timestamp', None))
                    key_path = (node.path or '').replace('\\', '\\')
                    values = list(node.values())
                except Exception:
                    # Corrupt key: skip its values but keep walking its subkeys.
                    ts = ''
                    key_path = ''
                    values = []
                for v in values:
                    try:
                        vname = getattr(v, 'name', '') or '(Default)'
                        vtype = int(getattr(v, 'type', 0) or 0)
                        desc = (key_path + '\\' + vname) if key_path else vname
                        w.writerow([hive_name, key_path, vname, TYPE_NAMES.get(vtype, str(vtype)), fmt_value(v), ts, desc])
                        rows += 1
                    except Exception:
                        skipped += 1
                try:
                    subs = list(node.subkeys())
                except Exception:
                    subs = []
                for sk in subs:
                    walk(sk, depth + 1)

            walk(hive.root(), 0)
    except Exception as e:
        print(f'ERROR: walk failed: {e}', file=sys.stderr)
        sys.exit(1)

    print(f'OK: {rows} values -> {args.csv}' + (f' ({skipped} skipped)' if skipped else ''))


if __name__ == '__main__':
    main()
