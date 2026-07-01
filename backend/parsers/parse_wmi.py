#!/usr/bin/env python3
"""
parse_wmi.py — WMI persistence (event subscriptions) from the CIM repository.

The WMI persistence triad (__EventFilter → __FilterToConsumerBinding →
Command/ActiveScript EventConsumer, MITRE T1546.003) lives in the CIM repository
(OBJECTS.DATA + INDEX.BTR + MAPPING*.MAP under \\Windows\\System32\\wbem\\
Repository). Read with dissect.cim (pure Python). The repository carries no clean
per-object timestamp, so OBJECTS.DATA's mtime is used as a coarse anchor.

Output CSV columns (consumed by collection.js):
  timestampColumns : Timestamp
  descriptionColumns: Type, Name, Detail
  sourceColumn      : Type
"""

import sys
import os
import csv
import argparse
from datetime import datetime, timezone

from dissect.cim import CIM

FIELDNAMES = ['Timestamp', 'Type', 'Name', 'Detail', 'ComputerName']

# class -> (friendly type, [detail property names])
PERSIST_CLASSES = {
    '__EventFilter':               ('EventFilter',   ['Name', 'Query', 'EventNamespace']),
    'CommandLineEventConsumer':    ('CmdConsumer',   ['Name', 'CommandLineTemplate', 'ExecutablePath']),
    'ActiveScriptEventConsumer':   ('ScriptConsumer',['Name', 'ScriptFileName', 'ScriptText', 'ScriptingEngine']),
    '__FilterToConsumerBinding':   ('Binding',       ['Filter', 'Consumer']),
}


def mtime_iso(path):
    try:
        return datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc).isoformat()
    except OSError:
        return ''


def getprop(inst, name):
    try:
        props = inst.properties
        p = props.get(name) if hasattr(props, 'get') else None
        if p is None:
            return ''
        v = getattr(p, 'value', p)
        if v is None:
            return ''
        return str(v).replace('\n', ' ').replace('\r', ' ').strip()
    except Exception:
        return ''


def walk_namespaces(ns, depth=0):
    yield ns
    if depth > 4:
        return
    try:
        for child in ns.namespaces:
            yield from walk_namespaces(child, depth + 1)
    except Exception:
        return


def parse(repo_dir):
    records = []
    ts = ''
    for cand in ('OBJECTS.DATA', 'objects.data'):
        p = os.path.join(repo_dir, cand)
        if os.path.isfile(p):
            ts = mtime_iso(p)
            break
    try:
        cim = CIM.from_directory(repo_dir)
    except Exception as e:
        print(f'ERROR: cannot open CIM repository: {e}', file=sys.stderr)
        return records

    try:
        root = cim.namespace('root')
    except Exception:
        try:
            root = cim.namespace
        except Exception:
            return records

    for ns in walk_namespaces(root):
        for cls_name, (ftype, props) in PERSIST_CLASSES.items():
            try:
                cls = ns.class_(cls_name)
            except Exception:
                continue
            if cls is None:
                continue
            try:
                instances = list(cls.instances)
            except Exception:
                continue
            for inst in instances:
                name = getprop(inst, 'Name') or getprop(inst, 'Consumer') or ''
                detail = ' | '.join(filter(None, (getprop(inst, p) for p in props[1:])))
                records.append({
                    'Timestamp': ts,
                    'Type': ftype,
                    'Name': name[:300],
                    'Detail': detail[:1000],
                    'ComputerName': '',
                })
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--dir', required=True, help='CIM repository directory (contains OBJECTS.DATA)')
    ap.add_argument('--csv', required=True, help='Output directory')
    ap.add_argument('--csvf', default='wmi_results.csv', help='Output CSV filename')
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        print(f'ERROR: Directory not found: {args.dir}', file=sys.stderr)
        sys.exit(1)
    os.makedirs(args.csv, exist_ok=True)
    records = parse(args.dir)
    out_path = os.path.join(args.csv, args.csvf)
    with open(out_path, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(records)
    print(f'Parsed {len(records)} WMI persistence objects -> {out_path}')


if __name__ == '__main__':
    main()
