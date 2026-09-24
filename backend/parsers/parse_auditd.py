#!/usr/bin/env python3
"""
parse_auditd.py — Linux auditd log parser.

Reads /var/log/audit/audit.log* files. Extracts SYSCALL, EXECVE, USER_AUTH,
USER_LOGIN, ADD_USER, DEL_USER, SOCKET events and maps them to ATT&CK.

Output CSV columns (consumed by collection.js):
  timestampColumns : Timestamp
  descriptionColumns: AuditType, Exe, Args
  sourceColumn      : HostName
"""
import sys
import os
import re
import csv
import argparse
from datetime import datetime, timezone

FIELDNAMES = ['Timestamp', 'AuditType', 'Syscall', 'Exe', 'Args',
              'UserName', 'HostName', 'Pid', 'Result', 'Key', 'SourceFile']

# Audit record: type=XXX msg=audit(epoch.ms:serial): key=val ...
RECORD_RE = re.compile(
    r'^type=(\S+)\s+msg=audit\((\d+\.\d+):\d+\):\s*(.*)$'
)
# Simple key=value or key="value" tokenizer
KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|((?:[^\s"\\]|\\.)*))')

INTEREST = {
    'SYSCALL', 'EXECVE', 'USER_AUTH', 'USER_LOGIN', 'USER_LOGOUT',
    'USER_START', 'ADD_USER', 'DEL_USER', 'SOCKET', 'CONNECT',
    'USER_CMD', 'PROCTITLE', 'CWD', 'PATH',
}


def epoch_to_iso(epoch_str):
    try:
        return datetime.fromtimestamp(float(epoch_str), tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        return ''


def parse_kv(s):
    d = {}
    for m in KV_RE.finditer(s):
        d[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return d


def unescape_hex(s):
    """Convert hex-encoded strings like 2F62696E2F7368 → /bin/sh."""
    if s and re.match(r'^[0-9A-Fa-f]+$', s) and len(s) % 2 == 0:
        try:
            return bytes.fromhex(s).decode('utf-8', errors='replace')
        except Exception:
            pass
    return s


def parse_file(path):
    records = []
    hostname = os.uname().nodename if hasattr(os, 'uname') else ''
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                m = RECORD_RE.match(line)
                if not m:
                    continue
                audit_type, epoch, rest = m.group(1), m.group(2), m.group(3)
                if audit_type not in INTEREST:
                    continue
                kv = parse_kv(rest)
                ts = epoch_to_iso(epoch)
                exe  = unescape_hex(kv.get('exe', kv.get('cmd', '')))
                args_parts = [kv.get(f'a{i}', '') for i in range(4) if kv.get(f'a{i}')]
                args = ' '.join(unescape_hex(a) for a in args_parts if a)
                user = (kv.get('acct') or kv.get('uid') or kv.get('auid') or '').strip('"')
                host = kv.get('hostname', hostname).strip('"')
                if host in ('-', '?', ''):
                    host = hostname
                records.append({
                    'Timestamp':  ts,
                    'AuditType':  audit_type,
                    'Syscall':    kv.get('syscall', ''),
                    'Exe':        exe,
                    'Args':       args,
                    'UserName':   user,
                    'HostName':   host,
                    'Pid':        kv.get('pid', ''),
                    'Result':     kv.get('res', kv.get('success', '')),
                    'Key':        kv.get('key', '').strip('"'),
                    'SourceFile': path,
                })
    except OSError as e:
        print(f'ERROR reading {path}: {e}', file=sys.stderr)
    return records


def parse_dir(base):
    records = []
    for root, _dirs, files in os.walk(base):
        for name in sorted(files):
            lname = name.lower()
            if lname.startswith('audit') and ('audit.log' in lname or lname == 'audit.log'):
                records.extend(parse_file(os.path.join(root, name)))
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--dir', required=True, help='Directory containing audit.log files')
    ap.add_argument('--csv', required=True, help='Output directory')
    ap.add_argument('--csvf', default='auditd_results.csv', help='Output CSV filename')
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
    print(f'Parsed {len(records)} auditd events -> {out_path}')


if __name__ == '__main__':
    main()
