#!/usr/bin/env python3
"""
parse_networklist.py — Network profiles (SSID, first/last connect, gateway MAC)
from the SOFTWARE hive's NetworkList key, via dissect.regf.

Joins Profiles (name + DateCreated + DateLastConnected) with Signatures
(Description + DefaultGatewayMac + DnsSuffix) by ProfileGuid. Useful for placing
a machine geographically and timelining its network attachments.

Output CSV columns (consumed by collection.js):
  timestampColumns : DateLastConnected, DateCreated
  descriptionColumns: ProfileName, DnsSuffix, GatewayMac
  sourceColumn      : ProfileName
"""

import sys
import os
import csv
import struct
import argparse
from datetime import datetime, timezone

from dissect.regf import regf

FIELDNAMES = ['DateLastConnected', 'DateCreated', 'ProfileName', 'DnsSuffix', 'GatewayMac', 'ProfileGuid', 'ComputerName']
NL = "Microsoft\\Windows NT\\CurrentVersion\\NetworkList"


def systemtime(data):
    # 8 little-endian uint16: year, month, dow, day, hour, minute, second, ms
    if not data or len(data) < 16:
        return ''
    try:
        y, mo, _dow, d, h, mi, s, _ms = struct.unpack_from('<8H', data, 0)
        if not y:
            return ''
        return datetime(y, mo or 1, d or 1, h, mi, s, tzinfo=timezone.utc).isoformat()
    except (struct.error, ValueError):
        return ''


def getval(key, name):
    try:
        v = key.value(name)
        return v.value if v is not None else None
    except Exception:
        return None


def getdata(key, name):
    try:
        v = key.value(name)
        return v.data if v is not None else None
    except Exception:
        return None


def mac_str(data):
    if not data or len(data) < 6:
        return ''
    return ':'.join(f'{b:02x}' for b in data[:6])


def parse(path):
    records = []
    try:
        hive = regf.RegistryHive(open(path, 'rb'))
    except Exception as e:
        print(f'ERROR: cannot open hive: {e}', file=sys.stderr)
        return records

    # 1. Signatures (Managed + Unmanaged) → map ProfileGuid -> {mac, dns}
    sig_by_guid = {}
    for branch in ('Managed', 'Unmanaged'):
        try:
            node = hive.open(f'{NL}\\Signatures\\{branch}')
        except Exception:
            continue
        for sig in node.subkeys():
            guid = getval(sig, 'ProfileGuid')
            if not guid:
                continue
            sig_by_guid[str(guid)] = {
                'GatewayMac': mac_str(getdata(sig, 'DefaultGatewayMac')),
                'DnsSuffix': getval(sig, 'DnsSuffix') or '',
            }

    # 2. Profiles → name + dates, joined with signature.
    try:
        profiles = hive.open(f'{NL}\\Profiles')
    except Exception:
        return records
    for p in profiles.subkeys():
        guid = p.name
        sig = sig_by_guid.get(str(guid), {})
        records.append({
            'DateLastConnected': systemtime(getdata(p, 'DateLastConnected')),
            'DateCreated': systemtime(getdata(p, 'DateCreated')),
            'ProfileName': getval(p, 'ProfileName') or '',
            'DnsSuffix': sig.get('DnsSuffix', ''),
            'GatewayMac': sig.get('GatewayMac', ''),
            'ProfileGuid': guid,
            'ComputerName': '',
        })
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--file', required=True, help='Path to SOFTWARE hive')
    ap.add_argument('--csv', required=True, help='Output directory')
    ap.add_argument('--csvf', default='networklist_results.csv', help='Output CSV filename')
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
    print(f'Parsed {len(records)} network profiles -> {out_path}')


if __name__ == '__main__':
    main()
