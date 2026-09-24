#!/usr/bin/env python3
"""
parse_pcap.py — network flows from a PCAP, via tshark (already installed).

Aggregates packets into directional flows (src,dst,sport,dport,proto) with byte
counts and first/last seen. The output CSV maps onto the network_connections
table, so the collection pipeline can feed the network map + its Phase 2/3
analytics (exfil, scan, lateral, geo) — which otherwise have no data.

Output CSV columns (consumed by collection.js → network_connections):
  src_ip, src_port, dst_ip, dst_port, protocol,
  bytes_sent, bytes_received, packet_count, first_seen, last_seen
"""

import sys
import os
import csv
import argparse
import subprocess
from datetime import datetime, timezone

FIELDNAMES = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
              'bytes_sent', 'bytes_received', 'packet_count', 'first_seen', 'last_seen']

TSHARK_FIELDS = [
    'frame.time_epoch', 'frame.len', 'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst',
    'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'ip.proto',
]


def epoch_iso(ep):
    try:
        return datetime.fromtimestamp(float(ep), tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        return ''


def run_tshark(path):
    cmd = ['tshark', '-r', path, '-T', 'fields', '-E', 'separator=,', '-E', 'quote=n', '-n']
    for f in TSHARK_FIELDS:
        cmd += ['-e', f]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    if proc.returncode != 0:
        print(f'ERROR: tshark failed: {proc.stderr[:300]}', file=sys.stderr)
    return proc.stdout.splitlines()


def parse(path):
    flows = {}  # (src,sport,dst,dport,proto) -> aggregate
    for line in run_tshark(path):
        c = line.split(',')
        if len(c) < 11:
            continue
        ts, length, ip_s, ip_d, ip6_s, ip6_d, tsp, tdp, usp, udp_p, proto = c[:11]
        src = ip_s or ip6_s
        dst = ip_d or ip6_d
        if not src or not dst:
            continue
        if tsp or tdp:
            sport, dport, pname = tsp, tdp, 'tcp'
        elif usp or udp_p:
            sport, dport, pname = usp, udp_p, 'udp'
        else:
            sport, dport, pname = '', '', {'1': 'icmp', '6': 'tcp', '17': 'udp'}.get(proto, proto or 'ip')
        try:
            blen = int(length or 0)
        except ValueError:
            blen = 0
        key = (src, sport, dst, dport, pname)
        f = flows.get(key)
        if f is None:
            f = {'bytes': 0, 'packets': 0, 'first': ts, 'last': ts}
            flows[key] = f
        f['bytes'] += blen
        f['packets'] += 1
        if ts and (not f['first'] or ts < f['first']):
            f['first'] = ts
        if ts and ts > f['last']:
            f['last'] = ts

    records = []
    for (src, sport, dst, dport, pname), f in flows.items():
        records.append({
            'src_ip': src, 'src_port': sport or '', 'dst_ip': dst, 'dst_port': dport or '',
            'protocol': pname,
            'bytes_sent': f['bytes'], 'bytes_received': 0, 'packet_count': f['packets'],
            'first_seen': epoch_iso(f['first']), 'last_seen': epoch_iso(f['last']),
        })
    return records


def parse_dir(base):
    records = []
    for root_dir, _dirs, files in os.walk(base):
        for name in files:
            if name.lower().endswith(('.pcap', '.pcapng', '.cap')):
                records += parse(os.path.join(root_dir, name))
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--dir', help='Directory to walk for pcaps')
    ap.add_argument('-f', '--file', help='Single pcap file')
    ap.add_argument('--csv', required=True, help='Output directory')
    ap.add_argument('--csvf', default='pcap_results.csv', help='Output CSV filename')
    args = ap.parse_args()

    if args.file and os.path.isfile(args.file):
        records = parse(args.file)
    elif args.dir and os.path.isdir(args.dir):
        records = parse_dir(args.dir)
    else:
        print('ERROR: provide -f <pcap> or -d <dir>', file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.csv, exist_ok=True)
    out_path = os.path.join(args.csv, args.csvf)
    with open(out_path, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(records)
    print(f'Parsed {len(records)} network flows -> {out_path}')


if __name__ == '__main__':
    main()
