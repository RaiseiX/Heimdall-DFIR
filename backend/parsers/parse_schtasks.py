#!/usr/bin/env python3
"""
parse_schtasks.py — Windows Scheduled Tasks from \\Windows\\System32\\Tasks\\*.

Each task is an XML file (no extension). Extracts the registration date, the
action command(s), trigger summary and author — strong persistence evidence
(T1053.005). Walks the given directory recursively for XML task definitions.

Output CSV columns (consumed by collection.js):
  timestampColumns : Date
  descriptionColumns: TaskName, Command
  sourceColumn      : TaskName
"""

import sys
import os
import csv
import re
import argparse
# defusedxml hardens against XXE / billion-laughs (task XML can be attacker-controlled).
from defusedxml.ElementTree import fromstring as safe_fromstring
from xml.etree.ElementTree import ParseError

FIELDNAMES = ['Date', 'TaskName', 'Command', 'Arguments', 'Triggers', 'Author', 'RunAs', 'Enabled', 'ComputerName']
NS = '{http://schemas.microsoft.com/windows/2004/02/mit/task}'


def localname(tag):
    return tag.split('}', 1)[-1]


def text_of(elem, *names):
    for n in names:
        e = elem.find(f'.//{NS}{n}')
        if e is None:
            e = elem.find(f'.//{n}')
        if e is not None and e.text:
            return e.text.strip()
    return ''


def is_task_xml(path):
    # Task files have no extension and are usually UTF-16 (BOM + null bytes), so
    # a raw byte check fails — decode the head with each candidate encoding.
    try:
        with open(path, 'rb') as fh:
            head = fh.read(1024)
    except OSError:
        return False
    for enc in ('utf-16', 'utf-8-sig', 'utf-8', 'latin-1'):
        try:
            t = head.decode(enc, errors='ignore').lstrip().lower()
        except (UnicodeDecodeError, UnicodeError):
            continue
        if t.startswith('<?xml') or '<task' in t[:300]:
            return True
    return False


def parse_file(path, task_name):
    # Windows task XML is usually UTF-16; the declared encoding may not match the
    # bytes. Decode defensively, drop the XML declaration, then parse the string.
    try:
        with open(path, 'rb') as fh:
            data = fh.read()
    except OSError:
        return None
    text = None
    for enc in ('utf-16', 'utf-8-sig', 'utf-8', 'latin-1'):
        try:
            text = data.decode(enc)
            break
        except (UnicodeDecodeError, UnicodeError):
            continue
    if not text:
        return None
    text = re.sub(r'^\s*<\?xml[^>]*\?>', '', text, count=1).strip()
    try:
        root = safe_fromstring(text)
    except (ParseError, ValueError):
        return None

    date = text_of(root, 'Date')
    author = text_of(root, 'Author')
    runas = ''
    principal = root.find(f'.//{NS}Principals')
    if principal is not None:
        runas = text_of(principal, 'UserId', 'GroupId', 'LogonType')

    # Actions: collect Exec Command + Arguments (the persistence payload).
    commands, arguments = [], []
    actions = root.find(f'.//{NS}Actions')
    if actions is not None:
        for exec_el in actions.iter():
            if localname(exec_el.tag) == 'Exec':
                c = text_of(exec_el, 'Command')
                a = text_of(exec_el, 'Arguments')
                if c:
                    commands.append(c)
                if a:
                    arguments.append(a)

    # Trigger types summary.
    triggers = []
    trig = root.find(f'.//{NS}Triggers')
    if trig is not None:
        for t in trig:
            triggers.append(localname(t.tag))

    enabled = text_of(root, 'Enabled') or 'true'

    return {
        'Date': date,
        'TaskName': task_name,
        'Command': ' ; '.join(commands),
        'Arguments': ' ; '.join(arguments),
        'Triggers': ', '.join(triggers),
        'Author': author,
        'RunAs': runas,
        'Enabled': enabled,
        'ComputerName': '',
    }


def parse_dir(base):
    records = []
    for root_dir, _dirs, files in os.walk(base):
        # Only descend task trees (avoid scanning unrelated files).
        if 'tasks' not in root_dir.lower():
            continue
        for name in files:
            path = os.path.join(root_dir, name)
            if not is_task_xml(path):
                continue
            # Task name = path under the Tasks root.
            low = root_dir.lower()
            idx = low.rfind('tasks')
            rel = root_dir[idx + 5:].strip('\\/').replace('/', '\\')
            task_name = (rel + '\\' + name) if rel else name
            rec = parse_file(path, task_name)
            if rec:
                records.append(rec)
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--dir', required=True, help='Directory to walk for Tasks')
    ap.add_argument('--csv', required=True, help='Output directory')
    ap.add_argument('--csvf', default='schtasks_results.csv', help='Output CSV filename')
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
    print(f'Parsed {len(records)} scheduled tasks -> {out_path}')


if __name__ == '__main__':
    main()
