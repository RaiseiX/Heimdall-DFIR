#!/usr/bin/env python3
"""
parse_hive_browse.py — navigate a Windows registry hive for the Files view.

Reads a hive (NTUSER.DAT, SYSTEM, SOFTWARE, SAM, …) with dissect.regf (pure
Python, already installed) and emits a JSON listing of one key level: the
values of `path` and its direct subkeys (each with a value/subkey count so the
UI can render a two-pane browser). With `--search <term>` it instead walks the
hive recursively and returns matching key names, value names and string-value
data.

Usage:
  parse_hive_browse.py -f <hive> [-p <key path>] [--limit N]
  parse_hive_browse.py -f <hive> --search <term> [--limit N] [--max-walk N]

Output (JSON to stdout):
  {
    "root": true/false,
    "path": "Software\\Martin Prikryl",
    "values": [{ "name", "type", "data" }],
    "subkeys": [{ "name", "path", "valueCount", "subkeyCount", "lastWrite" }],
    "truncated": true/false
  }

Search output:
  { "search": "winscp", "matches": [{ "kind": "key"|"value", "name", "path", … }],
    "truncated": true/false }
"""
import sys
import json
import argparse

try:
    from dissect.regf import regf
except ImportError as e:
    print(f'ERROR: dissect.regf not installed — run: pip3 install "dissect.regf>=3" ({e})', file=sys.stderr)
    sys.exit(2)

# Registry value type numbers → readable names (Winreg constants).
TYPE_NAMES = {
    0: 'REG_NONE',
    1: 'REG_SZ',
    2: 'REG_EXPAND_SZ',
    3: 'REG_BINARY',
    4: 'REG_DWORD',
    5: 'REG_DWORD_BIG_ENDIAN',
    6: 'REG_LINK',
    7: 'REG_MULTI_SZ',
    8: 'REG_RESOURCE_LIST',
    9: 'REG_FULL_RESOURCE_DESCRIPTOR',
    10: 'REG_RESOURCE_REQUIREMENTS_LIST',
    11: 'REG_QWORD',
}

MAX_VALUE_DATA = 8192


def fmt_value(v):
    """Return a stable, JSON-safe representation of a registry value."""
    try:
        raw = v.data
        if not isinstance(raw, (bytes, bytearray)):
            raw = bytes(raw)
    except Exception:
        raw = b''

    val_type = int(getattr(v, 'type', 0) or 0)

    # Strings / numbers are human-readable and small — show them directly.
    # dissect.regf already parses value types (v.value), so prefer it over
    # hand-decoding bytes (REG_SZ can be UTF-16-LE).
    if val_type in (1, 2, 4, 5, 11, 7):  # SZ / EXPAND_SZ / DWORD / DWORD_BE / QWORD / MULTI_SZ
        try:
            val = v.value
            if isinstance(val, list):
                val = '\n'.join(str(x) for x in val)
            text = str(val)
            return {'type': TYPE_NAMES.get(val_type, val_type), 'data': text[:MAX_VALUE_DATA], 'truncated': len(text) > MAX_VALUE_DATA}
        except Exception:
            pass

    # Binary / anything else: hex preview (never dump megabytes).
    hex_str = raw.hex()
    return {
        'type': TYPE_NAMES.get(val_type, val_type),
        'data': hex_str[:MAX_VALUE_DATA * 2],
        'binary': True,
        'truncated': len(raw) > MAX_VALUE_DATA,
    }


def search_hive(hive, term, limit, max_walk):
    """Recursively search key names, value names and string-value data.

    Returns (matches, truncated) where each match is
    { kind: 'key'|'value', name, path, … } and `truncated` is True when the
    walk budget was exhausted before the whole hive was covered.
    """
    term_l = term.lower()
    matches = []
    state = {'walked': 0}

    def visit(node, depth):
        if depth > 40 or state['walked'] >= max_walk or len(matches) >= limit:
            return
        state['walked'] += 1

        # A key's name is matched by its parent; its values are matched here.
        for sk in node.subkeys():
            if state['walked'] >= max_walk or len(matches) >= limit:
                return
            if term_l in sk.name.lower():
                matches.append({
                    'kind': 'key',
                    'name': sk.name,
                    'path': sk.path.replace('\\', '\\'),
                    'parentPath': (node.path or '').replace('\\', '\\'),
                    'lastWrite': sk.timestamp.isoformat() if sk.timestamp else '',
                })
            visit(sk, depth + 1)

        for v in node.values():
            if state['walked'] >= max_walk or len(matches) >= limit:
                return
            vname = getattr(v, 'name', '') or ''
            hit = term_l in vname.lower()
            snippet = ''
            if not hit:
                try:
                    vtype = int(getattr(v, 'type', 0) or 0)
                    if vtype in (1, 2, 7):  # REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ
                        val = v.value
                        if isinstance(val, list):
                            val = '\n'.join(str(x) for x in val)
                        text = str(val)
                        if term_l in text.lower():
                            hit = True
                            snippet = text[:160]
                except Exception:
                    pass
            if hit:
                matches.append({
                    'kind': 'value',
                    'name': vname or '(Default)',
                    'path': (node.path or '').replace('\\', '\\'),
                    'snippet': snippet,
                })

    visit(hive.root(), 0)
    return matches, state['walked'] >= max_walk


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--file', required=True, help='Path to the registry hive file')
    ap.add_argument('-p', '--path', default='', help='Key path inside the hive (empty = root)')
    ap.add_argument('-s', '--search', default='', help='Recursive search term (key name, value name or string data)')
    ap.add_argument('--limit', type=int, default=500, help='Max subkeys/values to return per level')
    ap.add_argument('--max-walk', type=int, default=100000, help='Max keys to visit during a search')
    args = ap.parse_args()

    try:
        hive = regf.RegistryHive(open(args.file, 'rb'))
    except Exception as e:
        print(json.dumps({'error': f'Cannot open hive: {e}'}))
        sys.exit(1)

    if args.search:
        try:
            matches, walked_truncated = search_hive(hive, args.search, args.limit, args.max_walk)
        except Exception as e:
            print(json.dumps({'error': f'Search failed: {e}'}))
            sys.exit(1)
        print(json.dumps({
            'search': args.search,
            'matches': matches,
            'truncated': walked_truncated or len(matches) >= args.limit,
        }, ensure_ascii=False))
        sys.exit(0)

    node = hive.root()
    key_path = (args.path or '').strip('\\')
    if key_path:
        try:
            node = hive.open(key_path)
        except Exception as e:
            print(json.dumps({'error': f'Key not found: {key_path} ({e})'}))
            sys.exit(1)

    # Values of the current key.
    values = []
    try:
        for v in node.values():
            values.append({'name': getattr(v, 'name', '(Default)'), **fmt_value(v)})
    except Exception:
        pass

    # Direct subkeys (each with counts for tree rendering).
    subkeys = []
    try:
        for sk in node.subkeys():
            sk_vcount = 0
            sk_scount = 0
            try:
                sk_vcount = len(list(sk.values()))
            except Exception:
                pass
            try:
                sk_scount = len(list(sk.subkeys()))
            except Exception:
                pass
            last_write = ''
            try:
                last_write = sk.timestamp.isoformat() if sk.timestamp else ''
            except Exception:
                pass
            subkeys.append({
                'name': sk.name,
                'path': (sk.path or sk.name).replace('\\', '\\'),
                'valueCount': sk_vcount,
                'subkeyCount': sk_scount,
                'lastWrite': last_write,
            })
    except Exception:
        pass

    # Sort subkeys alphabetically (case-insensitive), stable for navigation.
    subkeys.sort(key=lambda s: s['name'].lower())

    values_truncated = len(values) > args.limit
    subkeys_truncated = len(subkeys) > args.limit

    print(json.dumps({
        'root': not key_path,
        'path': (node.path or '') if not key_path else key_path,
        'name': node.name if not key_path else key_path.split('\\')[-1],
        'lastWrite': node.timestamp.isoformat() if getattr(node, 'timestamp', None) else '',
        'values': values[:args.limit],
        'subkeys': subkeys[:args.limit],
        'valuesTruncated': values_truncated,
        'subkeysTruncated': subkeys_truncated,
    }, ensure_ascii=False))


if __name__ == '__main__':
    main()
