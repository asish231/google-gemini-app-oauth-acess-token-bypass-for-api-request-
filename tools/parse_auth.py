#!/usr/bin/env python3
"""Parse the decrypted Gemini credential-store protobuf (StoredCredentialData).

Reads the plaintext produced by decrypt_auth.py (default
/tmp/gemini_auth_decrypted.bin) and maps field numbers to names using the
proto schema strings recovered from the binary:

    StoredCredentialData { gaia_id, email, profile_name, profile_photo_url,
                           scopes, refresh_token, id_token, hosted_domain, is_fst }

Note: in the observed serialization the field order in the file differs from the
proto declaration order; the parser below prints both the semantic name and the
raw field number so either layout is readable.

Usage:
    python3 parse_auth.py [path-to-plaintext.bin] [--json]
"""
import argparse
import json
import sys


def read_varint(d, i):
    v, s = 0, 0
    while i < len(d):
        b = d[i]; i += 1
        v |= (b & 0x7F) << s
        if not (b & 0x80):
            return v, i
        s += 7
    return v, i


def parse_proto(d):
    fields, i = [], 0
    while i < len(d):
        tag, i = read_varint(d, i)
        fn, wt = (tag >> 3) & 0x1F, tag & 0x7
        if wt == 0:
            v, i = read_varint(d, i)
            fields.append((fn, 'varint', v))
        elif wt == 2:
            ln, i = read_varint(d, i)
            fields.append((fn, 'bytes', d[i:i + ln]))
            i += ln
        elif wt == 1:
            fields.append((fn, 'fixed64', d[i:i + 8])); i += 8
        elif wt == 5:
            fields.append((fn, 'fixed32', d[i:i + 4])); i += 4
        else:
            break
    return fields


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('path', nargs='?', default='/tmp/gemini_auth_decrypted.bin')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    data = open(args.path, 'rb').read()
    print(f'plaintext: {len(data)} bytes', file=sys.stderr)

    names = {1: 'gaia_id', 2: 'email', 3: 'profile_name', 4: 'refresh_token',
             5: 'scopes', 6: 'id_token', 7: 'hosted_domain', 8: 'is_fst',
             10: 'display_name', 11: 'profile_photo_url'}

    result = {}
    for fn, wt, v in parse_proto(data):
        key = names.get(fn, f'field_{fn}')
        if wt == 'bytes':
            try:
                s = v.decode('utf-8')
                printable = all(32 <= ord(c) < 127 or c in '\n\t' for c in s)
            except UnicodeDecodeError:
                printable = False
            result[key] = s if printable else v.hex()[:80]
        else:
            result[key] = v

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for k, v in result.items():
            shown = v if len(str(v)) <= 110 else str(v)[:110] + '…'
            print(f'  {k:18s}: {shown}')
        rt = result.get('refresh_token')
        if rt:
            print(f"\nrefresh_token ({len(rt)} chars) found — "
                  'feed it to the desktop client or oauth2 token refresh.')


if __name__ == '__main__':
    main()
