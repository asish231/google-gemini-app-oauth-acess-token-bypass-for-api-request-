#!/usr/bin/env python3
"""Finding 4 — Gemini WEB API client via Chrome CDP (session riding).

Rides a signed-in gemini.google.com tab in a Chrome instance launched with
--remote-debugging-port=9222. Auth comes from the browser session itself
(cookies + XSRF), so this client contains no credentials at all.

It first needs a captured StreamGenerate request template (f.req envelope),
produced by tools/capture_request.py — or any manual capture of one send.
The template lives in config/send_request_template.json (gitignored if you
keep live session data in it).

Launch Chrome first:
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' \\
        --remote-debugging-port=9222 https://gemini.google.com/app

Usage:
    python3 gemini_web_client.py "your message"
    python3 gemini_web_client.py            # verification mode (2 messages)
"""
import json
import os
import subprocess
import sys
import time
import uuid

import websocket

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), '..',
                             'config', 'send_request_template.json')


def load_template():
    """The captured f.req envelope. Schema (reverse-engineered):
    outer = [null, "<inner as string>"]
    inner[0]  = [message_text, 0, null, null, null, null, 0]
    inner[1]  = ["<locale>"]          inner[3]  = session/flow token
    inner[59] = request UUID           (regenerated per send)
    """
    d = json.load(open(TEMPLATE_PATH))
    from urllib.parse import unquote
    body = unquote(d['send']['body'])
    freq_raw = body.split('&at=')[0].replace('f.req=', '', 1)
    outer = json.loads(freq_raw)
    return json.loads(outer[1])


def connect():
    targets = json.loads(subprocess.run(
        ['curl', '-s', 'http://localhost:9222/json/list'],
        capture_output=True, text=True).stdout)
    for t in targets:
        if 'gemini.google.com' in t.get('url', '') and t.get('type') == 'page':
            return t
    print('ERROR: no gemini.google.com tab. Launch Chrome with '
          '--remote-debugging-port=9222 and sign in.')
    sys.exit(1)


def main():
    inner = load_template()
    tab = connect()
    ws = websocket.create_connection(tab['webSocketDebuggerUrl'],
                                     timeout=120, suppress_origin=True)
    _id = [0]

    def cdp(method, params=None):
        _id[0] += 1
        payload = {'id': _id[0], 'method': method}
        if params:
            payload['params'] = params
        ws.send(json.dumps(payload))
        return _id[0]

    def ev(expr, timeout=120):
        rid = cdp('Runtime.evaluate',
                  {'expression': expr, 'returnByValue': True, 'awaitPromise': True})
        start = time.time()
        ws.settimeout(timeout)
        while time.time() - start < timeout:
            try:
                data = json.loads(ws.recv())
                if data.get('id') == rid:
                    return data['result']['result']['value']
            except Exception:
                break
        return None

    cdp('Page.bringToFront')
    time.sleep(1)

    def send_message(msg):
        inner[0][0] = msg
        inner[59] = str(uuid.uuid4()).upper()
        freq = json.dumps([None, json.dumps(inner)], separators=(',', ':'))
        js = f'''
        (async () => {{
            let xsrf = null;
            for (const s of document.querySelectorAll('script')) {{
                const m = (s.textContent || '').match(/"SNlM0e":"([^"]+)"/);
                if (m) {{ xsrf = m[1]; break; }}
            }}
            if (!xsrf) return JSON.stringify({{error: 'no XSRF token'}});
            const sid = String(Math.floor(Math.random() * 2e18) - 1e18);
            const reqid = Math.floor(Math.random() * 900000) + 100000;
            const url = '/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate?bl=boq_gemini-web-uiserver_20261012.19_p1&f.sid=' + sid + '&hl=en-GB&_reqid=' + reqid + '&rt=c';
            const body = 'f.req=' + encodeURIComponent({json.dumps(freq)}) + '&at=' + encodeURIComponent(xsrf);
            const resp = await fetch(url, {{method: 'POST', credentials: 'include',
                headers: {{'Content-Type': 'application/x-www-form-urlencoded'}}, body: body}});
            const text = await resp.text();
            return JSON.stringify({{status: resp.status, len: text.length, text: text}});
        }})()
        '''
        return ev(js)

    def parse_stream(text):
        """Length-prefixed chunks; declared length INCLUDES the trailing \\r\\n."""
        chunks = []
        stripped = text[4:] if text.startswith(")]}'") else text
        pos = 0
        while pos < len(stripped):
            nl = stripped.find('\n', pos)
            if nl == -1:
                break
            seg = stripped[pos:nl].strip()
            if seg.isdigit():
                n = int(seg)
                for trim in (2, 1, 0):
                    try:
                        chunks.append(json.loads(stripped[nl + 1:nl + 1 + n - trim]))
                        break
                    except Exception:
                        continue
                pos = nl + 1 + n
            else:
                pos = nl + 1
        return chunks

    def find_rc(node, out, depth=0):
        if depth > 8 or not isinstance(node, list):
            return
        if (len(node) >= 2 and isinstance(node[0], str)
                and node[0].startswith('rc_') and isinstance(node[1], list)):
            out.append(node[1])
            return
        for sub in node:
            find_rc(sub, out, depth + 1)

    def extract_reply(text):
        replies = []
        for chunk in parse_stream(text):
            if not isinstance(chunk, list):
                continue
            for item in chunk:
                if not (isinstance(item, list) and len(item) >= 3
                        and item[0] == 'wrb.fr' and isinstance(item[2], str)):
                    continue
                try:
                    idata = json.loads(item[2])
                except Exception:
                    continue
                found = []
                find_rc(idata, found)
                for seg in found:
                    parts = ''.join(s for s in seg if isinstance(s, str))
                    if parts:
                        replies.append(parts)
        return replies

    def chat(msg):
        raw = send_message(msg)
        if not raw:
            return None, {'error': 'no response'}
        data = json.loads(raw)
        if 'error' in data:
            return None, data
        replies = extract_reply(data['text'])
        return (replies[0] if replies else None), {
            'status': data['status'], 'all': replies}

    if len(sys.argv) > 1:
        msg = ' '.join(sys.argv[1:])
        print(f'Sending: {msg!r}')
        reply, meta = chat(msg)
        if reply:
            print(f"GEMINI: {reply.strip()}")
        else:
            print('No reply:', str(meta)[:300])
    else:
        tests = ['What is 7 multiplied by 6? Reply with only the number.',
                 'Name the capital of France in one word.']
        ok = 0
        for msg in tests:
            print(f'\nSENT: {msg!r}')
            reply, meta = chat(msg)
            if reply:
                print(f"REPLY: {reply.strip()!r}  (HTTP {meta.get('status')})")
                ok += 1
            else:
                print('NO REPLY:', str(meta)[:200])
        print(f'\n=== {ok}/{len(tests)} succeeded ===')
    ws.close()
    print('done')


if __name__ == '__main__':
    main()
