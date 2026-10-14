#!/usr/bin/env python3
"""Capture the web app's real StreamGenerate request envelope.

The web client (clients/gemini_web_client.py) needs ONE captured request to
learn the f.req envelope (session token at inner[3], locale, flags). This
script produces it by:

  1. Focusing the real Quill editor (.ql-editor) in the signed-in tab
  2. Typing a marker message via CDP Input.insertText
  3. Dispatching a TRUSTED CDP mouse click on the 'Send message' button
     (Page.bringToFront first — synthetic JS clicks are ignored by Angular)
  4. Hooking XMLHttpRequest.open/send BEFORE the click to capture the body
     and the streamed response

Output: config/send_request_template.json (gitignored — contains your
per-session flow token).

Launch Chrome with --remote-debugging-port=9222 and sign in to
gemini.google.com first.
"""
import json
import os
import subprocess
import sys
import time

import websocket

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), '..', 'config',
                             'send_request_template.json')


def main():
    targets = json.loads(subprocess.run(
        ['curl', '-s', 'http://localhost:9222/json/list'],
        capture_output=True, text=True).stdout)
    tab = next((t for t in targets
                if 'gemini.google.com' in t.get('url', '') and t.get('type') == 'page'),
               None)
    if not tab:
        sys.exit('no signed-in gemini.google.com tab found')

    ws = websocket.create_connection(tab['webSocketDebuggerUrl'],
                                     timeout=30, suppress_origin=True)
    _id = [0]

    def cdp(method, params=None):
        _id[0] += 1
        ws.send(json.dumps({'id': _id[0], 'method': method,
                            **({'params': params} if params else {})}))
        return _id[0]

    def ev(expr, timeout=25, await_=False):
        rid = cdp('Runtime.evaluate', {'expression': expr, 'returnByValue': True,
                                       **({'awaitPromise': True} if await_ else {})})
        start, ws.settimeout = time.time(), None
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

    # Install XHR hooks: capture the StreamGenerate body + response
    ev('''(() => {
        window.__sends = []; window.__resps = [];
        const ox = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(m, u, ...r) {
            this.__url = String(u); return ox.apply(this, [m, u, ...r]);
        };
        const os = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(body) {
            const url = this.__url || '';
            if (url.includes('StreamGenerate')) {
                window.__sends.push({url: url.substring(0, 300),
                    body: (typeof body === 'string') ? body.substring(0, 40000) : 'nonstring'});
                this.addEventListener('load', () => window.__resps.push(
                    {status: this.status, len: (this.responseText || '').length}));
            }
            return os.apply(this, arguments);
        };
        return 'ok';
    })()''')

    # Focus the REAL editor (not .ql-clipboard — Quill's hidden mirror)
    ev('''(() => {
        const t = document.querySelector('.ql-editor');
        if (!t) return 'no editor';
        t.focus();
        const sel = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(t); range.collapse(false);
        sel.removeAllRanges(); sel.addRange(range);
        return 'ok';
    })()''')

    # Type a marker message with CDP input events (real input path)
    cdp('Input.insertText', {'text': 'Reply with exactly: CAPTURE_OK'})
    time.sleep(2)

    # Trusted click at the Send button's center
    coords = ev('''(() => {
        const b = document.querySelector('button[aria-label="Send message"]');
        if (!b) return JSON.stringify({error: 'no send button'});
        const r = b.getBoundingClientRect();
        return JSON.stringify({x: r.x + r.width / 2, y: r.y + r.height / 2});
    })()''')
    c = json.loads(coords)
    if 'error' in c:
        sys.exit(f'capture failed: {c}')
    cdp('Input.dispatchMouseEvent', {'type': 'mousePressed', 'x': c['x'], 'y': c['y'],
                                     'button': 'left', 'clickCount': 1,
                                     'pointerType': 'mouse'})
    time.sleep(0.15)
    cdp('Input.dispatchMouseEvent', {'type': 'mouseReleased', 'x': c['x'], 'y': c['y'],
                                     'button': 'left', 'clickCount': 1,
                                     'pointerType': 'mouse'})

    # Wait for the send to fire, then read the captured envelope
    time.sleep(6)
    result = ev('''(() => JSON.stringify({
        sends: window.__sends, resps: window.__resps
    }))()''', timeout=10)
    data = json.loads(result)
    sends = data.get('sends') or []
    if not sends:
        sys.exit('no StreamGenerate request captured — was the click trusted? '
                 '(need Page.bringToFront + CDP mouse events, not JS .click())')

    os.makedirs(os.path.dirname(TEMPLATE_PATH), exist_ok=True)
    with open(TEMPLATE_PATH, 'w') as f:
        json.dump(sends, f, indent=2)
    print(f'captured {len(sends)} StreamGenerate envelope(s) '
          f'({len(sends[0]["body"])}-byte body)')
    print(f'template written: {TEMPLATE_PATH}')
    print('responses:', data.get('resps'))
    ws.close()


if __name__ == '__main__':
    main()
