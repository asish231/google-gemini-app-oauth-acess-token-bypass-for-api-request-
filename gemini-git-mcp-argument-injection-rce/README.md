# Gemini macOS App — Bundled `git_mcp_server` Argument Injection (Found Exploit → Arbitrary Command Execution)

**Finding:** The Gemini desktop app's bundled MCP helper `git_mcp_server` passes the
`remote` parameter of the `git_pull` / `git_push` tools **verbatim** into the git
command line. Because git accepts transport options after the subcommand, a value
like `--upload-pack=<shell command>` (or `--receive-pack=` for push) causes git to
**execute an attacker-influenced shell command with the user's full privileges**.

**Severity:** High — arbitrary command execution on macOS, reachable through a single
LLM tool call (the model can be steered into issuing it via prompt injection in
content the user asks Gemini about).

**Affected component:** `/Applications/Gemini.app/Contents/Helpers/git_mcp_server`
(Go, arm64, ~7.7 MB; internal source path in binary: `gdm/apps/janus/mcp_server/git_tools.go`)
shipped with Google Gemini.app for macOS, version 1.128.14.1166 (com.google.GeminiMacOS).

**Status:** Found, verified with three independent PoCs, and reported to Google VRP.
This folder contains the full write-up, PoC code, and evidence — sanitized of all
device-specific values.

## Contents

```
REPORT.md                    ← full technical report (discovery → mechanism → proofs → impact → fixes)
EVIDENCE.md                  ← sanitized evidence log (proof outputs + negative controls)
poc/mcp_injection_poc.py     ← first-pass PoC: marker tests + controlled negatives
poc/mcp_rce_conclusive.py    ← conclusive PoC: output-capturing command execution (3 proofs)
```

## One-paragraph explanation

The Gemini app runs a Model Context Protocol (MCP) server for git so its Agent mode
can operate on repositories. The tool schema advertises `remote` as a *"Remote name
(default origin)"*, but the server never enforces that — whatever the model supplies
is appended directly to the `git pull` / `git push` argument vector. Git, like most
CLI tools, treats arguments beginning with `--` as options: `--upload-pack=CMD`
makes git spawn `CMD` as the fetch helper, and `--receive-pack=CMD` does the same on
push. The server's authors already blocklisted the dangerous `ext::` transport
("transport 'ext' not allowed"), but missed argv option injection entirely. The
result: any content that can steer the model (a README on a public repo, a webpage,
an opened file) can turn a routine "pull my repo" request into arbitrary code
execution on the user's Mac.

## Quick reproduction (your own machine, your own throwaway repo)

```bash
mkdir -p /tmp/rce_test_repo && cd /tmp/rce_test_repo
git init -q && git add -A && git commit -qm init && git remote add origin /tmp/rce_test_repo

python3 poc/mcp_rce_conclusive.py
# → /tmp/RCE_PROOF2 contains: RCE_<uid>@<hostname> — shell substitution executed
```

> **Disclaimer:** published for educational/security-research purposes. Run only
> against your own machine and repositories. Reported to Google via VRP; disclosure
> here follows the researcher's judgment after verification. Spotted a mistake?
> Contact **asishkksharma@gmail.com**. This write-up was assisted by an uncensored
> AI model (Venus AI) — proofread carefully, but corrections are welcome.
