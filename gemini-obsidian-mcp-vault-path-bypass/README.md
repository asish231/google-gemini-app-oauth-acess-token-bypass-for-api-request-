# Gemini macOS App — Bundled `obsidian_mcp_server` Vault-Path Authorization Bypass (Arbitrary Directory Access)

**Finding:** The Gemini desktop app's bundled Obsidian MCP helper accepts **any
user-writable directory** as `vault_path` — it never checks that the directory is
an actual Obsidian vault, nor one of the app's user-approved "connected folders."
Every note tool then operates there with the user's full privileges:
`create` / `read` / `append` / `patch` / `move` / `delete` / `list` on `*.md` files.

**Severity:** Medium — authorization-boundary bypass enabling arbitrary-directory
markdown file read/write/delete with user privileges (privacy exfiltration and
integrity damage; no direct code execution found).

**Affected component:** `/Applications/Gemini.app/Contents/Helpers/obsidian_mcp_server`
(Go, arm64, ~7.7 MB) shipped with Google Gemini.app for macOS 1.128.14.1166
(com.google.GeminiMacOS).

**Status:** Found, retested, and confirmed with a 5/5 reproducible PoC (plus a
defense control). Reported to Google VRP.

## Contents

```
REPORT.md                             ← full technical report
EVIDENCE.md                           ← sanitized test log (9 discovery tests + 5/5 clean repro)
poc/obsidian_vaultpath_poc.py         ← conclusive one-run PoC (create/read/append/list/delete outside any vault)
poc/obsidian_discovery_tests.py       ← the original discovery test series
```

## One-paragraph explanation

The tool schemas describe `vault_path` as *"Path to the Obsidian vault root directory
(defaults to discovered active vault)"* — the intended contract is that the model
operates on the user's vault. In reality the server treats **whatever directory it
is given** as a vault: no `.obsidian` marker is required, no allowlist of
user-connected folders is consulted. A prompt-injected model response can therefore
point the toolset at any directory on the machine (other Obsidian vaults the user
never connected, `~/Documents`, a work folder) and read, modify, or permanently
delete `*.md` files there — silently bypassing the app's connected-folders consent
model. Relative `../` traversal **is** correctly blocked (defense control), which
makes clear the boundary was intended — the vault root itself is the gap.

## Quick reproduction (your own machine, harmless temp directory)

```bash
python3 poc/obsidian_vaultpath_poc.py
# → [1..5] create/read/append/list/delete all succeed in /tmp/not_a_vault_proof
# → control: ../../ traversal blocked
# → *** VAULT_PATH BYPASS CONFIRMED ***
```

> **Disclaimer:** educational/security-research use only; run only against your own
> machine and files. Reported to Google via VRP. Spotted an inaccuracy? Contact
> **asishkksharma@gmail.com**. This write-up was assisted by an uncensored AI model
> (Venus AI) and carefully proofread — corrections welcome.
