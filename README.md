# leap-auth — Gemini macOS App OAuth Access-Token Bypass

Security research: the Google Gemini desktop app (com.google.GeminiMacOS,
1.128.14.1166, macOS ARM64) stores its complete OAuth identity on-disk in a
recoverable form. This repo chains three findings into a working proof: **fresh
access tokens minted from the app's own extracted credentials, then live
send/receive chat against the app's private RPC API** (`robinfrontend-pa.googleapis.com`).

>  **New finding (separate folder):** [`gemini-git-mcp-argument-injection-rce/`](gemini-git-mcp-argument-injection-rce/)
> — argument injection in the app's bundled `git_mcp_server` leading to arbitrary
> command execution (found exploit, verified with 3 PoCs). Full report, evidence
> log, and PoC code there.

>  **Second finding (separate folder):** [`gemini-obsidian-mcp-vault-path-bypass/`](gemini-obsidian-mcp-vault-path-bypass/)
> — the bundled `obsidian_mcp_server` never validates `vault_path` as a real vault
> or approved folder: the full note toolset (create/read/append/delete/list) operates
> on arbitrary user-writable directories (verified 5/5, with traversal-blocked
> control). Report + evidence + PoC there.

>  **Disclaimer — educational/security-research use only.** Run these tools
> only against your own machine and your own Google account. Reusing extracted
> credentials outside the official app almost certainly violates Google's ToS.
> The extracted `client_secret` belongs to Google; this repo deliberately
> **does not hardcode it** — it is derived at runtime from a stock app binary
> to prove the obfuscation is reversible.

## The chain (all steps verified live)

```
┌─ BINARY (/Applications/Gemini.app) ──────────────────────────────┐
│ client_id      : plain string                                      │
│ client_secret  : 35 bytes XOR-0x5A in __DATA_CONST @ 0x10aa4b380   │
└────────────────────────────────────────────────────────────────────┘
┌─ KEYCHAIN ("Gemini Safe Storage") ────────────────────────────────┐
│ two 32-byte AES-256-GCM keys (protobuf blob)                       │
└────────────────────────────────────────────────────────────────────┘
┌─ AUTH STORE (~/Library/Application Support/.../user1/auth) ───────┐
│ magic 2ebafeca×2 · nonce@20 · AES-GCM ciphertext@35                │
│ decrypts to StoredCredentialData{ gaia_id, email, scopes,         │
│   refresh_token, id_token }                                        │
└────────────────────────────────────────────────────────────────────┘
        │  client_id + client_secret + refresh_token
        ▼
   oauth2.googleapis.com/token  →  ya29.… access token (all 18 app scopes)
        ▼
   robinfrontend-pa.googleapis.com/$rpc/assistant.mobile.robin.RobinService
   ├── CheckGeminiQuota   → live account quota
   ├── ListConversations  → real conversation list
   └── StreamGenerate      → {"query":{"text":"…"}} → real generated replies
```

Verified end-to-end: `9×7 → "63"`, `capital of Japan → "Tokyo"`, `2+2 → "4"` (2/2 repeatable, ~2.5–3 s round-trip).

## Repo layout

```
clients/
  gemini_desktop_client.py   # full desktop-API chat client (self-extracting creds)
  gemini_web_client.py       # web-API client via Chrome CDP (session riding)
tools/
  extract_client_secret.py   # XOR-0x5A decode of the secret from the binary
  decrypt_auth.py            # keychain keys -> AES-GCM decrypt of auth store
  parse_auth.py              # protobuf parse of StoredCredentialData
  xref_scan.py               # ARM64 ADRP+ADD xref scanner (finds the OAuth builder)
  xref_dump.py               # string-reference dump of the builder function
  disas_oauth.py             # capstone view of the secret-provider function
  oauth_server.py            # localhost OAuth callback listener (auth-code capture)
  mach_scan.py               # mach-API memory scan attempt (blocked by hardened runtime)
  lldb_secret_scan.py        # lldb memory scan attempt (blocked by hardened runtime)
docs/
  VULN_REPORT.md             # full findings report (sanitized)
  METHODOLOGY.md             # how every artifact was collected, step by step
config/
  credentials.example.json   # shape of the gitignored local credentials file
```

## Quick start (your own machine, your own account)

```bash
pip3 install --user --break-system-packages cryptography websocket-client capstone numpy

# 1. Extract the client_secret from the app binary
python3 tools/extract_client_secret.py

# 2. Decrypt the auth store (pulls AES keys from your keychain at runtime)
python3 tools/decrypt_auth.py && python3 tools/parse_auth.py

# 3. Chat through the app's private API (auto-runs 1+2 if needed)
python3 clients/gemini_desktop_client.py "What is 9 multiplied by 7?"

# Alternative: web API via a signed-in Chrome (CDP port 9222)
python3 clients/gemini_web_client.py "What is 7 multiplied by 6?"
```

The clients never contain credential values — they collect them from the
binary/keychain/auth-store at runtime, exactly as an attacker's process would.

## Findings summary

| # | Finding | Severity |
|---|---|---|
| 1 | `client_secret` shipped in binary, "protected" by single-byte XOR | High (design) |
| 2 | Auth store decryptable — AES keys sit in the same user's keychain | High |
| 2b | Auth file mode `644` (world-readable ciphertext) | Low/Med |
| 3 | Extracted identity mints tokens accepted by the private RPC API | Critical (chain) |
| 4 | Web session riding via CDP (cookies+XSRF) enables scripted chat | High (chain) |

Full details: `docs/VULN_REPORT.md`. Step-by-step collection story: `docs/METHODOLOGY.md`.

## Responsible disclosure

Recommendations for the vendor are in the report (token-broker instead of shipped
secret, 0600 store perms, device-bound refresh tokens, shorter-lived access).
**Before publishing credentials or filing, rotate access**: revoke the app's
grant at https://myaccount.google.com/connections and sign out/in of the app.

## Code quality, provenance & contact

- **Every script in this repo was verified working live** during the original
  research session, then **rewritten into a clean, public-readable format** —
  clear docstrings, argument options, sane structure, and no leftover debug
  scratch code. What's pushed is simply a cleaned-up, well-organized version of
  the exact tools that produced the findings; nothing was added or invented.
- **Sanitization:** no personal secrets are hardcoded anywhere. Every credential
  slot (client_secret, AES keys, refresh_token, cookies, XSRF) is replaced by
  the script that collects it at runtime from your own machine — that's the PoC.
- **Transparency:** this research write-up was produced with the assistance of
  an uncensored AI model (Venis AI), so there may be occasional typos or
  phrasing mistakes in the docs. I have proofread everything to the best of my
  ability — if you spot an error, please reach out to
  **asishkksharma@gmail.com** and I'll fix it.
