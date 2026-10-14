# Methodology — how every artifact was collected

This is the step-by-step story of the audit. Nothing here was guessed; every
claim maps to a tool in `tools/` that reproduces it. **No credential values
appear anywhere in this repo** — each one is replaced by the script that
collects it at runtime.

> **Note:** all scripts referenced below were verified live and then rewritten
> into this clean, public-readable format. If anything reads awkwardly or you
> find a mistake (this documentation was assisted by an uncensored AI model,
> Venus AI), please reach out to **asishkksharma@gmail.com**.

## Phase 0 — Reconnaissance (no tools shipped)

- `strings` over the 213 MB arm64 binary surfaced:
  - the OAuth **client_id** (`839509190550-…apps.googleusercontent.com`) — plain string;
  - endpoint hostnames: `robinfrontend-pa.googleapis.com`,
    `webchannel-robinfrontend-pa.googleapis.com`, `oauth2.googleapis.com`,
    `accounts.google.com/o/oauth2/auth`, `www.googleapis.com/oauth2/v4/token`;
  - 132 `$rpc/assistant.mobile.robin.RobinService/…` method paths → ConnectRPC;
  - crypto hints: boringssl ChaCha20-Poly1305, `keystore_loader_mac.cc`,
    keychain service name `Gemini Safe Storage`, acct `Gemini Keys`;
  - the auth-store path via `Data/` + `/auth` strings next to the client_id.
- App logs (`~/Library/Caches/com.google.GeminiMacOS/Logs/diagnostic*.log`)
  confirmed: `signinStatus=signedIn`, token refresh every ~60 min with the full
  18-scope list, `Browser OAuth not needed: kSignedIn`.
- Live network check (`lsof`/`nettop`): the app held a TLS session to
  `webchannel-robinfrontend-pa` (the SSE streaming endpoint).

## Phase 1 — Auth store format + decryption (→ `tools/decrypt_auth.py`)

1. `xxd` the 2 KB `~/…/Data/user1/auth` file → magic `2ebafeca` repeated twice.
2. Hand-parsed the protobuf header: field 4 = **12-byte nonce** (offset 20),
   field 5 = ciphertext length (offset 35 start).
3. `security find-generic-password -s "Gemini Safe Storage" -w` returned a
   hex protobuf blob; parsing it yielded **two 32-byte keys**.
4. Built a decryption matrix: {key1, key2} × {AES-256-GCM, ChaCha20-Poly1305}
   × {ct@30, ct@35, ct@37} × {AAD: none/8B/12B/35B} × nonce offsets.
   **AES-GCM with key #1, nonce@20, ct@35 won** → plaintext protobuf
   (`StoredCredentialData`): gaia_id, email, scopes, **refresh_token**,
   id_token JWT, profile name/photo.
5. `tools/parse_auth.py` maps the field numbers (schema strings recovered from
   the binary: `StoredCredentialData`, `refresh_token`, `gaia_id`, …).

## Phase 2 — Binary analysis: finding the client_secret
(→ `tools/xref_scan.py`, `tools/xref_dump.py`, `tools/disas_oauth.py`)

1. `strings` had NO `GOCSPX` and no secret-like literal near the client_id —
   only `[REDACTED:string:` markers → the secret is **constructed at runtime**.
2. Wrote an ARM64 cross-reference scanner (numpy over the 178 MB `__TEXT`):
   decode all instructions, find `ADRP` (opcode mask `0x9F000000 == 0x90000000`),
   pair with a following `ADD #imm12` on the same register, and keep pairs
   resolving to the client_id's page → **one exact reference at PC `0x10087966c`**.
3. `tools/xref_dump.py` dumped every string reference in the OAuth builder
   (`createOAuthClientsAsDataAndReturnError`): client_id, 18 scopes, keychain
   names — and a call to a sub-function at `0x1008794bc` right where the
   `Argo_OAuthClient.client_secret` field gets filled.
4. Capstone disassembly of `0x1008794bc` exposed the deobfuscator:

   ```asm
   adrp x23, 0x10aa4b000 ; add x23, x23, #0x360   ; blob base
   mov  w24, #0x5a                                ; XOR key
   ldrb w26, [x8, #0x20] ; eor w8, w26, w24        ; decode loop
   cmp  x22, #0x23                                ; 35 bytes
   ```

5. `__DATA_CONST` mapping from `otool -l` (vmaddr `0x10a9f0000`, fileoff
   178192384) gave file offset 178566016; XOR-0x5A decoding produced a valid
   `GOCSPX-…` Google client secret. `tools/extract_client_secret.py` now does
   this standalone (Mach-O header parsing instead of otool).

### Dead ends (kept as documentation)

- `lldb` attach → **denied** (hardened runtime, no `get-task-allow`).
- Raw `task_for_pid` via ctypes (`tools/mach_scan.py`) → **denied** (unsigned
  helper lacks the entitlement; Apple's signed `sample`/`vmmap` DO work, so
  process introspection itself is allowed for same-user tools).
- `heap`/`leaks` memory string-scan → no string-search capability / no hits.
- Single-byte XOR scan for `GOCSPX` across ±1 MB of the client_id → 0 hits
  (the blob lives in `__DATA_CONST`, far from the string).

## Phase 3 — Token minting + private API (→ `clients/gemini_desktop_client.py`)

1. `POST oauth2.googleapis.com/token` with (client_id, XOR-decoded secret,
   extracted refresh_token) → **fresh `ya29.…` access token** (3599 s, all
   18 scopes). The endpoint that returned `403 PERMISSION_DENIED` before the
   audit now accepted requests.
2. `CheckGeminiQuota` → live quota JSON. `ListConversations` → the account's
   real conversations. (A 404 on one method name was expected — method names
   differ; the working set was enumerated from the binary's `$rpc` strings.)
3. `StreamGenerate` schema discovered via a **server validation oracle**:
   posting unknown JSON fields returns `Cannot find field "x"` — probing
   `query` returned `Invalid value at 'query.query' (…UserQuery), "hi"`,
   revealing `query: {text}` without any captured request.
4. `{"query": {"text": "…"}}` → `{"modelResponses":[{"textResponse":{"text": …}}]}`.
   Verified 2/2: `"63"` (9×7), `"Tokyo"` (capital of Japan), plus `"4"` (2+2).

## Phase 4 — Web-session riding (→ `tools/capture_request.py`, `clients/gemini_web_client.py`)

Independent chain against `gemini.google.com` (no extracted OAuth needed):

1. Chrome with `--remote-debugging-port=9222`, signed into Gemini.
2. Learning curve of the UI automation (documented so it's reproducible):
   - the editable element is `.ql-editor` (NOT `.text-input-field`, and
     `.ql-clipboard` is Quill's hidden mirror — typing there is invisible);
   - text must be inserted via `Input.insertText` (Angular sees real input);
   - the **Send button only appears once text is present**
     (`button[aria-label="Send message"]`);
   - JS `el.click()` is ignored (`isTrusted: false`); `Input.dispatchKeyEvent`
     Enter was ignored; a **trusted CDP mousePressed/Released pair** at the
     button center works — but ONLY after `Page.bringToFront()` (background
     tabs drop input events).
3. XHR hooks (monkey-patched `open`/`send`) captured the exact
   `StreamGenerate` envelope + streamed response.
4. Response format: `)]}'` prefix, then `[len]\n[json]` chunks where **len
   includes the trailing `\r\n`** (the 2-byte bug that initially broke every
   parser). Generated text lives in `rc_*` blocks nested in `wrb.fr` payloads.
5. Verified 2/2: `"42"` (7×6), `"Paris"` (capital of France), and a full-text
   extraction of an open-domain answer.

## Phase 5 — OAuth flow itself (→ `tools/oauth_server.py`)

- Reconstructed the app's browser OAuth: client_id + loopback redirect
  (`http://localhost:PORT/…`) + PKCE (`code_challenge`, S256) — strings from
  `auth_code_provider_localhost.cc` in the binary.
- Ran a localhost callback listener; the **authorization code** was captured
  live — proving the flow — but the exchange requires the client_secret
  (Phase 2's target), closing the loop.

## Artifact → tool map

| Secret/artifact | Hardcoded? | Collected at runtime by |
|---|---|---|
| client_id | ✅ (public identifier, not a secret) | `extract_client_secret.py` |
| client_secret | ❌ never | `extract_client_secret.py` (XOR-0x5A decode) |
| AES keys | ❌ never | `decrypt_auth.py` (keychain read) |
| refresh_token | ❌ never | `decrypt_auth.py` + `parse_auth.py` |
| access token | ❌ never | minted fresh by `clients/gemini_desktop_client.py` |
| XSRF + session cookies | ❌ never | `gemini_web_client.py` (live page) |
| f.req envelope | ❌ never | `capture_request.py` writes a gitignored template |
