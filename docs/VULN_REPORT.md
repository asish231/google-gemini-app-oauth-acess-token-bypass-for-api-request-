# Gemini macOS App — OAuth Reverse-Engineering & Security Analysis Report

**Target:** Google Gemini.app 1.128.14.1166 (com.google.GeminiMacOS) — macOS ARM64
**Date:** 2026-10-14
**Status:** All findings PROVEN by live exploitation on the researcher's own machine/account
**Note:** personal identifiers have been redacted; secret values are never printed —
each is re-derived at runtime by the corresponding tool.

> **About the code in this repo:** every script was verified working during the
> research session and then rewritten into a clean, readable format for public
> consumption — the pushed code is simply a tidied-up version of the exact tools
> that produced these findings. This write-up was assisted by an uncensored AI
> model (Venus AI), so occasional typos/phrasing slips are possible despite my
> best proofreading — corrections welcome at **asishkksharma@gmail.com**.

---

## Executive Summary

The Gemini desktop app's entire OAuth credential chain is recoverable by any code
running as the logged-in user. Chaining three findings fully replicates the app's
authentication and yields **working send/receive chat access to the app's private
RPC API** (`robinfrontend-pa.googleapis.com`) — the same API the app uses.

**Final proof:** `StreamGenerate` with `{"query": {"text": "…"}}` returned real
generated responses — `"63"` (9×7), `"Tokyo"` (capital of Japan), `"4"` (2×2) —
2/2 repeatable, ~2.5–3.2 s round-trips.

---

## Finding 1 — OAuth client_secret embedded in the binary (trivially deobfuscated)

**Severity: High (by-design weakness of installed-app secrets, but the "obfuscation" is security theater)**

- The Swift OAuth-config builder (`createOAuthClientsAsDataAndReturnError`,
  `JanusLibWrapperImpl.mm`) constructs `Argo_OAuthClient` with clientID, scopes —
  and a clientSecret **computed at runtime**.
- Located via an ARM64 cross-reference scan (ADRP+ADD pairs against the client_id
  string at VA `0x109e17220`).
- The secret-provider function at `0x1008794bc` reads 35 bytes from
  `__DATA_CONST` VA `0x10aa4b380` (file offset 178566016) and **XORs each byte
  with 0x5A**:

```asm
adrp x23, #0x10aa4b000
add  x23, x23, #0x360      ; blob base
mov  w24, #0x5a            ; XOR key
ldrb w26, [x8, #0x20]     ; obfuscated byte
eor  w8, w26, w24          ; decode
cmp  x22, #0x23            ; 35 bytes
```

**Extraction:** `tools/extract_client_secret.py` re-derives the secret from a
stock binary at runtime (Mach-O headers are parsed, VA→file-offset computed,
XOR-0x5A applied, and the result is validated against the `GOCSPX-` format).
**Proof:** a valid access token was minted from Google's token endpoint using
only these + the Finding-2 refresh token.

## Finding 2 — OAuth credential store decryptable (refresh_token extraction)

**Severity: High**

- The app persists OAuth credentials at
  `~/Library/Application Support/com.google.GeminiMacOS/Data/user1/auth`.
- Format: magic `2ebafeca×2` + version + protobuf header (12-byte nonce at
  offset 20, ciphertext at offset 35) + **AES-256-GCM** ciphertext (ct ‖ 16-byte tag).
- The encryption keys live in the login keychain (`Gemini Safe Storage` /
  acct `Gemini Keys`) as a protobuf blob containing two 32-byte keys — readable
  by any process the user approves for keychain access.
- Decrypted plaintext (protobuf `StoredCredentialData`): gaia_id, email, full
  scope list, **refresh_token**, id_token JWT, profile info.

**Extraction:** `tools/decrypt_auth.py` reads the keychain keys at runtime,
exhausts the key/offset/AAD/cipher matrix, and writes the plaintext;
`tools/parse_auth.py` maps the protobuf fields.
**Proof:** the extracted refresh token works — see Finding 3.

**Weakness (2b):** the auth file is mode **644 (world-readable)** — any local
process can exfiltrate the ciphertext silently.

## Finding 3 — Full private-API access with extracted credentials (chat)

**Severity: Critical (as a chain)**

**Token minting** (the app's exact client credentials):

```
POST https://oauth2.googleapis.com/token
  client_id=839509190550-…       (from binary)
  client_secret=GOCSPX-…          (XOR-decoded from binary)
  refresh_token=1//…             (from decrypted auth store)
→ ya29.… access token (3599 s, all 18 app scopes)
```

**Private API** (`robinfrontend-pa.googleapis.com` — returned
`403 PERMISSION_DENIED` to unauthenticated callers at the start of the audit):

| RPC | Result |
|---|---|
| `CheckGeminiQuota` | ✅ live quota (TPU-seconds, % used) |
| `ListConversations` | ✅ full conversation list with IDs + titles |
| `StreamGenerate` | ✅ **real chat generation** |

**Chat proof** (ConnectRPC JSON codec; schema discovered via a server validation
oracle — unknown fields return `Cannot find field`, revealing
`query: UserQuery{text}`):

```json
POST /$rpc/assistant.mobile.robin.RobinService/StreamGenerate
Authorization: Bearer ya29…
{"query": {"text": "What is 9 multiplied by 7? Reply with only the number."}}

→ [{"modelResponses": [{"responseId": "rc_…",
    "textResponse": {"text": "63"}}]}]
```

2/2 repeatability verified (`"63"`, `"Tokyo"`).

## Supporting findings

- **F4 — Web-session riding:** with CDP access to a signed-in Chrome, the web API
  (`gemini.google.com/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate`)
  is fully scriptable. Envelope: `f.req=[null, "<inner>"]`, message at
  `inner[0][0]`, XSRF (`at=`) scraped from `SNlM0e` in page scripts. The streamed
  response is `)]}'` + length-prefixed JSON chunks (declared length **includes**
  the trailing `\r\n`); generated text sits in `rc_*` blocks inside `wrb.fr`
  payloads. Trusted CDP mouse events (after `Page.bringToFront`) are required —
  Angular ignores synthetic `el.click()`. Verified 2/2 (`"42"`, `"Paris"`).
- **F5 — Endpoint/protocol map (from binary):** prod `robinfrontend-pa` and
  streaming `webchannel-robinfrontend-pa` (SSE), 132 `$rpc` methods on
  `assistant.mobile.robin.RobinService`, ConnectRPC (`application/json` +
  `application/proto`), plus autopush/preprod/staging variants compiled in.
- **F6 — OAuth flow:** browser-based PKCE loopback flow (localhost callback),
  auth endpoint `accounts.google.com/o/oauth2/auth`, token endpoint
  `www.googleapis.com/oauth2/v4/token`.

## Attack-chain summary

```
binary (client_id + XOR'd client_secret)  ┐
keychain (AES keys) → decrypt auth store │→ refresh_token → ACCESS TOKEN → RobinService
(refresh_token)                          ┘                                   │
                                                                      chat send/receive ✅
```

Any process running as the user (with the keychain unlocked / one approval) can
replicate this chain and use the victim's Gemini subscription programmatically,
invisibly to the app.

## Recommendations

1. Replace the shipped client_secret with a Google-internal token broker
   (e.g., GaiaMint attestation-bound exchange) — XOR is not protection.
2. Store the credential store with `0600` permissions.
3. Bind refresh tokens to device attestation / DPoP-style proofs so extracted
   tokens cannot be replayed from other clients.
4. Prefer short-lived, app-attested access over 1-hour bearer tokens.
5. Detect anomaly: minted tokens from non-app TLS fingerprints / unusual clients.
