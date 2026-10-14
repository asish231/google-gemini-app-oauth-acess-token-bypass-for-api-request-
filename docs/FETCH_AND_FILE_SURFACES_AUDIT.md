# Third-Party Fetch & File-Handling Surfaces Audit (Documented Negatives)

Follow-up round covering the remaining solo-testable server surfaces after the
entitlement and server-authz audits. All probes use the researcher's own OAuth
token and account; no third-party or internal targets were touched.

## 1. Custom MCP OAuth initiation (`InitiateCustomMcpAuth`) — URL scheme enforced

The RPC fetches a user-supplied MCP server URL server-side ("The MCP server
could not be reached. Please check the URL." for unresolvable hosts), which is
the expected behavior for a connect-third-party-service feature — and the exact
shape where SSRF hides. Probed the fetcher's scheme handling via error behavior
(no internal targets touched):

| URL | Result |
|---|---|
| `https://example.example/` | 404 "could not be reached" (attempted fetch) |
| `http://example.example/` | 500 "URL must use HTTPS" |
| `file:///etc/hostname` | 500 "URL must use HTTPS" |
| `gopher://example.example/1` | 500 "URL must use HTTPS" |
| `ftp://example.example/x` | 500 "URL must use HTTPS" |

**Verdict:** scheme allowlist enforced (HTTPS-only). No `file://` local-read
primitive, no cleartext downgrade. Internal-target probing (metadata endpoints,
internal ports) was deliberately **not** performed — out of scope. Negative.

## 2. Conversation search injection (`SearchConversationHistory`) — parameterized

Differential test: SQL metacharacters (`' OR '1'='1`, `"; DROP TABLE x; --`),
NUL byte, and path separators all return byte-identical result sets to a
guaranteed-no-match gibberish string (4686 B, 0 results), while a real term
(`test`) returns 11 snippets (95790 B). The query is treated literally
(parameterized/FTS) — **no SQL injection**.

## 3. File-handling RPCs — no attacker-controlled paths or URLs

`DownloadGeneratedImage`, `SaveEditedImage`, `ExportMessage`,
`Get/DeleteGeminiAppArtifacts`, `ProcessFile`: field oracles show **no**
`url`/`path`/`filename`/`destination`-style fields on any of them (all return
"Cannot find field"). These RPCs operate on server-managed artifact references,
not caller-supplied paths — no traversal or server-fetch primitive. Negative.

## 4. Preference/bot write paths — no tier surface

`UpdateUserPreferences`: 12-field oracle finds no plan/tier/mode fields; a real
write round-trips only cosmetic fields. Bots (`CreateBot`/`GetBot`/`DeleteBot`)
carry no model/tier fields (`defaultFeatureMode` only); a probe bot created
during testing was deleted afterwards. Negative.

## 5. Sibling generation endpoints

`StreamGenerateYourDay` works (legitimate feature); `StreamGmailInlineRewrite`
and `StreamGenerateProjectDetail` reject malformed shapes with field errors —
no parallel unauthenticated generation path found.

## Overall

No new vulnerability in this round. Combined with the entitlement audit (25+
probes, server-enforced tiers) and the server-authz audit (ownership enforced,
unguessable IDs), the solo-testable server surface of RobinService is now
comprehensively covered with no bypass found. The single open high-stakes lead
remains the **second-account cross-account A/B test** (sharing flows).
