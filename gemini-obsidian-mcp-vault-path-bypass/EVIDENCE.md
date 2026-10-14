# Evidence Log (sanitized) — `obsidian_mcp_server` Vault-Path Bypass

All tests performed 2026-10-14 on the researcher's machine against
researcher-owned temp directories and harmless system files only. No third-party
data, no real user vaults were touched; hostname and device-specific values redacted.

**Target binary:** `/Applications/Gemini.app/Contents/Helpers/obsidian_mcp_server`
(Go, arm64, ~7.7 MB; shipped with Gemini.app 1.128.14.1166)

**MCP handshake (stdio, no authentication):**

```
→ initialize {protocolVersion: 2025-06-18, clientInfo: {name: poc}}
← serverInfo: {name: "obsidian-mcp-server", version: "1.0.0"}
```

**`tools/list` (15 tools):** `obsidian_append_note`, `obsidian_create_directory`,
`obsidian_create_note`, `obsidian_delete_note`, `obsidian_get_backlinks`,
`obsidian_get_outgoing_links`, `obsidian_get_rules`, `obsidian_init_vault`,
`obsidian_list_notes`, `obsidian_list_tags`, `obsidian_manage_tags`,
`obsidian_move_note`, `obsidian_patch_note`, `obsidian_read_note`,
`obsidian_search_notes` — all accept free-form `vault_path`.

## Discovery series (test → result)

| # | Test | Result | Meaning |
|---|---|---|---|
| A | `read_note` baseline inside a real temp vault | note content returned | harness sane |
| B | `note_path: "../../etc/hosts"` | `ERROR: … attempts to escape vault path` | relative traversal **blocked** |
| C | `note_path: "/etc/hosts"` (absolute) | `note 'hosts' not found in vault` | absolute paths rejected |
| D | URL-encoded `..%2f..%2f` | rejected (same as B) | encoding tricks rejected |
| T1 | `vault_path: "/etc"`, `note_path: "hosts"` | `not found in vault` | non-`*.md` invisible |
| T2 | `init_vault` on `/etc` | `mkdir /etc/.obsidian: permission denied` | system dirs refused (perms) |
| T3 | **`create_note` with `vault_path: "/tmp/notavault"`** (never initialized) | `Successfully created note 'probe.md'`; **file created** | ✅ bypass: write outside any vault |
| T4 | **`delete_note` same dir, `permanent: true`** | `Permanently deleted note 'probe.md'`; **file removed** | ✅ bypass: delete outside any vault |
| T5 | `append_note` on extensionless file | `does not exist` | `*.md` filter discovered |
| T6 | `patch_note` with guessed field names | schema validation error → fetched real schema (`target_content`/`replacement_content`) | schemas documented |
| T7 | `read_note` extensionless existing file | `not found in vault` | confirms `*.md` filter |
| T8/T9 | `move_note` (wrong fields), `list_notes` | schema error / `No notes found` | — |
| MD-1 | `read_note` `target.md` in **non-vault** dir | **file content returned** | ✅ bypass: read |
| MD-2 | `append_note` `target.md` in **non-vault** dir | **file modified** (`APPEND_MARKER` present) | ✅ bypass: modify |
| MD-3 | `list_notes` in **non-vault** dir | **note listed** | ✅ bypass: enumerate |

## Conclusive clean repro (`poc/obsidian_vaultpath_poc.py`)

Target: `/tmp/not_a_vault_proof` — never initialized, no `.obsidian`, never
connected to the app.

```
[1] create_note in non-vault dir : Successfully created note 'proof.md' | file exists: True
[2] read_note from non-vault dir  : matches file content: True
[3] append_note in non-vault dir  : marker in file: True
[4] list_notes in non-vault dir   : note listed: True
[5] delete_note in non-vault dir  : Permanently deleted note 'proof.md' | file removed: True
[C] control: ../ traversal blocked : True
*** VAULT_PATH BYPASS CONFIRMED — all 5 tools operated outside any vault ***
```

## Verdict

The vault **root** (`vault_path`) is unvalidated: any user-writable directory is
treated as a vault, and the full `*.md` toolset (create/read/append/list/delete —
patch/move share the same pattern) operates there with user privileges. The
**inside** of the boundary is properly hardened (relative traversal blocked,
absolute paths rejected) — proving the boundary is intentional, and the root gap
is an implementation miss, not a design choice.

Run the PoC only on your own machine.
