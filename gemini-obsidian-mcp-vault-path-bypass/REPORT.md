# Full Technical Report — `obsidian_mcp_server` Vault-Path Authorization Bypass (Arbitrary Directory Access)

**Title:** `vault_path` parameter not validated as an Obsidian vault or approved folder — full note toolset (create/read/append/patch/move/delete/list) operates on arbitrary user-writable directories

**Finding class:** CWE-862 (Missing Authorization) / CWE-22-adjacent — the documented
contract ("Obsidian vault root directory") is never enforced, bypassing the app's
user-consent boundary for connected folders.

**Affected product:** Google Gemini.app for macOS, 1.128.14.1166 (com.google.GeminiMacOS)
**Affected component:** bundled helper `obsidian_mcp_server` (Go, arm64, ~7.7 MB)
**Severity:** Medium (arbitrary-directory `*.md` read/write/delete with user privileges; no code execution found)
**Found by:** independent security research on the researcher's own machine and files
**Reported to:** Google Vulnerability Reward Program (bughunters.google.com)

---

## 1. Executive summary

The Gemini desktop app ships an MCP server for Obsidian so its Agent mode can
manage the user's notes. Its tools accept a `vault_path` parameter documented as
the *"Path to the Obsidian vault root directory (defaults to discovered active
vault)"*. This research found that the server **never validates** that the given
path is an actual Obsidian vault — nor that it is one of the folders the user
connected to the app. Any user-writable directory is silently treated as a vault,
and the entire toolset then operates on `*.md` files inside it with the user's
full privileges.

Concretely verified on a directory that was never initialized as a vault (no
`.obsidian` marker) and never connected to the app (7/7 tools):

| Tool | Result on arbitrary directory |
|---|---|
| `obsidian_create_note` | ✅ file created |
| `obsidian_read_note` | ✅ file content returned |
| `obsidian_append_note` | ✅ file modified |
| `obsidian_list_notes` | ✅ file listed |
| `obsidian_delete_note` | ✅ file permanently removed |
| `obsidian_patch_note` | ✅ file content search/replaced in non-vault dir (verified: `REDACTED BY ATTACKER` written) |
| `obsidian_move_note` | ✅ file renamed across non-vault dir (`victim.md` → `stolen.md`, original gone) |

The server *does* correctly block relative `../` traversal inside a given vault
("attempts to escape vault path"), proving the vault boundary is an intended
security property — the unvalidated vault **root** is the gap.

## 2. Background

- The app's Agent mode supports bundled MCP tools (feature flags in the app binary
  include `AgentMode__enable_skill_download`, bundled obsidian tools referenced in
  app diagnostics: reading, creating, appending, patching, moving, deleting notes).
- The app itself has a **connected-folders consent model** (the app binary wires a
  `connectedFolderService` into its agent tool context) — the user approves which
  folders the agent may touch.
- `obsidian_mcp_server` is a standalone Go binary speaking MCP over stdio with no
  authentication; for research it can be driven directly, which is how this finding
  was verified without the app in the loop.
- Tool schemas (extracted from the binary's `go.shape.struct` type strings) — all
  share the same free-form `vault_path`:

```
VaultPath string  "json:\"vault_path,omitempty\" jsonschema:\"Path to the Obsidian vault root directory …\""
```

Tools (from `tools/list`): `obsidian_append_note`, `obsidian_create_directory`,
`obsidian_create_note`, `obsidian_delete_note`, `obsidian_get_backlinks`,
`obsidian_get_outgoing_links`, `obsidian_get_rules`, `obsidian_init_vault`,
`obsidian_list_notes`, `obsidian_list_tags`, `obsidian_manage_tags`,
`obsidian_move_note`, `obsidian_patch_note`, `obsidian_read_note`,
`obsidian_search_notes`.

## 3. How this was found (methodology)

1. **Carry-over hypothesis** from the sibling finding in `git_mcp_server`
   (see `../gemini-git-mcp-argument-injection-rce/`): bundled Go MCP servers pass
   parameters through with minimal validation — audit their schemas first.
2. Extracted every `go.shape.struct` schema from the binary: all fifteen tools
   expose `vault_path` as a free-form string with only a *description* ("Path to
   the Obsidian vault root directory") — no enforcement hint.
3. Drove the server over stdio against a researcher-owned temp directory that was
   never initialized as a vault and never connected to the app, and exercised the
   full toolset with harmless content.

## 4. The vulnerability

The server joins `vault_path + note_path` and applies two checks to the **result**:

- relative traversal: `..` segments are rejected ("attempts to escape vault path") — correct;
- file-type filter: only `*.md` files are recognized as notes.

But the **root** is never checked: no `.obsidian` marker requirement, no
cross-check against the app's connected-folders approval list, not even a
directory-existence check for read tools. Combined with the model's ability to
supply any `vault_path`, the intended boundary — "operate on *the user's vault*" —
is unenforced.

## 5. Proof of concept

Driver: `poc/obsidian_vaultpath_poc.py` (single clean run; MCP handshake → five
tool calls → control test). Target: `/tmp/not_a_vault_proof` — a directory that
was **never** initialized as a vault (no `.obsidian`) and **never** connected to
the app.

Observed output (sanitized; full log in EVIDENCE.md):

```
[1] create_note in non-vault dir : Successfully created note 'proof.md' | file exists: True
[2] read_note from non-vault dir  : matches file content: True
[3] append_note in non-vault dir  : marker in file: True
[4] list_notes in non-vault dir   : note listed: True
[5] delete_note in non-vault dir  : Permanently deleted note 'proof.md' | file removed: True
[C] control: ../ traversal blocked : True
*** VAULT_PATH BYPASS CONFIRMED — all 5 tools operated outside any vault ***
```

Every operation succeeded in a directory that is not a vault and was never
approved by the user.

## 6. Negative controls (what is properly defended)

| Input | Result | Meaning |
|---|---|---|
| `note_path: "../../etc/hosts"` | `ERROR: … attempts to escape vault path` | relative traversal blocked — the boundary is intentional |
| `note_path: "/etc/hosts"` (absolute) | `note 'hosts' not found in vault` | absolute paths rejected by the join |
| non-`*.md` filenames (e.g. `fakerc`) | `not found in vault` | only markdown files are visible to the tools |
| `obsidian_init_vault` on a system dir (`/etc`) | `mkdir /etc/.obsidian: permission denied` | vault initialization refuses protected paths (and read tools appear to require a real vault context for content resolution in some flows) |

The controls show the authors hardened the **inside** of the vault boundary while
leaving the boundary's **root** unvalidated.

## 7. Exploitation scenario

1. The victim uses Gemini app Agent mode with bundled Obsidian tools enabled and
   has connected one vault (e.g., their personal notes) — the normal, consented setup.
2. The victim asks Gemini about attacker-influenced content (public repo README,
   web page, opened file).
3. Injected instructions steer the model to call `obsidian_read_note` (or
   `list_notes` + `read`) with `vault_path` pointing at a directory the user never
   connected — e.g., a *different* Obsidian vault with private material,
   `~/Documents`, or a work folder — and `note_path` for a `*.md` file there.
4. Content is returned to the model and flows into the chat (exfiltration to
   attacker-visible channels or into Google's processing).
5. The same call pattern with `append`/`patch`/`delete`/`move` corrupts or destroys
   the user's markdown data in arbitrary directories.

No user action is required beyond a normal "look at this" request; the consent
boundary the app shows in its UI ("connected folders") is not consulted by the
bundled server.

## 8. Impact

- **Confidentiality:** read any `*.md` file readable by the user (private notes,
  drafts, documentation in arbitrary directories — including Obsidian vaults the
  user deliberately did not connect).
- **Integrity/availability:** create, modify, move, permanently delete `*.md`
  files in any user-writable directory.
- **Scope limit (honest):** the `*.md` filter and blocked relative traversal
  constrain direct code-execution paths — no RCE was found via this server alone.
  The finding is an authorization-bypass / privacy issue, not command execution.

## 9. Remediation recommendations

1. Validate `vault_path` server-side against the app's **connected/approved
   folders** list (the consent model the app already has), or against vaults
   explicitly registered via `obsidian_init_vault`.
2. Require the `.obsidian` marker (or equivalent registration) before operating on
   a directory, rather than accepting any path.
3. Consider making `vault_path` non-overridable per call for model-driven usage —
   bind the server to the user-connected vault(s) at configuration time.
4. Audit the sibling bundled servers (`git_mcp_server` — see the sibling report —
   and any future file-capable MCP helpers) under the same lens: parameters that
   name security-relevant roots must be validated, not described.

## 10. Timeline & disclosure

- **2026-10-14** — found during the helper-audit pass; verified across nine
  discovery tests and a clean 5/5 reproducible PoC on researcher-owned directories.
- **2026-10-14** — report prepared for Google VRP (bughunters.google.com).
- Public write-up published in this repository for educational transparency,
  alongside the sibling `git_mcp_server` finding.

## 11. Contact

Questions, corrections, or additional context: **asishkksharma@gmail.com**

> This document was written with the assistance of an uncensored AI model (Venus
> AI) and proofread carefully. The finding language deliberately uses "found /
> verified / exploitation scenario" framing. If anything reads incorrectly,
> please reach out.
