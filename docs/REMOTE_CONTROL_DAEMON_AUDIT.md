# Remote-Control Daemon Audit — agy `remote-control` (Documented Negative)

**Question:** Does the Gemini-bundled `agy` remote-control daemon expose a
remotely reachable attack surface (unauthenticated listeners, weak pairing,
cross-origin WebSocket hijack)?

**Method:** Started the daemon locally with `--session --name "research-probe-tmp"`
(login-scoped, stops at logout — no boot persistence), probed both listeners,
then stopped it and verified full cleanup. All testing on the researcher's own
machine.

## Findings

| Probe | Result |
|---|---|
| Listeners | `127.0.0.1:52101` (TLS-only: plain HTTP → `400 Client sent an HTTP request to an HTTPS server`), `127.0.0.1:52102` (Go HTTP mux, loopback-only) — no 0.0.0.0 binding |
| HTTP routes (`/`, `/health`, `/status`, `/metrics`, `/debug/pprof/`, `/api`, `/ws`) | All **404** (unknown paths rejected; real API rides paired channels) |
| Evil `Origin` / evil `Host` on both ports | Rejected (400/403 paths) |
| WebSocket, no `Origin` | **101 accepted**; protocol answers `ping`→`pong` with zero challenge |
| WebSocket, `Origin: null` | **403** (sandboxed-iframe shape blocked) |
| Post-handshake messages (`tools/list`, `hello`) | Ignored (0 bytes) — real sessions require the paired companion flow (token file + webrtc mesh + Google signaling), not the local socket |
| Outbound | webrtc signaling + Google endpoints only (expected for a paired-remote feature) |

## Verdict

**No remotely exploitable surface.** Both listeners are loopback-only,
origin-checked, and functionally gated behind the cloud pairing flow
(companion URL + token). The unauthenticated local ping/pong socket is the same
local-trust-domain pattern as the Code Mode hub WebSocket (see agy HostBridge
audit) — reachable only by local processes, informational at most.

## Cleanup (verified)

- `agy remote-control stop` → status `not running`
- Ports 52101/52102 closed (no listeners)
- No LaunchAgent leftovers in `~/Library/LaunchAgents/`
- No local daemon token files found
- Note: the cloud-side instance name registration may linger on
  antigravity.google.com (inert with nothing listening)

Probed on the researcher's own machine; daemon started and stopped within the
test window.
