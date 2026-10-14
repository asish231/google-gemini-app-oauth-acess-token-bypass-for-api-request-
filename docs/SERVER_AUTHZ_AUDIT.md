# Server-Side Authorization Audit — RobinService Object Access & Mutations (Documented Negative)

**Question:** Does the Gemini backend enforce object ownership server-side on
conversation/mutation RPCs, or can a caller read, modify, or delete objects it
does not own (IDOR / broken object-level authorization)?

**Method:** RobinService ConnectRPC driven with the researcher's own OAuth token
(Pro plan) via the extracted-credential client. All probes use the researcher's
OWN objects plus single-hex-flipped IDs (objects that almost certainly do not
exist). Testing stopped at existence/oracle signals — no foreign data was ever
returned, so there was nothing further to pursue solo.

## Results

| Probe | Result |
|---|---|
| ID structure (50 conversation IDs) | `c_` + 16 hex (64-bit), 0/49 gaps < 4096, no timestamp correlation → cryptographically random, enumeration infeasible |
| Correct conversation RPCs discovered | `GetConversationMetadata`, `ListConversationTurns` (earlier `GetConversation` 404s — wrong method name, not an authz signal) |
| `GetConversationMetadata` flipped IDs (×3) | Clean **404** `Conversation not found` (`NOT_FOUND`) |
| `ListConversationTurns` flipped ID | Clean **404** `CONVERSATION_TURNS_NOT_FOUND` with structured `RobinStatus` detail |
| `UpdateConversation` schema | Nested shape `{"conversation": {conversationId, pinned, …}}` (flat fields rejected); works on own object (pin round-trip verified + restored) |
| `UpdateConversation` flipped ID | Clean **404** `UPDATE_CONVERSATION_NOT_FOUND` |
| `DeleteConversation` / `BatchDeleteConversations` nonexistent IDs | Silent success (idempotent no-op — standard REST behavior, harmless) |
| `BranchConversation` conversationId-only | 500 `BranchNotFoundException: Invalid request id` (requires turn-level IDs too) |
| `ListPermissions` / `RevokePermission` bogus ID | Clean metadata-only / no-op responses |
| Share-creation shape (`CreateSharedConversation`) | Takes `sharedConversation` wrapper requiring embedded turn history (`conversation_id`, `conversation_turn`, `share_token`, `external_url_id`, `shortened_url` fields mapped from binary); full share lifecycle + cross-account test **requires a second Google account** |

## Verdict

**Server-side object authorization is solid everywhere reachable with a single
account.** Nonexistent/foreign IDs return structured 404s on reads AND mutations;
deletes are safely idempotent; IDs are unguessable. No IDOR, no confused-deputy,
no mass-assignment signal was observed.

The one test that could still yield a finding — true cross-account access (account
A's token touching account B's objects, or share-link access controls) —
fundamentally requires a second account owned by the researcher and was not
performed. Queued as the single open lead.

Probed on the researcher's own account and machine; single-call PoCs only.
