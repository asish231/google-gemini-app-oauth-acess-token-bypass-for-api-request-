# Entitlement Enforcement Audit — Plan-Tier Model Access (Documented Negative)

**Question:** Does the Gemini backend enforce plan-tier entitlements (Pro vs Ultra)
server-side, or can a client upgrade its served model tier via API parameters?

**Method:** RobinService `StreamGenerate` (ConnectRPC, `assistant.mobile.robin.RobinService`)
driven with the researcher's own Pro-plan OAuth token via the extracted-credential client.
Every client-controllable field that could influence model routing was probed
(~25 distinct probes, 2026-10-14). Served model read from the response's
`modelAttributionName`.

## Results (extended: 25+ distinct probe methods)

| Surface probed | Probe | Result | Served model |
|---|---|---|---|
| `requestedBardMode` | enum oracle (bogus string) | reveals server enum `assistant.mobile.robin.BardMode` | — |
| `requestedBardMode` | `MODE_ULTRA`, `MODE_GEMINI_PRO_NEW`, `MODE_BASIC`, `MODE_GEMINI` | **400 "Invalid value"** — not in server enum | — |
| `requestedBardMode` | `MODE_ADVANCED_BETA` | valid enum value, rejected: **"is not supported"** (policy) | — |
| `requestedBardMode` | `MODE_ADVANCED`, `MODE_CLASSIC` (controls) | 200 | 3.5 Flash-Lite |
| `model.modelId` | real names (`gemini-3-pro`, `gemini-3-pro-preview`, `gemini-3.1-pro-low-thinking`, `gemini-3.8-flash-high`, `gemini-2.5-pro`, `gemini-3-pro-thinking`) | 200, **silently overridden** | 3.5 Flash-Lite |
| `model.modelId` | web mode-picker hex IDs (`cf41b0e0dd7d53e5`, `8c46e95b1a07cecc`) | 200, overridden | 3.5 Flash-Lite |
| `model.modelId` | bogus strings | 200, fallback | 3.5 Flash-Lite |
| `model.*` subfields | `model`,`id`,`name`,`category`,`tier`,`variant`,`version`,`family`,`displayName`,`experimental`,`thinkingLevel`,`spec`,`capabilities` | **do not exist** (only `modelId`) | — |
| `testingModeCategory` (INT32) | **full sweep 0–30 (31 values)** | all ignored | 3.5 Flash-Lite |
| `testingModelId` / `testingAgentId` | real + bogus values | ignored | 3.5 Flash-Lite |
| `isSmartModelSelectionEnabled` | true / false | no routing effect | 3.5 Flash-Lite |
| `isFirstRequestAfterManualPickerOverride` | true (+ pro modelId) | no routing effect | 3.5 Flash-Lite |
| combined payload | modelId + category + testingModelId together | all overridden | 3.5 Flash-Lite |
| `modeVariantId` | arbitrary + real + "ultra"/"pro" + picker hex IDs (all 4 real mode IDs) | **influences routing but only downward** — unknown/foreign variants fall back to **Legacy** (a downgrade, never an upgrade) | Legacy |
| mode-selection fields | `modeId`, `requestedModeId`, `bardModeId`, `selectedModeId`, `currentModeId`, `activeModeId` | **do not exist** on this RPC | — |
| `query.*` subfields | `bardMode`, `mode`, `model`, `modeId`, `language`, `locale`, `voiceQuery`, `conversationId`, `parentTurnId`, `clientTurnId` | **do not exist** (only `text`, `attachments`) | — |
| top-level context | `conversationId`, `targetConversationId`, `parentTurnId(s)`, `parentReqId`, `clientTurnId`, `lastTurnId` | **do not exist** on StreamGenerate | — |
| `userPreferences.*` | `plan`, `tier`, `subscriptionTier`, `bardMode`, `defaultMode`, `modelPreference`, `preferredModel`, `enableUltra`, `isUltraUser` (+3 more) | **do not exist** (12 fields tested) | — |
| `UpdateUserPreferences` | real field write + re-read | write path works, applies only known cosmetic fields | — |
| `CreateBot` | wrapper/shape discovery + `model` subfield | `bot`/`publicMetadata` wrappers rejected; unknown `botConfig` tolerated (creates default bot, cleaned up); bots carry **no model/tier fields** (`defaultFeatureMode` only) | — |
| `GetBot`/`DeleteBot` | own bot read + probe-bot lifecycle | works as documented; probe bot deleted | — |
| preprod endpoint | `preprod-robinfrontend-pa` + pro modelId | 200, **same enforcement** | 3.5 Flash-Lite |
| mode-config RPCs | `GetModeConfigs`, `ListModes`, `GetAvailableModes`, `GetModeFeatureQuota` | **404** (not exposed) | — |
| `CheckGeminiQuota` / `CheckModeFeatureQuota` / `GetUserStatus` / `GetUsageInfo` (`userTier: TIER1`, GXU pools) | controls | 200 — quota/status only, no tier elevation path | — |
| `ProcessQuery` | string vs object shapes | requires different (object) shape; not a parallel generation path for this probe | — |
| `UpdateConversation`, `GetConversationTurn` | wrong-field probes | 400 (field shape, not authz signal) | — |

## Verdict

**Server-side entitlement enforcement is solid.** Every client-controllable model/mode
field is either (a) limited by a server-side enum, (b) silently overridden to the
account's entitled model tier, or (c) able to influence routing only *downward*
(unknown `modeVariantId` → Legacy fallback). No combination of parameters caused a
Pro-plan token to be served an Ultra-tier model.

Additional server-side signals corroborate account-bound routing: `GetUserStatus`
reports `isAdvancedModeUser: true`, `isSubscriptionTierForced: false`, mode-picker
categories gated by `requiresAdvancedSubscription`, and a `launch_ultra_mode_pro_policy`
with per-category configs; `GetUsageInfo` exposes `userTier: TIER1` plus GXU budget
pools — all read-only, with no client-writable tier path found anywhere
(`UpdateUserPreferences` accepts only cosmetic fields; bot objects carry no model fields).

This is a documented **negative** finding: the plan-tier gate cannot be bypassed via
`ClientGenerateRequest` parameter manipulation or any adjacent RobinService surface
probed on the researcher's own Pro-plan account.

## Notes

- The `MODE_DOWNGRADE_REASON_*` enum cluster in the client binary (`QUOTA_EXHAUSTED`,
  `PEAK_HOUR`, `GREY_OUT_PRO_IN_PICKER`, …) corroborates that tier routing and
  downgrade decisions live server-side.
- Probing performed on the researcher's own account and machine; single-call PoCs only,
  no continued consumption of any non-entitled resource.
