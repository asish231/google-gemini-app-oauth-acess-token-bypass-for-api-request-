# Entitlement Enforcement Audit — Plan-Tier Model Access (Documented Negative)

**Question:** Does the Gemini backend enforce plan-tier entitlements (Pro vs Ultra)
server-side, or can a client upgrade its served model tier via API parameters?

**Method:** RobinService `StreamGenerate` (ConnectRPC, `assistant.mobile.robin.RobinService`)
driven with the researcher's own Pro-plan OAuth token via the extracted-credential client.
Every client-controllable field that could influence model routing was probed
(~25 distinct probes, 2026-10-14). Served model read from the response's
`modelAttributionName`.

## Results

| Surface probed | Probe | Result | Served model |
|---|---|---|---|
| `requestedBardMode` | enum oracle (bogus string) | reveals server enum `assistant.mobile.robin.BardMode` | — |
| `requestedBardMode` | `MODE_ULTRA`, `MODE_GEMINI_PRO_NEW`, `MODE_BASIC`, `MODE_GEMINI` | **400 "Invalid value"** — not in server enum | — |
| `requestedBardMode` | `MODE_ADVANCED_BETA` | valid enum value, rejected: **"is not supported"** (policy) | — |
| `requestedBardMode` | `MODE_ADVANCED`, `MODE_CLASSIC` (controls) | 200 | 3.5 Flash-Lite |
| `model.modelId` | real names (`gemini-3-pro`, `gemini-3-pro-preview`, `gemini-3.1-pro-low-thinking`, `gemini-3.8-flash-high`, `gemini-2.5-pro`, `gemini-3-pro-thinking`) | 200, **silently overridden** | 3.5 Flash-Lite |
| `model.modelId` | web mode-picker hex IDs (`cf41b0e0dd7d53e5`, `8c46e95b1a07cecc`) | 200, overridden | 3.5 Flash-Lite |
| `model.modelId` | bogus strings | 200, fallback | 3.5 Flash-Lite |
| `testingModeCategory` (INT32) | sweep 0–8 | all ignored | 3.5 Flash-Lite |
| `testingModelId` / `testingAgentId` | real + bogus values | ignored | 3.5 Flash-Lite |
| `isSmartModelSelectionEnabled` | true / false | no routing effect | 3.5 Flash-Lite |
| `isFirstRequestAfterManualPickerOverride` | true (+ pro modelId) | no routing effect | 3.5 Flash-Lite |
| combined payload | modelId + category + testingModelId together | all overridden | 3.5 Flash-Lite |
| `modeVariantId` | arbitrary + real + "ultra" + picker hex IDs | **influences routing but only downward** — unknown variants fall back to **Legacy** (a downgrade, never an upgrade) | Legacy |
| `query.mode`, `query.model`, `resolvedModeCategory`, `thinkingLevel`, `userSelectedModel`, `modelTier` | existence oracle | fields do not exist on this RPC | — |
| `GetModeConfigs` / `ListModes` / `GetAvailableModes` / `GetModeFeatureQuota` | RPC probes | 404 (not exposed) | — |
| `CheckGeminiQuota` / `CheckModeFeatureQuota` / `GetUserStatus` | controls | 200 — quota (TPU-seconds) and status only, no tier elevation | — |

## Verdict

**Server-side entitlement enforcement is solid.** Every client-controllable model/mode
field is either (a) limited by a server-side enum, (b) silently overridden to the
account's entitled model tier, or (c) able to influence routing only *downward*
(unknown `modeVariantId` → Legacy fallback). No combination of parameters caused a
Pro-plan token to be served an Ultra-tier model.

This is a documented **negative** finding: the plan-tier gate cannot be bypassed via
`ClientGenerateRequest` parameter manipulation on the RobinService surface.

## Notes

- The `MODE_DOWNGRADE_REASON_*` enum cluster in the client binary (`QUOTA_EXHAUSTED`,
  `PEAK_HOUR`, `GREY_OUT_PRO_IN_PICKER`, …) corroborates that tier routing and
  downgrade decisions live server-side.
- Probing performed on the researcher's own account and machine; single-call PoCs only,
  no continued consumption of any non-entitled resource.
