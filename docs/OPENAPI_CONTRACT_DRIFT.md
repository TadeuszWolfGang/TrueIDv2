## OpenAPI Contract Drift

This document tracks the contract drift between runtime payloads, `docs/openapi.yaml`, and contract tests.

### Scope

Milestone 1 intentionally covers only five critical endpoint groups:

- search
- conflicts
- alerts
- timeline
- export

Out of scope for this milestone:

- SSE payloads from `crates/common/src/live_event.rs`
- notification payloads from `apps/web/src/routes_notifications.rs`
- the remaining `additionalProperties: true` schemas outside the five groups above

### Drift Table

| Group | Runtime Source | Current Drift | Milestone 1 Action |
| --- | --- | --- | --- |
| Search | `apps/web/src/routes_search.rs`, `crates/common/src/model.rs` | `SearchResponse.events` uses an untyped object list in OpenAPI instead of `StoredEvent`. `DeviceMapping` in OpenAPI is missing `country_code`, `city`, and `tags`, and still advertises a top-level `user` field that the runtime struct does not expose. | Document `StoredEvent`, fix `DeviceMapping`, keep runtime unchanged. |
| Export | `apps/web/src/routes_search.rs` | Export endpoints omit supported filters (`vendor`, `from`, `to`) and do not document `x-trueid-truncated`, attachment semantics, or CSV field behavior (`user` vs `current_users`). | Extend query params and response headers/notes in OpenAPI. |
| Conflicts | `apps/web/src/routes_conflicts.rs` | `Conflict` schema is incomplete and includes stale `resolution_note`. `conflicts/stats` omits `by_severity`. | Align `Conflict` and add explicit `ConflictStatsResponse`. |
| Alerts | `apps/web/src/routes_alerts.rs` | `AlertRule` schema is missing `channels`, `action_webhook_headers`, `created_at`, `updated_at`, and models `conditions` incorrectly. `AlertFiring` is missing `rule_id`, `mac`, `source`, and `webhook_response`. `alerts/stats` is completely untyped. | Split request/response schemas for rules, extend `AlertFiring`, add `AlertStatsResponse`. |
| Timeline | `apps/web/src/routes_timeline.rs` | Timeline responses now have explicit schemas in OpenAPI, but the rest of the API still contains many unrelated `additionalProperties: true` components outside this milestone scope. | Done for Milestone 1. Revisit the remaining untyped components outside the five critical groups in a later milestone. |

### Decisions Already Made

- `by_severity` in `conflicts/stats` is part of the supported contract.
- Cursor format remains opaque. Hex encoding is an implementation detail, not a public contract guarantee.
- SSE payloads are excluded from Milestone 1.

### Follow-up After Milestone 1

- Revisit the remaining `additionalProperties: true` components outside the five critical groups.
- Decide whether SSE `LiveEvent` payloads become part of the published OpenAPI contract.
