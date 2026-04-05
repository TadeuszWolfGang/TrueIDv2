## API Contract Review Checklist

Use this checklist whenever an HTTP payload, query parameter, export format, or SSE shape changes.

### Required

- Update `docs/openapi.yaml` in the same change that modifies the public HTTP contract.
- Update `apps/web/tests/api_v2_tests.rs` contract coverage for the changed payload or parameter.
- If the change affects one of the critical groups, review `docs/OPENAPI_CONTRACT_DRIFT.md`:
  - search
  - conflicts
  - alerts
  - timeline
  - export

### Do Not Leak Implementation Details By Accident

- Keep cursor format documented as opaque unless the exact encoding is intentionally part of the public contract.
- Do not rely on `additionalProperties: true` for critical endpoint groups without a conscious decision.
- If a response field is filtered by one query name and returned under another field name, document both sides explicitly.

### Exports

- If CSV or JSON export shape changes, update:
  - header row expectations
  - `Content-Disposition`
  - `x-trueid-truncated`
  - any field semantics that are easy to misread, such as `user` vs `current_users`

### CI / Guardrails

- If a contract changes, make sure the targeted Schemathesis scope still covers the affected endpoint.
- Keep spec-shape tests green before pushing.

### Current Scope Note

- SSE `LiveEvent` payloads are still outside the published OpenAPI contract.
- If that changes, document the decision and add explicit schema coverage.
