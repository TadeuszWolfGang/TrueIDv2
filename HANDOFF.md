# HANDOFF — dashboard startup order

## Phase
POST-REALIZATION — regression reproduced and fixed locally; review and browser
acceptance pending.

## Last action
Codex reproduced the dashboard startup race with the production JavaScript in a
Node VM. Authentication now starts once at DOMContentLoaded, after the remaining
parser-blocking scripts have defined their tab handlers. Initialization errors
emit a fixed console message without exception details or response bodies.

## Current state
Branch: `fix/dashboard-startup-order`.
Base: `c28480cb4896a67d10f8094171e5b07202e65661` (merged PR #39).

Triage: P1 / high availability impact, small effort. A fast `/api/auth/me`
response could reach `switchTab('mappings')` before `mappings.js` defined
`loadMappingsStats`. The resulting ReferenceError was caught and silently
redirected an authenticated user back to login. The affected area is frontend
bootstrap; API contracts, database schema, dependencies and authentication policy
remain unchanged.

Changes:
- `apps/web/assets/js/app.js`: wait for DOMContentLoaded once and report a
  sanitized initialization failure.
- `scripts/test-dashboard-bootstrap.cjs`: exercise the actual utility, API,
  application and mappings scripts with a fast session response and delayed
  dependency loading; retain the unauthorized redirect and sanitize error logs.
- `.github/workflows/security-scan.yml`: run the Node regression suite in SAST.

Validation:
- RED before the production fix: 1 passed, 2 failed as expected (early auth
  request and missing diagnostic).
- GREEN: 3 passed, 0 failed.
- JavaScript syntax, CSP asset policy and `git diff --check`: passed.
- Node provides the test runner and VM; no package installation is required.
- Logs: `../validation-full-20261025/dashboard-bootstrap-red.log` and
  `../validation-full-20261025/dashboard-bootstrap-green.log`.

## Next action
Review the local commit, then validate a fresh HTTPS browser login and dashboard
load in the lab. Confirm `/api/auth/me` succeeds, the mappings tab loads and the
browser remains on the dashboard. Keep deployment and any GitHub push separate
from this local checkpoint.

## Open questions / risks
- The deterministic regression establishes the startup defect. Browser
  acceptance must still confirm the observed lab login loop is resolved.
- The event ordering assumes the existing parser-blocking script tags in
  `index.html`; re-evaluate bootstrap if modules become async or dynamically
  injected.
- Rust and live integration suites are owned by the parallel validation lane;
  this change does not rerun or claim those results.
- The two documented public-key-only dependency exceptions from PR #39 remain
  RUSTSEC-2023-0071 and RUSTSEC-2026-0387.

## READY-TO-RUN COMMAND
Prerequisites:
- [x] Node.js with the built-in `node:test` runner is available.
- [x] Python 3 is available for the existing CSP asset checker.
- [x] The operator authorized the dashboard availability fix and local tests.
- [x] Commands run from the repository root without a server or credentials.

```bash
node --test scripts/test-dashboard-bootstrap.cjs
node --check apps/web/assets/js/app.js
node --check scripts/test-dashboard-bootstrap.cjs
python3 scripts/check-csp-assets.py
git diff --check
```
