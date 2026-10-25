# HANDOFF — PR #39 dependency security fixes

## Phase
PLANNING — maintenance of the existing dependency update.

## Last action
Codex inspected PR #39, the dependency graph, current RustSec findings, and CI.
The operator authorized completing the fixes and updating this PR.

## Current state
Branch: `dependabot/cargo/rust-dependencies-5bc6568c9f`.
Starting commit: `4dd5de558a010839d89f04526c53a1a129fd8a94`.
The existing PR already updates Rustls and Tokio. Remaining compatible fixes
cover QUIC, certificate validation/root stores, and constant-time utilities.
The `crypto-bigint` advisory requires a separate exposure assessment because
its parent elliptic-curve dependency cannot accept the patched major version.

## Next action
Apply the targeted updates below. Confirm the cryptographic call sites before
choosing a narrowly documented exception or a compatible dependency change.
Add execution of workspace tests to CI, which currently only compiles them.

## Open questions / risks
- OIDC signature verification must continue to support RS256, ES256 and EdDSA.
- A passing advisory policy must disclose every accepted exception.
- Local Docker is unavailable; container and DAST validation will run in Actions.
- Do not merge the PR; update it and verify its checks.

## READY-TO-RUN COMMAND
Prerequisites:
- [x] PR branch checked out with no pre-existing local modifications.
- [x] Rust 1.95.0 is installed.
- [x] Operator authorized the existing dependency-fix plan.
- [ ] Network access for registry packages and the RustSec advisory database.

```bash
cargo update -p quinn-proto --precise 0.11.18
cargo update -p ctutils --precise 0.4.4
cargo update -p rustls-webpki --precise 0.103.16
cargo update -p webpki-roots --precise 1.0.10
cargo update -p webpki-root-certs --precise 1.0.10
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D clippy::correctness -D clippy::suspicious -D clippy::perf
cargo audit
cargo deny check advisories
python3 -m unittest scripts/test_check_zap_report.py
python3 scripts/check-csp-assets.py
```

Capture logs outside the checkout in `../validation/`. Record final results and
remaining exceptions in this handoff and in the PR description.
