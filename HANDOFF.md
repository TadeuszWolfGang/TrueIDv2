# HANDOFF — PR #39 dependency security fixes

## Phase
POST-REALIZATION — code review and local validation complete; verify PR checks.

## Last action
Codex applied five targeted patch updates, reviewed the public-key-only
crypto-bigint exception, made HS256 explicit, and added workspace test execution
to CI. Independent review found no blocking issue. The operator authorized
completing the fixes and updating this PR.

## Current state
Branch: `dependabot/cargo/rust-dependencies-5bc6568c9f`.
Starting commit: `4dd5de558a010839d89f04526c53a1a129fd8a94`.
The existing PR updates Rustls and Tokio. This repair additionally updates
quinn-proto to 0.11.18, ctutils to 0.4.4, rustls-webpki to 0.103.16, and
both webpki root packages to 1.0.10. RSA update proposals are enabled again.

Local validation:
- `cargo test --workspace --locked`: 414 passed, 16 intentionally ignored.
- The 16 ignored auth/RBAC tests were then run explicitly against a disposable
  loopback-only development instance: 16 passed.
- Rustfmt, security-focused Clippy, 5 ZAP policy tests, CSP policy, shell syntax,
  and `git diff --check`: passed. Clippy still reports pre-existing warnings.
- Current RustSec database: 21d909e4c8bd4e14c7aea58bf980c881a0053ab1.
- `cargo audit` and `cargo deny check advisories`: passed under the documented
  policy. Two public-key-only exceptions remain: RUSTSEC-2023-0071 (RSA) and
  RUSTSEC-2026-0387 (crypto-bigint); neither is a claim of removing that crate.
- Without exceptions, only those two advisories remain.
- Native logs are in `../validation/`; hosted scan results belong in PR #39.

## Next action
Push the repair commit to the existing PR branch without rewriting history.
Verify security-scan, CodeQL, Windows agent smoke and glibc compatibility for
the resulting head SHA; investigate any failure before considering it complete.
Update the PR description with actual results and the two explicit exceptions.

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
- [x] Network access for registry packages and the RustSec advisory database.
- [x] cargo-audit installed; cargo-deny 0.20.2 installed in `../audit-tools/bin`.

```bash
cargo update -p quinn-proto --precise 0.11.18
cargo update -p ctutils --precise 0.4.4
cargo update -p rustls-webpki --precise 0.103.16
cargo update -p webpki-roots --precise 1.0.10
cargo update -p webpki-root-certs --precise 1.0.10
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D clippy::correctness -D clippy::suspicious -D clippy::perf
cargo audit --db ../advisory-db --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2026-0387
PATH="../audit-tools/bin:$PATH" cargo deny check advisories
python3 -m unittest scripts/test_check_zap_report.py
python3 scripts/check-csp-assets.py
```

Capture logs outside the checkout in `../validation/`. Record final results and
remaining exceptions in this handoff and in the PR description.
