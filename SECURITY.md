# Security Policy

This crate is published as a stable `1.x` crate on crates.io.

Do not publish exploitable details publicly before a fix is available. Report
security issues privately to the repository owner.

Security-sensitive changes should include:

- tests for default, feature-matrix, target-matrix, WASM compatibility, and
  all-features builds through `scripts/checks.sh`;
- release-codegen inspection for volatile wipe visibility;
- bounded Kani harnesses when `cargo-kani` is installed or via the Kani
  workflow;
- Miri verification on nightly for default, `alloc`, and all-features builds;
- `docs/SAFETY.md` updates for unsafe code;
- `docs/THREAT_MODEL.md` updates for guarantee or scope changes.

## GitHub Security Defaults

Enable GitHub CodeQL default setup in the repository security settings. Keep the
checked-in CI workflow separate from CodeQL so GitHub owns SARIF upload
permissions and there is no competing advanced CodeQL workflow in this repo.
