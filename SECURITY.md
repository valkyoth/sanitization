# Security Policy

This crate is published as a release candidate on crates.io.

Do not publish exploitable details publicly before a fix is available. Report
security issues privately to the repository owner.

Security-sensitive changes should include:

- tests for default, `alloc`, compatibility `unsafe-wipe`, and all-features
  builds;
- `SAFETY.md` updates for unsafe code;
- `THREAT_MODEL.md` updates for guarantee or scope changes.

## GitHub Security Defaults

Enable GitHub CodeQL default setup in the repository security settings. Keep the
checked-in CI workflow separate from CodeQL so GitHub owns SARIF upload
permissions and there is no competing advanced CodeQL workflow in this repo.
