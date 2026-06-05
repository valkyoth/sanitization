# Security Policy

This crate is pre-release and not published yet.

Do not publish exploitable details publicly before a fix is available. For now,
report issues privately to the repository owner once the upstream repository is
created.

Security-sensitive changes should include:

- tests for default, `alloc`, `unsafe-wipe`, and all-features builds;
- `SAFETY.md` updates for unsafe code;
- `THREAT_MODEL.md` updates for guarantee or scope changes.

## GitHub Security Defaults

Enable GitHub CodeQL default setup in the repository security settings. Keep the
checked-in CI workflow separate from CodeQL so GitHub owns SARIF upload
permissions and there is no competing advanced CodeQL workflow in this repo.
