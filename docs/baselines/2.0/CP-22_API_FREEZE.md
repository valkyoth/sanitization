# CP-22 API Freeze Review

CP-22 freezes the semantic public API accepted at CP-21 and records the
intentional compatibility boundary from `v1.2.5` to `2.0.0`.

## Reviewed Candidate

- 1.x baseline: `v1.2.5` (`d41204551c840e086b2a7d53c83514633e604e82`)
- 2.0 candidate: CP-21 (`082d1e19fb5473e565b31c24e1c743f4c88d7470`)
- compiler: Rust 1.97.1
- `cargo-semver-checks`: 0.49.0
- `cargo-public-api`: 0.52.0

The CP-22 dependency-only update pins `syn` 2.0.119 for the derive crate. It
does not alter generated or runtime API behavior.

## Semver Results

Every normal library target was checked against `v1.2.5` under both an assumed
major release and an assumed minor release.

| Package | Major comparison | Minor comparison |
| --- | --- | --- |
| `sanitization` | Pass | Expected failure: 11 major lint classes |
| `sanitization-arrayvec` | Pass | Expected failure: `inherent_method_const_removed` |
| `sanitization-bytes` | Pass | Pass |
| `sanitization-crypto-interop` | Pass | Pass |
| `sanitization-derive` | Not applicable: proc-macro-only target | Not applicable: proc-macro-only target |

The core break classes are recorded in `cp22-semver-review.json`. Each class
has an explicit destination in `docs/MIGRATION_2.0.md` and a machine-readable
entry in `docs/migration-2.0.json`.

The derive crate is verified by its rustdoc-derived macro snapshot, compile-pass
tests, and compile-fail tests. `cargo-semver-checks` intentionally skips
proc-macro-only targets because they do not expose a normal library API.

## Semantic API Freeze

`scripts/capture-2.0-public-api.py` captures rustdoc-derived API output for all
five publishable packages. The committed files under `public-api/` are the
CP-21 semantic baseline. Normal verification compares the current tree to
those files and fails on additions, removals, or signature changes.

The snapshots deliberately include feature-gated APIs by using
`--all-features`. The older source-level CP-21 inventory remains as a second,
independent declaration check.

## Reproduction

```bash
scripts/verify-2.0-api-freeze.py --run-semver-tools
scripts/capture-2.0-public-api.py
scripts/verify-migration-2.0.py
scripts/verify-derive-failures.sh
```

The exact per-package semver commands and accepted results are stored in
`cp22-semver-review.json`.

## Scope Disposition

`docs/SCOPE_2.0.0.md` identifies the concepts frozen into 2.0 and the additive
ideas deferred beyond 2.0. No deferred item is required to satisfy a 2.0
security guarantee. New major concepts remain prohibited after CP-21; only
finding remediation, documentation corrections, tests, and release metadata
may change before the final release.

## Independent Close-Out

This document records the reproducible API and semver portion of CP-22. The
independent CP-22 review covered the full CP-00 through CP-22 implementation
range and was accepted with no open finding contradicting the documented
guarantees. CP-23 may change only coordinated release metadata,
documentation, package validation, and publication tooling.
