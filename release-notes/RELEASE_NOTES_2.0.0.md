# Release 2.0.0

Version 2.0.0 is a security-model release. It preserves the dependency-free,
`no_std` default and canonical volatile wipe backend while making generic
storage, exposure, data-oblivious control state, derive behavior, and native
protection outcomes more explicit and fail-closed.

## Ownership And Exposure

- Renamed checked mapped-container operations to `try_*`, removed redundant
  `*_checked` aliases, and kept `*_or_panic` only for deliberate fail-stop
  application policy. Fallible generator callbacks use explicit
  `try_replace_from_fallible_*` names.
- Added `StableSharedSecretStorage` and `StableMutableSecretStorage` contracts.
  Generic `Secret<T>` exposure now requires an explicit storage-stability
  attestation covering safe shared access, interior mutation, mutable access,
  callbacks, guards, trait methods, and destruction.
- Fixed-size containers now expose their owned storage directly. Core APIs that
  create temporary copies are reason-bearing `export_*` boundaries so the
  extra secret lifetime is visible and searchable.
- Added `SecretBoxBytes` for fixed-allocation runtime-length secret bytes that
  never grow, reallocate, or expose their private backing allocation.
- Renamed `ReadOnceSecret<T>` to `ConsumeOnceSecret<T>`. Its single scoped
  shared access is claimed atomically and cleared on normal return, returned
  errors, and panic unwinding.

## Data-Oblivious State

- Made `Choice`, masks, and `CtOrdering` declassification reason-bearing and
  removed ordinary equality or raw extraction paths that bypassed the review
  boundary.
- Replaced the generic copyable CT marker with redacted, non-`Copy`,
  clear-on-drop `SecretIndex` and `SecretScalar<T>` owners.
- Added `PublicValue<T>`, `SecretValue<T>`, `SecretCtOption`, and
  `SecretCtResult` so dummy, unselected, mapped, and panic-path secret values
  receive explicit cleanup.
- Renamed `strict-ct` to `strict-compare` to state its actual scope:
  assembly-backed equal-length byte equality on reviewed native targets.
- Expanded Kani, codegen, leakage, panic-unwind, ownership-transition, and
  zero-sized/drop-bearing test coverage for the native CT API.

## Derives And Companion Crates

- Rejected enum sanitization derives because generated safe code cannot clear
  inactive variant storage. Reviewed manual enums must use `secure_replace`
  before every transition; stable-layout struct wrappers are preferred.
- Required every skipped derive field to include a non-empty reason and
  rejected duplicate, malformed, empty, or misplaced helper attributes.
- Kept constant-time derives struct-only and field-wise; enums, unions, and
  unsafe selection skips remain compile failures.
- Corrected `sanitization-arrayvec` so live values are sanitized and dropped
  before the complete inline backing region, including historical spare bytes,
  is volatile-cleared.
- Added secure ArrayVec `pop` and `truncate` handling with valid destructor
  ordering and stale-slot cleanup.

## Wiping And Native Hardening

- Consolidated clearing behind the canonical safe `sanitization::wipe` API and
  private sealed `wipe_backend`; removed misleading best-effort and
  `unsafe-wipe` compatibility surfaces.
- Added `wipe::WipeOnDrop<T>` for the audited built-in plain-data set. Public
  downstream representation-erasure implementations remain intentionally
  unsupported.
- Added `ProtectionRequest`, required/preferred policy, structured
  `ProtectionReport` outcomes, and partial setup reports so compiled features
  are not confused with achieved runtime protection.
- Made fork inheritance, dump exclusion, memory locking, guard pages, and
  canary integrity explicit per-container policy outcomes.
- Hardened `SecretPool` with checked fixed-layout accounting, generation-bound
  canaries, failure quarantine, and efficiency reporting.
- Added opt-in `SealedSecretBytes<N>` with guard pages, fallible page sealing,
  poisoning/retirement after unsafe transition failures, and multi-page fault
  recovery tests. This remains a reviewed optional facility with documented
  platform limits, not an infallible secrecy guarantee.
- Reworked cache eviction and SIMD/vector scrubbing to report supported,
  executed, limited, and unsupported outcomes instead of implying universal
  hardware coverage.
- Added named hardened-native, guarded-native, and Linux hardening profiles;
  runtime requests and reports remain authoritative over feature selection.

## Verification And Release Evidence

- Added path-specific LLVM IR and assembly checks across optimization, LTO,
  panic, and codegen-unit profiles.
- Added lifecycle allocation-quarantine probes, Loom concurrency models,
  sanitizer jobs, fail-closed negative fixtures, Miri/Kani coverage, and
  downstream migration builds.
- Added repeated multi-seed dudect-style leakage runs and relative performance
  baselines for x86_64 Linux, AArch64 Linux, and Apple Silicon.
- Recorded native and compile-only target tiers, exact accepted workflow URLs,
  and GitHub artifact SHA-256 digests in the 2.0 release evidence record.
- Added semantic public-API snapshots and semver review for all five
  publishable crates, freezing the CP-21 API before final release metadata.
- Added complete migration, storage-contract, protection-report, scope,
  guarantees, non-guarantees, target, evidence, and verification-tooling docs.
- Updated package archive validation and publication tooling for all five
  `2.0.0` crates in dependency order.
- Updated dependency-audit detection to use Cargo's subcommand registry and
  scan every committed workspace, fuzz, and tooling lockfile.
- Added a CI declassification-reason lint with fail-closed fixtures. Consumer
  call sites must use meaningful direct literals rather than dynamic or
  placeholder labels; human review remains authoritative.
- Sealed `wipe::Wipe` to its audited built-in implementations and added a
  downstream compile-fail guard against no-op `WipeOnDrop<T>` implementations.
- Added concise checked-error composition through `SecretIntegrityResult`,
  `SecretIntegrityResultExt`, operation-error mapping helpers, and one-shot
  requested-protection report validation.
- Documented recommended library propagation, mapped text, fail-stop, and
  application error-boundary patterns without collapsing distinct failures
  into one global error enum.
- Added `AllowlistedSecret<T, P>` and a rationale-bearing policy macro so
  closed deployments can centrally approve exact storage types while retaining
  the independent shared/mutable stability bounds.
- Kept storage contracts deliberately non-derived: field inspection cannot
  prove method behavior, interior mutation, guard cleanup, callbacks, or
  deferred allocation release.

## Migration

This release contains intentional source-breaking changes. Read
[`docs/MIGRATION_2.0.md`](https://github.com/valkyoth/sanitization/blob/main/docs/MIGRATION_2.0.md)
before upgrading from `1.2.5`. The migration guide covers generic storage
bounds, direct versus copied exposure, CT declassification, derives, wipe API
renames, ArrayVec behavior, consume-once ownership, native protection policy,
feature profiles, and deferred experimental facilities.
