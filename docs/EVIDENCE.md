# Evidence

This document records the current verification evidence for the `sanitization`
crate. It is not a blanket claim of identical wall-clock timing or complete
microarchitectural side-channel resistance.

The same information is also summarized in machine-readable form in
`docs/ct-evidence.json`. The named harness registry is
`docs/verification-harnesses.json`. CP-20 generates dated per-commit artifacts
with exact CI run URLs, rustc versions, target triples, feature sets, and
native/compile-only classification. Final release records must cite the
accepted workflow run and artifact digests.

## Scope

The 2.0 development line strengthens the native `sanitization::ct` module. Its
claim is:

- no secret-dependent control flow inside the provided primitives;
- no secret-dependent memory access inside the provided primitives;
- public length and allocation metadata may affect control flow;
- explicit declassification is required through `ct::Choice::declassify`;
- stronger assembly comparison backends are available only on documented
  targets and features.

The optional `derive` feature also exposes conservative field-wise derives for
`ct::ConstantTimeEq` and `ct::ConditionallySelectable`. Those derives generate
calls to each field's own `ct` trait implementation. They do not compare raw
struct bytes, do not read padding, and reject enums/unions. Their evidence is
compile-time expansion plus integration tests, not a separate hardware timing
claim.

The crate does not claim:

- identical wall-clock timing on every CPU;
- protection against all cache, branch predictor, SMT, transient-execution, or
  power side channels;
- constant-time behavior for arbitrary caller closures;
- browser or Node WASM JIT constant-time behavior;
- protection for copies made outside crate-owned containers.

## Target Tiers

`docs/ct-evidence.json` mirrors these tiers for tooling and release review.

| Target/profile | Tier | Evidence |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu`, release portable/`strict-compare` | Tier A candidate | Native tests, path-specific codegen, relative performance, and multi-seed leakage artifacts |
| `aarch64-unknown-linux-gnu`, release portable/`strict-compare` | Tier B native | Native tests, AArch64 codegen, relative performance, and multi-seed leakage artifacts |
| `x86_64-pc-windows-msvc` | Tier B native | Native feature tests, x86_64 codegen, and relative performance; no timing claim |
| `aarch64-apple-darwin` | Tier B native | Native tests, AArch64 codegen, relative performance, and multi-seed leakage artifacts |
| BSD, Android, iOS, embedded ARM/RISC-V | Tier B or B/C compile-only | Cross-compilation manifests; no native runtime or timing claim |
| WASM `wasm32-*` | Tier C | API/build compatibility and documented reduced volatile/memory-lock guarantees; no strong JIT timing claim |

Tier A candidate means the repository has automated evidence collection, but a
stable release must still preserve the exact rustc version, target triple,
feature set, accepted CI run, and artifact digests that produced the evidence.

## Automated Checks

Run the local release-sensitive matrix:

```bash
scripts/checks.sh
```

This script runs formatting, feature-matrix tests, examples, clippy, target
checks for installed targets, release codegen checks, optional Kani proofs,
documentation with warnings denied, and package listing.
The derive test target covers `SecureSanitize`, `SecureSanitizeOnDrop`, and the
native `ct` struct derives.

Run derive rejection checks directly:

```bash
scripts/verify-derive-failures.sh
```

This builds temporary downstream crates and asserts that native `ct` enum
derives, skipped `ConditionallySelectable` fields, enum sanitization without
inactive-variant acknowledgement, unreasoned skips, malformed or duplicate
helper options, unions, and missing generic drop bounds remain compile
failures.

Run Miri separately when a nightly toolchain with Miri is installed:

```bash
scripts/verify-miri.sh
```

The Miri script covers both the core crate's feature configurations and the
`sanitization-arrayvec` complete inline-backing wipe.

Miri verifies supported Rust memory-safety paths. It does not execute the native
OS mapping, locking, protection, dump/fork-policy, or guard-page syscalls, which
are compiled out under `cfg(miri)`. Native Linux tests cover the new locked and
guarded UTF-8 wrappers; other supported platforms require their own native
evidence.

Run Kani proofs directly when `cargo-kani` is installed:

```bash
scripts/verify-kani.sh
```

Latest local run while preparing the 2.0 CP-20 evidence slice:

- Kani version: `Kani Rust Verifier 0.67.0`;
- result: all configured `scripts/verify-kani.sh` harnesses passed for
  `no-default-features`, `alloc`, and `std` runs.

Run release codegen checks directly:

```bash
scripts/verify-codegen.sh
scripts/verify-codegen-matrix.sh
```

The first script checks the canonical backend and current host architecture.
The matrix script validates exact downstream probe bodies under optimization
2/3/s/z, Thin/Fat LTO, one/many codegen units, and unwind/abort panic modes.
See `docs/VERIFICATION_TOOLING.md`.

Collect and validate repeated native leakage evidence:

```bash
scripts/collect-leakage-evidence.py --output-dir target/cp20/leakage
scripts/verify-target-evidence.py \
  --leakage-summary target/cp20/leakage/summary.json
```

Run the relative performance regression baseline:

```bash
cargo run --release --manifest-path tools/performance-baseline/Cargo.toml -- \
  --output target/cp20/performance.json
scripts/verify-target-evidence.py \
  --performance target/cp20/performance.json
```

Run lifecycle allocation quarantine and fault-model checks:

```bash
cargo test --manifest-path tools/lifecycle-probes/Cargo.toml -- --test-threads=1
```

Run fail-closed verification fixtures and validate the harness registry:

```bash
scripts/test-verification-fail-closed.py
scripts/verify-verification-harnesses.py
```

Validate the machine-readable evidence draft directly:

```bash
scripts/verify-evidence.py
```

This verifies that `docs/ct-evidence.json` has the expected schema and that its
listed Kani proof names match the proof harnesses in `src/owned.rs`.

Generate local release-evidence metadata for reviewer or release notes:

```bash
scripts/evidence-report.py
```

This records the current commit, dirty state, rustc host/version, installed
targets, and optional Kani/Miri tool availability. It does not replace the
checks above; it captures the environment in which they were run.

## Kani Harnesses

The crate includes bounded proof harnesses behind `#[cfg(kani)]`. They are not
compiled into normal crate builds.

Current proof scope:

- volatile byte clearing zeroes a fixed buffer;
- `SecretBytes<N>::secure_clear` erases visible fixed-size contents;
- legacy `constant_time_eq` matches byte equality for bounded fixed arrays;
- public length mismatch is rejected;
- `ct::Choice` normalizes to `0` or `1`;
- `ct::Choice` boolean algebra matches public normalized bit behavior;
- `ct::eq_fixed` matches byte equality for bounded fixed arrays;
- `ct::cmp_fixed` matches lexicographic ordering for bounded fixed arrays;
- `ct::ConstantTimeOrd` matches Rust ordering for bounded signed and unsigned
  primitive integer harnesses;
- `ct::eq_public_len` rejects public length mismatch;
- `ct::conditional_copy` matches the public interpretation of the `Choice`;
- `ct::conditional_swap` matches the public interpretation of the `Choice`;
- `ct::oblivious_lookup` matches public-index lookup or fallback behavior for
  the bounded harness;
- `ct::select_slice` matches the public interpretation of the `Choice`;
- `ct::CtOption` unwrap/combine/select behavior matches the public
  interpretation of hidden presence bits;
- `ct::CtResult` unwrap/map/select behavior matches the public interpretation
  of hidden success bits;
- secret CT scalar, option, and result ownership tests cover clear-on-drop,
  selected-value transfer, dummy/unselected cleanup, mapping panic unwind,
  sanitizer panic without retry, independent selection, and zero-sized values;
- allocation growth arithmetic does not under-allocate for the bounded harness.
- complete fixed-size replacement exposes exactly the committed replacement.

These proofs are functional correctness checks over bounded inputs. They do not
prove hardware timing, compiler backend behavior, or absence of every
microarchitectural leak. Kani currently treats these harnesses as sequential
and does not model real concurrent scheduling, atomic interleavings under
contention, or concurrent kernel behavior. This release adds no new
concurrency primitives or unsafe trait implementations.

## Release Codegen Checks

`scripts/verify-codegen.sh` emits release LLVM IR and assembly for the
`sanitization` library with all features enabled and validates exact exported
downstream probe bodies.

The script checks:

- the volatile wipe function is present in LLVM IR;
- volatile byte-zero stores are present in LLVM IR;
- removed best-effort compatibility aliases remain absent;
- native `ct` slice helper symbols are present in LLVM IR;
- the native `ct` optimizer barrier and mask-generation patterns remain present
  in LLVM IR;
- no `memcmp` or `bcmp` call is emitted in the checked release IR or assembly;
- on x86_64 hosts, the assembly comparison symbol and byte-load instructions
  are present;
- on x86_64 hosts, CPUID-gated cache-flush instructions, completion fences,
  and SSE/AVX register-scrub instructions are present;
- on AArch64 hosts, the claimed V0-V7 and V16-V31 register-zeroing
  instructions are present.
- the downstream probes cover fixed, dynamic, mapped, pooled, sealed,
  derive-generated, tuple, companion, and CT paths.

This is a regression check, not a formal proof. Manual review should still be
performed for release candidates that change unsafe code, comparison backends,
or compiler/toolchain versions.

## Documentation Evidence

Permanent documentation that constrains the claims:

- `README.md`: API examples, feature table, target behavior, release checks;
- `docs/GUARANTEES.md`: the positive claims for secret ownership, clearing,
  locked/guarded storage, and native data-oblivious primitives;
- `docs/NON_GUARANTEES.md`: timing, runtime, platform, caller-code, serialization,
  and interop limits;
- `docs/BARRIERS.md`: volatile wipe, optimizer, assembly, cache, register, and
  release-evidence barrier strategy;
- `docs/TARGETS.md`: human-readable target tiers and feature availability matrix;
- `docs/LEAKAGE_TESTS.md`: expectations, commands, and metadata requirements for
  dudect-style timing/leakage harnesses;
- `docs/THREAT_MODEL.md`: guarantees, residual risks, WASM limits, canary limits;
- `docs/SAFETY.md`: unsafe boundaries and invariants;
- `docs/ROADMAP.md`: 1.2 target tiers and release checkpoint gates.

## Open Evidence Gaps

- CP-20 workflow artifacts are per commit and expire. CP-22/CP-23 must preserve
  the accepted run URLs and artifact digests in the final release record.
- Hosted-runner leakage results do not control affinity, frequency scaling,
  turbo/boost, or SMT unless the report explicitly records otherwise. They are
  repeated falsification attempts, not proof.
- Windows has native functional, codegen, and performance evidence but no
  target-specific timing claim.
- BSD, Android, iOS, embedded, and WASM results are compile-only; they must not
  be described as native runtime evidence.
- WASM JIT behavior remains a documented non-guarantee.
