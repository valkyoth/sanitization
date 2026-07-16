# Verification Tooling

CP-19 adds evidence machinery. It does not promote target tiers or replace an
independent review. CP-20 uses these harnesses to collect dated target evidence.

The machine-readable registry is `docs/verification-harnesses.json`.

## Path-Specific Codegen

`tools/direct-exposure-codegen` exports named downstream functions for:

- direct and copied fixed-secret exposure;
- `SecretBoxBytes`, `SecretVec`, and `SecretString` clearing;
- locked, guarded, pooled, and sealed clearing;
- derive-generated struct and enum cleanup;
- tuple and `sanitization-arrayvec` cleanup;
- CT equality, ordering, conditional copy/swap, and oblivious lookup.

`scripts/verify-codegen-artifact.py` extracts each exact function body from
LLVM IR. It does not accept a matching symbol elsewhere in the artifact as
evidence for the public path.

`scripts/verify-codegen-matrix.sh` covers:

| Variant | Optimization | LTO | Codegen units | Panic |
| --- | --- | --- | --- | --- |
| `opt2-many-unwind` | 2 | off | 16 | unwind |
| `opt3-one-unwind` | 3 | off | 1 | unwind |
| `opts-thin-unwind` | s | Thin | 1 | unwind |
| `optz-fat-abort` | z | Fat | 1 | abort |

Compiler and target expansion belongs to CP-20 because those runs need dated
runner metadata.

## Allocation Quarantine And Fault Models

`tools/lifecycle-probes` installs a test-only allocator that delays
deallocation. This keeps released blocks allocated and readable so tests can
search them for full secret markers after `SecretVec` growth and drop.

This allocator deliberately leaks quarantined test allocations. It must never
be used in production and is excluded from the publishable workspace.

The same tool enumerates required setup failures for mapping, dump exclusion,
fork policy, locking, protection, random generation, and cache policy. This is
a deterministic state-transition model. It verifies rollback expectations but
does not replace native syscall-failure tests.

## Fuzzing

The unpublished `fuzz` package contains:

- `owned_lifecycle`: growth, replacement, bounded serde input, UTF-8
  conversion, and acknowledged enum transitions;
- `ct_primitives`: equality, ordering, conditional copy/swap, and oblivious
  lookup functional stress.

CI runs short smoke campaigns. Longer, seeded campaigns and retained corpora
belong to release evidence rather than ordinary unit testing.

## Sanitizers

`.github/workflows/security-evidence.yml` runs x86_64 Linux AddressSanitizer and
ThreadSanitizer jobs through `scripts/verify-sanitizer.sh`.

Rust nightly currently exposes ASan and TSan modes used here. The project does
not claim a general Rust UBSan job: rustc does not currently provide a
corresponding supported `-Zsanitizer=undefined` workflow. Miri, Kani, native
tests, and explicit arithmetic checks cover different portions of that space,
but are not described as UBSan.

Sanitizer success is evidence only for the compiled target and feature set. It
does not exercise unsupported targets or prove syscall semantics.

## Formal And Concurrency Checks

Miri additionally covers `sanitization-bytes` and the crypto companion paths.
Kani includes complete fixed-secret replacement in addition to clearing,
comparison, capacity, and protection-report properties.

The Loom model covers:

- competing consume-once accessors;
- pool allocation, clearing, generation, and reuse;
- retirement ordering for modeled atomic protection state.

Kani is not concurrency evidence. Loom models atomics but not kernel behavior.

## Core-Dump Marker Probe

`scripts/verify-core-dump-probe.sh` is opt-in because hosted CI commonly pipes
or suppresses core dumps. On a permitted Linux runner with a relative
`core_pattern`, set:

```bash
SANITIZATION_RUN_CORE_DUMP_PROBE=1 scripts/verify-core-dump-probe.sh
```

The probe derives a process-specific marker directly into locked storage,
aborts, and searches the resulting core file. A missing core file is a failure
when the probe was explicitly requested.

## Fail-Closed Tests

`scripts/test-verification-fail-closed.py` seeds malformed evidence and an
incomplete LLVM artifact. Both validators must reject those fixtures.

`scripts/verify-verification-harnesses.py` also ensures:

- harness names are unique;
- referenced scripts exist;
- every tool and fuzz package is `publish = false`;
- tooling has not entered the publishable workspace.
