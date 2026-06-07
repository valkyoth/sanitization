# Contributing

Security-sensitive changes should keep unsafe code isolated behind the crate
root `#![deny(unsafe_code)]` policy and documented in `SAFETY.md`.

Before submitting changes, run:

```bash
bash scripts/checks.sh
```

Changes to `wipe`, `unsafe_wipe`, platform memory backends, comparison
assembly, cache flushing, or guarded mappings must update `SAFETY.md`. Changes
that alter guarantees, limits, or supported attacker models must update
`THREAT_MODEL.md`.
