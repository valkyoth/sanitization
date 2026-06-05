# Contributing

Security-sensitive changes should keep the default crate free of unsafe code.

Before submitting changes, run:

```bash
bash scripts/checks.sh
```

Changes to `unsafe_wipe` must update `SAFETY.md`. Changes that alter guarantees,
limits, or supported attacker models must update `THREAT_MODEL.md`.
