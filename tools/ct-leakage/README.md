# ct-leakage

Unpublished timing/leakage evidence harness for the native `sanitization::ct`
work.

This is not a proof of identical wall-clock timing. It is a dudect-style
statistical smoke test that tries to falsify the crate's narrower claim for a
specific machine, compiler, feature set, and release profile.

The harness uses architecture cycle counters on x86/x86_64 (`rdtsc`) and
AArch64 (`cntvct_el0`) so release evidence has useful resolution. Hardened
VMs, containers, or kernels that trap those instructions are not supported by
this tool; collect evidence on a host that permits the counter or record the
target as missing measured timing evidence.

Run from the repository root:

```bash
cargo run --release --manifest-path tools/ct-leakage/Cargo.toml -- \
  --samples 200000 \
  --inner 500 \
  --output target/ct-leakage-portable.json
```

To test the assembly comparison backend:

```bash
cargo run --release --manifest-path tools/ct-leakage/Cargo.toml --features asm-compare -- \
  --samples 200000 \
  --inner 500 \
  --output target/ct-leakage-asm-compare.json
```

For high-assurance release evidence, collect output on each target machine and
attach it to the release candidate or pentest handoff. Record CPU isolation,
frequency scaling, turbo/boost, SMT, and scheduler-affinity settings separately
if they were controlled by the operator.
