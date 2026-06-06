# Roadmap

This crate is still in release-candidate status. We will use that window to fix
the architecture before `1.0.0`, even if that means making breaking changes
while adoption is still low.

The goal is not to be a drop-in replacement for `zeroize`. The goal is to be a
zero-dependency secret lifecycle crate for new projects: redacted containers,
narrow exposure APIs, constant-time equality for crate-owned secrets, and one
audited memory clearing path.

## Non-Negotiables

- Keep zero external runtime dependencies.
- Keep `no_std` as the default.
- Keep proc macros out of the core crate.
- Prefer small, explicit unsafe internals over broad safe APIs with weaker
  security properties.
- Document limits instead of implying complete process-memory secrecy.

## Pre-1.0 Architecture Direction

### 1. Make Volatile Wiping the Default Clear Path

The current `unsafe-wipe` feature creates two clearing tiers:

- default safe best-effort clearing;
- opt-in volatile clearing.

That split is honest, but it is easy for users to miss. Before `1.0.0`, the
planned direction is to make optimizer-resistant volatile clearing the normal
clear path for secret-owned memory.

Expected shape:

- Move the volatile wipe backend into one small internal module.
- Keep the unsafe code isolated and audited.
- Route byte-slice, heap-capacity, and temporary-copy clearing through that
  backend where applicable.
- Remove or repurpose `unsafe-wipe` so users do not need to opt in for serious
  clearing.

### 2. Simplify `SecretBytes<N>` Storage

`SecretBytes<N>` currently uses atomic byte storage on targets with 8-bit
atomics and falls back on non-atomic storage elsewhere. That is defensible, but
it is surprising and creates target-dependent clearing behavior.

Planned direction:

- Store fixed-size bytes as `[u8; N]`.
- Keep mutation behind `&mut self`.
- Clear with the same internal volatile wipe path used by other byte buffers.
- Re-evaluate `Sync` explicitly during the implementation.

This should make behavior easier to audit and more consistent across embedded
and server targets.

### 3. Keep Secret Lifecycle APIs

The crate should keep focusing on lifecycle management rather than becoming a
large blanket trait implementation crate.

Keep and harden:

- `SecretBytes<N>`;
- `SecretVec`;
- `SecretString`;
- `Secret<T>`;
- closure-based exposure;
- redacted `Debug`;
- dependency-free struct macros.

Avoid before `1.0.0`:

- broad blanket impls for every primitive and container;
- proc-macro derives in the core crate;
- compatibility layers that make the security model harder to explain.

### 4. Add Stronger Verification

Before stable `1.0.0`, add or evaluate:

- Miri runs for the unsafe boundary where target support allows it.
- Assembly or IR inspection notes for the wipe backend.
- Feature-matrix checks after removing or changing `unsafe-wipe`.
- External review focused on unsafe clearing, drop behavior, and API misuse.

Property-based or timing-distribution tests can live outside the published
crate if keeping dev dependencies out of the repository remains preferred.

### 5. Treat Memory Locking as Optional, Not Core

`mlock`, `VirtualLock`, guard pages, and platform-specific memory policies are
important for high-assurance deployments, but they are not portable memory
clearing primitives.

Planned stance:

- Keep them out of the default API.
- Consider a separate feature or companion crate after the core wipe design is
  stable.
- Document clearly that swap, hibernation, crash dumps, and OS policy remain
  outside the core guarantee.

## Stable Release Bar

Do not tag `1.0.0` until:

- the volatile default clearing architecture is implemented;
- `SecretBytes<N>` storage behavior is settled;
- README, SAFETY, SECURITY, and THREAT_MODEL match the final design;
- the local check matrix passes;
- at least one external reviewer has looked at the unsafe boundary and secret
  lifecycle API;
- downstream testing has not found API friction that would require immediate
  breaking changes.
