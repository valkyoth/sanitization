# sanitization 2.1.1

This maintenance release updates the project toolchain and dependency set
without changing the minimum supported Rust version or the documented 2.1 API.

## Toolchain And Dependencies

- Release development now uses Rust `1.99.1`.
- Rust `1.90.0` remains the MSRV, and the compatibility matrix now checks every
  stable release through `1.99.1`.
- SHA-2 is updated to `0.11.1` and `syn` to `3.0.9`.
- Workspace, fuzzing, and standalone-tool lockfiles are refreshed to current
  compatible releases, including `zeroize 1.9.1` and `serde_json 1.0.154`.

## CI And Release Tooling

- `actions/upload-artifact` is updated to the SHA-pinned `v7.0.2` release.
- The current SHA pins for `actions/checkout v7.0.1`,
  `Swatinem/rust-cache v2.9.2`, and `kani-github-action v1.1` are retained.
- Kani jobs now request Kani `0.68.0` explicitly rather than following a
  moving latest-version default.
- README examples, package verification metadata, API snapshots, and release
  commands now target `2.1.1`.
- Redundant homepage metadata is removed so Cargo `1.99.1` and nightly release
  tooling remain warning-free; canonical repository links are unchanged.

## Coordinated Crates

All six publishable workspace crates are released together at `2.1.1`:

- `sanitization-derive`
- `sanitization`
- `sanitization-arrayvec`
- `sanitization-bytes`
- `sanitization-crypto-interop`
- `sanitization-secrecy`

The core crate continues to exact-pin the matching derive release because the
generated code and runtime traits form one versioned interface.
