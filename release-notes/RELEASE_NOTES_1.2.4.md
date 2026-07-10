# Release 1.2.4

- Switched the pinned/default toolchain to Rust `1.97.0` while retaining Rust
  `1.90.0` as the minimum supported version.
- Verified the complete all-features workspace across every supported stable
  compiler from Rust `1.90.0` through Rust `1.97.0`.
- Refreshed compatible dependency locks, including `zeroize 1.9.0`,
  `arrayvec 0.7.8`, `bytes 1.12.1`, `quote 1.0.46`, and `syn 2.0.118`.
- Updated all GitHub workflows to the current `actions/checkout@v7` release.
- Updated fallible secret constructors for Rust 1.97 Clippy without changing
  their clear-on-error RAII behavior.
- Updated all workspace crates and crates.io-facing version references for the
  `1.2.4` patch release.
