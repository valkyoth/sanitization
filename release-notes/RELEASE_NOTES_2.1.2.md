# sanitization 2.1.2

This maintenance release updates the six crates in the sanitization workspace.
The default development toolchain and upper end of the compatibility matrix
are Rust `1.100.0`. The minimum supported compiler is Rust `1.90.0`.

CI bootstraps rustup `1.29.3` on Linux and macOS when needed. Dependency and
build jobs use cargo-audit `0.23.0`, cargo-deny `0.21.0`, and the commit-pinned
Swatinem/rust-cache `v2.9.3`. The workspace, fuzz targets, and standalone
tools use refreshed lockfiles, including `syn 3.0.10` for derive macros,
`zeroize 1.9.2` for interoperability, and `loom 0.7.3` for concurrency tests.
