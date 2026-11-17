# sanitization 2.2.0

The secrecy adapter adds `SecretString::try_from_string_bounded::<MAX>`
for owned strings and `try_from_str_bounded::<MAX>` for borrowed text.
Both check the public UTF-8 byte length before reserving final storage.
The owned conversion wipes its source allocation on success and error.
Serde uses these constructors with its existing 1 MiB limit.

This release also includes the maintenance updates prepared after 2.1.1.
The default development toolchain and upper end of the compatibility matrix
are Rust `1.100.0`. The minimum supported compiler is Rust `1.90.0`.

CI bootstraps rustup `1.29.3` on Linux and macOS when needed. Dependency and
build jobs use cargo-audit `0.23.0`, cargo-deny `0.21.0`, and the commit-pinned
Swatinem/rust-cache `v2.9.3`. The workspace, fuzz targets, and standalone
tools use refreshed lockfiles, including `syn 3.0.10` for derive macros,
`zeroize 1.9.2` for interoperability, and `loom 0.7.3` for concurrency tests.
