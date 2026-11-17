# sanitization 2.2.0

The secrecy adapter adds `SecretString::try_from_string_bounded::<MAX>`
for owned strings and `try_from_str_bounded::<MAX>` for borrowed text.
Both check the public UTF-8 byte length before reserving final storage.
The owned conversion wipes its source allocation on success and error.
`try_from_utf8_bounded::<MAX>` also accepts owned byte vectors and wipes
their full capacity even on invalid UTF-8. The shared allocation errors
now describe bytes rather than calling boxed text a slice.
Serde uses these constructors with its existing 1 MiB default, or a
caller-selected visitor limit through `SecretStringSeed::<MAX>`. This does
not bound parser-owned input buffers or enable plaintext serialization.

This release also includes the maintenance updates prepared after 2.1.1.
The default development toolchain and upper end of the compatibility matrix
are Rust `1.100.0`. The minimum supported compiler is Rust `1.90.0`.

CI bootstraps rustup `1.29.3` on Linux and macOS when needed. Dependency and
build jobs use cargo-audit `0.23.0`, cargo-deny `0.21.0`, and the commit-pinned
Swatinem/rust-cache `v2.9.3`. The workspace, fuzz targets, and standalone
tools use refreshed lockfiles, including `syn 3.0.10` for derive macros,
`zeroize 1.9.2` for interoperability, and `loom 0.7.3` for concurrency tests.
