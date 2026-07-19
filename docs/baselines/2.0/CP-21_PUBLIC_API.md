# CP-21 Public API Candidate

`cp21-public-api.json` freezes the source-level API candidate after downstream
migration work. It records workspace package metadata, feature maps, normal
dependencies, package include lists, public source declarations, and hashes of
every publishable crate manifest and Rust source file.

The recorded workspace package version remains `1.2.5` by design. The 2.0
development checkpoints preserve release metadata until CP-23 performs the
reviewed version and publication transition.

Regenerate after an accepted CP-21 API change:

```bash
scripts/capture-2.0-api.py
```

Verify it without modifying the repository:

```bash
scripts/capture-2.0-api.py --check
```

This snapshot is deliberately not presented as a semantic Rust API model. It
can detect any source or manifest change and gives CP-22 a fixed candidate to
compare, but line-based declaration collection cannot fully understand
re-exports, cfg evaluation, macro expansion, or generic compatibility. CP-22
must run `cargo-semver-checks` and rustdoc/public-API comparison before freeze.
