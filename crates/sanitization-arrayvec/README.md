<p align="center">
  <b>Fixed-capacity ArrayVec secret storage for sanitization.</b><br>
  Clear-on-drop array-backed buffers for projects that already use `arrayvec`.
</p>

<div align="center">
  <a href="https://crates.io/crates/sanitization">sanitization crate</a>
  |
  <a href="https://docs.rs/sanitization-arrayvec">Docs.rs</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/docs/SAFETY.md">Safety</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/sanitization">
    <img src="https://raw.githubusercontent.com/valkyoth/sanitization/main/.github/images/sanitization.webp" alt="sanitization Rust crate overview">
  </a>
</p>

# sanitization-arrayvec

Small `arrayvec` integration crate for [`sanitization`](https://crates.io/crates/sanitization).

The main `sanitization` crate stays dependency-free. This sister crate provides
`SecretArrayVec<T, CAP>`, a clear-on-drop wrapper around `arrayvec::ArrayVec`
for projects that already use `arrayvec`.

```rust
use sanitization::SecretBytes;
use sanitization_arrayvec::SecretArrayVec;

let mut keys = SecretArrayVec::<SecretBytes<32>, 4>::new();
keys.push(SecretBytes::from_array([7; 32])).unwrap();
keys.clear_secret();
```
