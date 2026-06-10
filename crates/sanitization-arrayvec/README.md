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
