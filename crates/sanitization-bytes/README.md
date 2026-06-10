# sanitization-bytes

Small `bytes` integration crate for [`sanitization`](https://crates.io/crates/sanitization).

The main `sanitization` crate stays dependency-free. This sister crate provides
`SecretBytesMut`, a clear-on-drop wrapper around `bytes::BytesMut` for projects
that already use `bytes`.

```rust
use sanitization_bytes::SecretBytesMut;

let mut token = SecretBytesMut::with_capacity(16);
token.extend_from_slice(b"session-token").unwrap();
token.extend_from_slice(b"-v2").unwrap();
token.clear_secret();
```

`SecretBytesMut` treats capacity as fixed after construction. Appending beyond
capacity returns an error instead of reallocating, because implicit growth would
free an old allocation that still contains secret bytes.
