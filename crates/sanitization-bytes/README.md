# sanitization-bytes

Small `bytes` integration crate for [`sanitization`](https://crates.io/crates/sanitization).

The main `sanitization` crate stays dependency-free. This sister crate provides
`SecretBytesMut`, a clear-on-drop wrapper around `bytes::BytesMut` for projects
that already use `bytes`.

```rust
use sanitization_bytes::SecretBytesMut;

let mut token = SecretBytesMut::from_slice(b"session-token");
token.extend_from_slice(b"-v2");
token.clear_secret();
```
