# sanitization-derive

Optional derive macros for the `sanitization` crate.

Use through the main crate:

```toml
sanitization = { version = "1.0.0-rc.6", features = ["derive"] }
```

The derive crate only generates calls to `sanitization::SecureSanitize`; it does
not implement memory wiping itself.
