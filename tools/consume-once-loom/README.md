# Consume-Once Loom Model

This unpublished tool models the atomic claim and cleanup ordering used by
`sanitization::ConsumeOnceSecret<T>`.

Run it with:

```text
cargo test --release --manifest-path tools/consume-once-loom/Cargo.toml
```

The model verifies that two racing consumers cannot both enter the protected
value and that the winning scope completes cleanup before it exits. Panic and
application-error cleanup are tested against the production type in the main
crate's test suite.
