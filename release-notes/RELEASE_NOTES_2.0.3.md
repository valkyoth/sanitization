# sanitization 2.0.3

This patch release closes the policy-ordering gap for runtime-length secret
decoders and generators.

## Protection before materialization

`LockedSecretVec` and `GuardedSecretVec` now provide policy-aware in-place
constructors for exact-length and capacity-bounded output. Every control marked
`Required` is established before the fill callback runs. This lets decoders,
RNGs, KDFs, and protocol implementations write directly into final protected
storage without first materializing plaintext under a degraded mapping.

The callback receives exactly the requested public capacity. This remains true
when guard-page allocation rounds its internal writable payload to a larger
page boundary. Success clears the entire unreported tail; callback failure and
excessive reported lengths clear the mapping before returning.

`LockedSecretString` and `GuardedSecretString` expose matching constructors.
They validate the initialized prefix as UTF-8 without reallocating and clear
invalid payloads before returning an error.

## Typed integrity boundary

`ProtectedSecretFillError<E>` distinguishes required-protection setup,
callback, canary-integrity, and length failures.
`ProtectedSecretTextFillError<E>` adds UTF-8 validation failure.

When canaries are enabled, the suffix canary is placed at the caller-visible
capacity boundary while the fill callback runs and verified immediately after
it returns. This catches an unsafe external decoder writing past its advertised
destination before the canary is moved to the final initialized length.

Controls marked `Preferred` retain their documented degraded-success semantics.
Applications that require a control before any plaintext is written must mark
that control `Required`.

All five workspace crates are released together at `2.0.3`, with the derive
crate exact-pinned to the matching runtime version.
