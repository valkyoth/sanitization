# CP-03 Restricted Generic Secret Exposure

Status: implementation review record

Base commit: `5d10001`

Checkpoint: `CP-03`

CP-03 restricts generic `Secret<T>` exposure to types carrying the storage
contracts introduced in CP-02. It does not change which values can be owned,
explicitly sanitized, or cleared on drop.

## API Boundary

`Secret<T>` retains these operations for every `T: SecureSanitize`:

- `Secret::new`;
- `Secret::into_cleared`;
- `SecureSanitize::secure_sanitize`;
- redacted `Debug`;
- `Default` when `T: Default`;
- clear-on-drop ownership.

Shared closure exposure now requires:

```text
T: StableSharedSecretStorage
```

Mutable closure exposure now requires:

```text
T: StableMutableSecretStorage
```

The mutable contract extends the shared contract. Fixed arrays, reviewed
built-in fixed-storage types, and downstream types with explicit audited marker
implementations retain generic closure access.

## Deliberate Rejections

The new compile-fail gate verifies that generic exposure is unavailable for:

- `Secret<Vec<u8>>`;
- `Secret<String>`;
- a custom `RefCell<Vec<u8>>` owner that can replace its allocation through
  `&self`.

These types can still be wrapped and cleared. Callers needing scoped dynamic
byte or UTF-8 access should use `SecretVec`, `SecretString`, or their bounded
and mapped counterparts.

## Compatibility And Interop

`Secret<T>` now implements `SecureSanitize` by forwarding to `T`. The optional
`zeroize-interop` bridge uses that implementation directly, so it remains
available for storage-unstable owned values without reopening generic access.

No `Deref`, `DerefMut`, `AsRef`, `AsMut`, `Borrow`, `BorrowMut`, ordinary
equality, cloning, or secret-printing debug path is added.

## Verification

The checkpoint includes:

- unit coverage for stable built-in and downstream storage;
- drop-clearing coverage for a storage-unstable owned value;
- compile-fail fixtures for dynamic and interior-mutable storage;
- rustdoc borrow-escape rejection;
- workspace all-feature checks on Rust 1.97.1;
- MSRV workspace checks on Rust 1.90.0;
- the normal repository check path.
