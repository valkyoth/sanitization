# Stable Secret Storage Contracts

`Secret<T>` can clear any `T: SecureSanitize`, but generic exposure is safe
only when `T` also attests that its secret-bearing storage remains under the
wrapper's control. Version 2.0 expresses that condition with two safe marker
traits:

- `StableSharedSecretStorage` permits scoped `&T` exposure;
- `StableMutableSecretStorage` permits scoped `&mut T` exposure and extends
  the shared contract.

These are conditional security contracts, not Rust memory-safety contracts.
An incorrect implementation does not by itself create undefined behavior, but
it can invalidate the crate's claim that released secret storage was cleared.

## Normative Contract

No safe operation reachable through `&self` or `&mut self` may release,
transfer, replace, or reallocate secret-bearing storage without clearing it
first. This includes:

- inherent and trait methods;
- mutation through `Cell`, `RefCell`, locks, atomics, or custom interior
  mutability;
- destructors and guard values returned by safe methods;
- callbacks initiated by those methods; and
- allocator operations or ownership transfers hidden behind safe APIs.

`StableSharedSecretStorage` requires this property for every safe operation
reachable through `&self`. `StableMutableSecretStorage` additionally requires
it for every safe operation reachable through `&mut self`.

The traits do not prevent an exposure closure from deliberately copying,
logging, exporting, or replacing secret data. They only establish what the
wrapped type itself promises while the closure has access.

## Built-In Implementations

The core crate implements the contracts for audited fixed-layout values and
secret containers whose safe operations preserve the contract. Dynamic
standard containers such as `Vec<T>` and `String` do not implement the marker
traits: safe growth can release an old allocation containing secret remnants.

Prefer purpose-built containers:

| Need | Type |
| --- | --- |
| Fixed bytes | `SecretBytes<N>` |
| Fixed heap allocation | `SecretBoxBytes` |
| Dynamic bytes with wipe-before-growth | `SecretVec` |
| Dynamic UTF-8 | `SecretString` |
| Bounded bytes or text | `BoundedSecretVec<MAX>`, `BoundedSecretString<MAX>` |
| Locked or guarded storage | mapped containers under the native features |

## Manual Implementation

Manual implementations should be rare and accompanied by a reviewable storage
argument:

```rust
use sanitization::{
    Secret, SecretBytes, SecureSanitize, StableMutableSecretStorage,
    StableSharedSecretStorage,
};

struct FixedCredentials {
    key: SecretBytes<32>,
    nonce: [u8; 12],
}

impl SecureSanitize for FixedCredentials {
    fn secure_sanitize(&mut self) {
        self.key.secure_sanitize();
        self.nonce.secure_sanitize();
    }
}

// STORAGE CONTRACT: all storage is inline and fixed-size. Shared methods do
// not mutate it, and mutable methods overwrite it in place.
impl StableSharedSecretStorage for FixedCredentials {}
impl StableMutableSecretStorage for FixedCredentials {}

let secret = Secret::new(FixedCredentials {
    key: SecretBytes::from_array([7; 32]),
    nonce: [9; 12],
});
assert_eq!(secret.with_secret(|value| value.nonce[0]), 9);
```

Before implementing either trait, review all safe methods, implemented traits,
interior-mutable fields, returned guards, callbacks, and destructor paths. In a
controlled high-assurance profile, allow-list reviewed implementations rather
than accepting arbitrary downstream attestations.

## Generic Bounds

Libraries that expose generic secret access should carry the appropriate bound
at their own API boundary:

```rust
use sanitization::{Secret, StableSharedSecretStorage};

fn inspect<T, R>(secret: &Secret<T>, f: impl FnOnce(&T) -> R) -> R
where
    T: StableSharedSecretStorage,
{
    secret.with_secret(f)
}
```

Do not add a marker implementation only to satisfy a compiler error. Choose a
container with controlled storage or document and review the actual invariant.

See `crates/sanitization/examples/storage_contracts.rs` and
`scripts/verify-secret-exposure-failures.sh` for positive and negative cases.
