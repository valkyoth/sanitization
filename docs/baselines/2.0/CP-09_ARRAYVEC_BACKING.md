# CP-09 ArrayVec Backing Cleanup

Status: implementation review record

Base commit: `7d6e145`

Checkpoint: `CP-09`

CP-09 closes the historical inline-storage gap in
`sanitization-arrayvec`.

## Cleanup Order

`SecretArrayVec<T, CAP>` now:

1. calls `SecureSanitize` on every live value being removed;
2. lets `ArrayVec` drop those still-valid values;
3. obtains the resulting `MaybeUninit<T>` spare region through
   `ArrayVec::spare_capacity_mut`; and
4. volatile-clears every byte in that region.

No live `T` is raw-zeroed. The byte length comes from `size_of_val` on the
stable spare-capacity slice, avoiding separate capacity multiplication. A
zero-sized backing region is an explicit no-op.

## Unsafe Boundary

The sister crate contains one allowed unsafe module. It converts the writable
`MaybeUninit<T>` spare slice into a mutable byte slice. This is valid because:

- the slice contains no live values;
- every returned slot is writable inline storage owned by the `ArrayVec`;
- `u8` has alignment one;
- every byte pattern is valid for `MaybeUninit<T>`; and
- the byte view does not outlive the exclusive spare-capacity borrow.

The helper uses the main crate's existing volatile-write API and introduces no
second wipe implementation.

## Operation Coverage

- wrapping an existing `ArrayVec` clears its current historical spare bytes;
- `pop` wipes the stale moved-from inline slot before returning the value;
- `truncate` sanitizes removed values before drop and then wipes spare bytes;
- `clear_secret`, `SecureSanitize`, `Drop`, and `into_cleared` wipe the complete
  backing region after live cleanup;
- reuse cannot preserve bytes from an earlier occupant after cleanup.

Tests cover push, pop, truncate, clear, wrapping, reuse, full backing cleanup,
zero-sized drop-bearing values, and sanitize-before-drop ordering.
