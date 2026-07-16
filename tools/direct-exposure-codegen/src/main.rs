use core::hint::black_box;
use sanitization::{
    ct, GuardedSecretVec, LockedSecretBytes, SealedSecretBytes, SecretBoxBytes, SecretBytes,
    SecretPoolSlot, SecretString, SecretVec, SecureSanitize,
};
use sanitization_arrayvec::SecretArrayVec;

#[derive(sanitization::SecureSanitize)]
pub struct DerivedStruct {
    first: SecretBytes<32>,
    second: SecretBytes<16>,
}

#[derive(sanitization::SecureSanitize)]
#[sanitization(enum_inactive_variant_bytes = "acknowledged")]
pub enum DerivedEnum {
    Key(SecretBytes<32>),
    Empty,
}

#[inline(never)]
#[no_mangle]
pub fn cp04_direct_exposure(secret: &SecretBytes<4096>) -> u8 {
    secret.expose_secret(|bytes| black_box(bytes)[black_box(2048)])
}

#[inline(never)]
#[no_mangle]
pub fn cp04_copy_exposure(secret: &SecretBytes<4096>) -> u8 {
    secret.expose_secret_copy(|bytes| black_box(bytes)[black_box(2048)])
}

#[inline(never)]
#[no_mangle]
pub fn cp05_clear_secret_box(secret: &mut SecretBoxBytes) {
    secret.clear_secret();
}

#[inline(never)]
#[no_mangle]
pub fn cp19_clear_secret_vec(secret: &mut SecretVec) {
    secret.clear_secret();
}

#[inline(never)]
#[no_mangle]
pub fn cp19_clear_secret_string(secret: &mut SecretString) {
    secret.clear_secret();
}

#[inline(never)]
#[no_mangle]
pub fn cp19_clear_locked(secret: &mut LockedSecretBytes<32>) {
    secret.secure_clear();
}

#[inline(never)]
#[no_mangle]
pub fn cp19_clear_guarded(secret: &mut GuardedSecretVec) {
    secret.clear_secret();
}

#[inline(never)]
#[no_mangle]
pub fn cp19_clear_sealed(secret: &mut SealedSecretBytes<32>) {
    let _ = black_box(secret.try_secure_sanitize());
}

#[inline(never)]
#[no_mangle]
pub fn cp19_clear_pool_slot(slot: &mut SecretPoolSlot<'_, 32, 2>) {
    slot.secure_clear();
}

#[inline(never)]
#[no_mangle]
pub fn cp19_clear_derived_struct(value: &mut DerivedStruct) {
    value.secure_sanitize();
}

#[inline(never)]
#[no_mangle]
pub fn cp19_clear_derived_enum(value: &mut DerivedEnum) {
    value.secure_sanitize();
}

#[inline(never)]
#[no_mangle]
pub fn cp19_clear_tuple(value: &mut (SecretBytes<32>, SecretBytes<16>)) {
    value.secure_sanitize();
}

#[inline(never)]
#[no_mangle]
pub fn cp19_clear_arrayvec(value: &mut SecretArrayVec<SecretBytes<16>, 4>) {
    value.clear_secret();
}

#[inline(never)]
#[no_mangle]
pub fn cp19_ct_eq(left: &[u8; 32], right: &[u8; 32]) -> ct::Choice {
    ct::eq_fixed(black_box(left), black_box(right))
}

#[inline(never)]
#[no_mangle]
pub fn cp19_ct_cmp(left: &[u8; 32], right: &[u8; 32]) -> ct::CtOrdering {
    ct::cmp_fixed(black_box(left), black_box(right))
}

#[inline(never)]
#[no_mangle]
pub fn cp19_ct_copy(destination: &mut [u8; 32], source: &[u8; 32], choice: ct::Choice) {
    ct::conditional_copy(destination, source, choice).expect("fixed lengths match");
}

#[inline(never)]
#[no_mangle]
pub fn cp19_ct_swap(left: &mut [u8; 32], right: &mut [u8; 32], choice: ct::Choice) {
    ct::conditional_swap(left, right, choice).expect("fixed lengths match");
}

#[inline(never)]
#[no_mangle]
pub fn cp19_ct_lookup(table: &[u8; 16], index: ct::SecretIndex) -> u8 {
    ct::oblivious_lookup(table, index, &0)
}

fn main() {
    let secret = SecretBytes::<4096>::from_fn(|index| index as u8);
    black_box(cp04_direct_exposure(black_box(&secret)));
    black_box(cp04_copy_exposure(black_box(&secret)));

    let mut boxed = SecretBoxBytes::from_fn(4096, |index| index as u8);
    cp05_clear_secret_box(black_box(&mut boxed));
    black_box(boxed);

    let mut vec = SecretVec::from_slice(&[7; 64]);
    cp19_clear_secret_vec(black_box(&mut vec));
    let mut string = SecretString::from_secret_str("codegen probe");
    cp19_clear_secret_string(black_box(&mut string));

    let mut derived = DerivedStruct {
        first: SecretBytes::from_array([1; 32]),
        second: SecretBytes::from_array([2; 16]),
    };
    cp19_clear_derived_struct(black_box(&mut derived));
    let mut derived_enum = DerivedEnum::Key(SecretBytes::from_array([3; 32]));
    cp19_clear_derived_enum(black_box(&mut derived_enum));
    black_box(DerivedEnum::Empty);

    let mut tuple = (
        SecretBytes::from_array([4; 32]),
        SecretBytes::from_array([5; 16]),
    );
    cp19_clear_tuple(black_box(&mut tuple));

    let mut arrayvec = SecretArrayVec::<SecretBytes<16>, 4>::new();
    arrayvec.push(SecretBytes::from_array([6; 16])).unwrap();
    cp19_clear_arrayvec(black_box(&mut arrayvec));

    let left = [9_u8; 32];
    let mut right = [9_u8; 32];
    black_box(cp19_ct_eq(black_box(&left), black_box(&right)));
    black_box(cp19_ct_cmp(black_box(&left), black_box(&right)));
    cp19_ct_copy(
        black_box(&mut right),
        black_box(&left),
        ct::Choice::from_u8(1),
    );
    cp19_ct_swap(
        black_box(&mut right),
        black_box(&mut [0_u8; 32]),
        ct::Choice::from_u8(0),
    );
    black_box(cp19_ct_lookup(
        black_box(&[0_u8; 16]),
        ct::SecretIndex::new(7),
    ));

    black_box(cp19_clear_locked as fn(&mut LockedSecretBytes<32>));
    black_box(cp19_clear_guarded as fn(&mut GuardedSecretVec));
    black_box(cp19_clear_sealed as fn(&mut SealedSecretBytes<32>));
    black_box(cp19_clear_pool_slot as fn(&mut SecretPoolSlot<'_, 32, 2>));
}
