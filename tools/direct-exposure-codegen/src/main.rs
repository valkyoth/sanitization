use core::hint::black_box;
use sanitization::SecretBytes;

#[inline(never)]
fn cp04_direct_exposure(secret: &SecretBytes<4096>) -> u8 {
    secret.expose_secret(|bytes| black_box(bytes)[black_box(2048)])
}

#[inline(never)]
fn cp04_copy_exposure(secret: &SecretBytes<4096>) -> u8 {
    secret.expose_secret_copy(|bytes| black_box(bytes)[black_box(2048)])
}

fn main() {
    let secret = SecretBytes::<4096>::from_fn(|index| index as u8);
    black_box(cp04_direct_exposure(black_box(&secret)));
    black_box(cp04_copy_exposure(black_box(&secret)));
}
