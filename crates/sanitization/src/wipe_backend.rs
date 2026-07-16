#[cfg(target_arch = "wasm32")]
use core::hint::black_box;
use core::{
    ptr,
    sync::atomic::{compiler_fence, fence, Ordering},
};

mod sealed {
    pub trait Sealed {}
}

pub(crate) trait ErasureBackend: sealed::Sealed {
    fn erase(ptr: *mut u8, len: usize);

    #[cfg(feature = "multi-pass-clear")]
    fn fill(ptr: *mut u8, len: usize, value: u8);
}

struct VolatileRam;

impl sealed::Sealed for VolatileRam {}

impl ErasureBackend for VolatileRam {
    #[inline(never)]
    fn erase(ptr: *mut u8, len: usize) {
        ordered_volatile_store(ptr, len, 0);
    }

    #[cfg(feature = "multi-pass-clear")]
    #[inline(never)]
    fn fill(ptr: *mut u8, len: usize, value: u8) {
        ordered_volatile_store(ptr, len, value);
    }
}

#[inline(never)]
pub(crate) fn erase(ptr: *mut u8, len: usize) {
    VolatileRam::erase(ptr, len);
}

#[cfg(feature = "multi-pass-clear")]
#[inline(never)]
pub(crate) fn erase_multi_pass(ptr: *mut u8, len: usize) {
    VolatileRam::erase(ptr, len);
    VolatileRam::fill(ptr, len, 0xFF);
    VolatileRam::erase(ptr, len);
}

#[cfg(not(target_arch = "wasm32"))]
#[inline(never)]
fn ordered_volatile_store(ptr: *mut u8, len: usize, value: u8) {
    compiler_fence(Ordering::SeqCst);

    let mut offset = 0;
    while offset < len {
        // SAFETY: Callers pass a pointer and length from either a live
        // mutable byte slice or the full capacity of an owned contiguous
        // allocation. Each computed address is allocated and writable for a
        // single byte, including spare capacity, and is never read through
        // this pointer.
        unsafe {
            ptr::write_volatile(ptr.add(offset), value);
        }
        offset += 1;
    }

    compiler_fence(Ordering::SeqCst);
    // CP-10 retains the 1.x hardware-ordering boundary. Reducing this fence
    // requires target-specific codegen, native evidence, and external review.
    fence(Ordering::SeqCst);
}

#[cfg(target_arch = "wasm32")]
#[inline(never)]
fn ordered_volatile_store(ptr: *mut u8, len: usize, value: u8) {
    compiler_fence(Ordering::SeqCst);
    let store: fn(*mut u8, usize, u8) = wasm_volatile_store_impl;
    black_box(store)(ptr, len, value);
    compiler_fence(Ordering::SeqCst);
    fence(Ordering::SeqCst);
}

#[cfg(target_arch = "wasm32")]
#[inline(never)]
fn wasm_volatile_store_impl(ptr: *mut u8, len: usize, value: u8) {
    let mut offset = 0;
    while offset < len {
        // SAFETY: Same pointer validity contract as
        // `ordered_volatile_store`.
        unsafe {
            ptr::write_volatile(ptr.add(offset), value);
        }
        offset += 1;
    }
}
