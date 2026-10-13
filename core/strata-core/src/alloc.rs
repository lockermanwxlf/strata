//! The core's global allocator: the system allocator, except that every heap block is
//! zeroed before it is freed.
//!
//! `zeroize` wipes the buffers that hold secrets when they are dropped, but not the
//! copies left behind elsewhere: a `Vec` that grew moved its old contents out of a
//! block it then freed, and UniFFI passes every `ByteArray` (passwords in, revealed
//! values out) through a buffer that it frees without wiping. Zeroing on free covers
//! all of them. The cost is one `memset` over each block as it is freed.

use std::alloc::{GlobalAlloc, Layout, System};

pub struct ZeroizingAlloc;

// SAFETY: every method forwards to `System` with the caller's arguments, so `System`'s
// guarantees carry over. `dealloc` first writes zeros over the block, which the caller
// still owns (`ptr` came from this allocator with this `layout`) until `System.dealloc`
// returns. `realloc` keeps the default implementation, which allocates, copies and
// then calls `dealloc`, so the old block is wiped too.
unsafe impl GlobalAlloc for ZeroizingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds `GlobalAlloc::alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as for `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` points to a live block of `layout.size()` bytes owned by the
        // caller, so it may be written; it is then returned to `System`, which
        // allocated it.
        unsafe {
            ptr.write_bytes(0, layout.size());
            barrier(ptr);
            System.dealloc(ptr, layout);
        }
    }
}

// Stores right before a free are dead as far as the compiler is concerned, so it could
// drop the `write_bytes` above. `black_box` stops that: it passes the pointer to an
// empty `asm!` block that may read memory, so the zeros must be in memory first. This
// is how Linux's `memzero_explicit` works (`memset` plus `barrier_data`). Volatile
// writes, as `zeroize` uses, would do the same byte by byte, far too slowly for the
// 64 MiB Argon2 blocks this frees.
#[inline(always)]
fn barrier(ptr: *mut u8) {
    std::hint::black_box(ptr);
}
