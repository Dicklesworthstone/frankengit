#![forbid(unsafe_code)]

use fgit_pack::PackLimits;

#[must_use]
pub const fn limits() -> PackLimits {
    PackLimits {
        max_input_bytes: 32 * 1024,
        max_entries: 16,
        max_object_bytes: 4 * 1024,
        max_delta_depth: 16,
        max_delta_fanout: 16,
        max_total_expanded_bytes: 8 * 1024,
        max_expansion_ratio: 256,
        max_delta_work: 32 * 1024,
        max_inflate_work: 64 * 1024,
        max_cached_bytes: 8 * 1024,
        max_index_entries: 16,
    }
}

#[must_use]
pub const fn always() -> bool {
    true
}
