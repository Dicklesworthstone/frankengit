#![forbid(unsafe_code)]

use fgit_pack::PackLimits;

pub const SHA1_TRAILER: [u8; 20] = [0xaa; 20];

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

#[must_use]
pub fn pack_with_entries(entries: &[Vec<u8>]) -> Vec<u8> {
    let count = u32::try_from(entries.len()).expect("test pack entry count fits u32");
    let mut pack = b"PACK\0\0\0\x02".to_vec();
    pack.extend_from_slice(&count.to_be_bytes());
    for entry in entries {
        pack.extend_from_slice(entry);
    }
    pack.extend_from_slice(&SHA1_TRAILER);
    pack
}

#[must_use]
pub fn entry(kind: u8, payload: &[u8]) -> Vec<u8> {
    declared_entry(kind, payload.len(), &zlib_stored(payload))
}

#[must_use]
pub fn declared_entry(kind: u8, declared_size: usize, member: &[u8]) -> Vec<u8> {
    let mut entry = entry_header(kind, declared_size);
    entry.extend_from_slice(member);
    entry
}

fn entry_header(kind: u8, declared_size: usize) -> Vec<u8> {
    assert!(matches!(kind, 1..=4 | 6 | 7), "native pack entry kind");

    let mut remaining = declared_size;
    let mut first = (kind << 4) | u8::try_from(remaining & 0x0f).expect("masked size");
    remaining >>= 4;
    if remaining == 0 {
        return vec![first];
    }
    first |= 0x80;
    let mut header = vec![first];
    while remaining != 0 {
        let mut next = u8::try_from(remaining & 0x7f).expect("masked size");
        remaining >>= 7;
        if remaining != 0 {
            next |= 0x80;
        }
        header.push(next);
    }
    header
}

fn zlib_stored(bytes: &[u8]) -> Vec<u8> {
    let length = u16::try_from(bytes.len()).expect("stored fixture length fits RFC 1951");
    let mut member = vec![0x78, 0x01, 0x01];
    member.extend_from_slice(&length.to_le_bytes());
    member.extend_from_slice(&(!length).to_le_bytes());
    member.extend_from_slice(bytes);
    member.extend_from_slice(&adler32(bytes).to_be_bytes());
    member
}

fn adler32(bytes: &[u8]) -> u32 {
    let mut a = 1_u32;
    let mut b = 0_u32;
    for &byte in bytes {
        a = (a + u32::from(byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}
