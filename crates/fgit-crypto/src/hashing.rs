//! FIPS 180-4 SHA-1 and SHA-256, implemented in-tree in safe Rust.
//!
//! Both cores are the scalar, portable reference implementations required by
//! the safe-performance doctrine: any future optimised variant must reproduce
//! these outputs exactly. Correctness evidence is the published FIPS 180-4
//! known-answer vectors plus block-boundary vectors, checked in under
//! `goldens/digest_vectors.tsv` and independently derived (see the crate
//! documentation).
//!
//! The SHA-1 core additionally exposes every compression block to a
//! [`BlockObserver`], which is how the collision-defense hook in
//! [`crate::defense`] observes real internal state rather than a summary.

use crate::defense::{BlockObserver, BlockVerdict, Sha1BlockContext, UnobservedBlocks};

/// Compression block width shared by SHA-1 and SHA-256.
const BLOCK_BYTES: usize = 64;
/// Offset at which the 64-bit big-endian message length is written.
const LENGTH_OFFSET: usize = 56;

const SHA1_INITIAL_STATE: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

const SHA1_ROUND_CONSTANTS: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];

const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428A_2F98,
    0x7137_4491,
    0xB5C0_FBCF,
    0xE9B5_DBA5,
    0x3956_C25B,
    0x59F1_11F1,
    0x923F_82A4,
    0xAB1C_5ED5,
    0xD807_AA98,
    0x1283_5B01,
    0x2431_85BE,
    0x550C_7DC3,
    0x72BE_5D74,
    0x80DE_B1FE,
    0x9BDC_06A7,
    0xC19B_F174,
    0xE49B_69C1,
    0xEFBE_4786,
    0x0FC1_9DC6,
    0x240C_A1CC,
    0x2DE9_2C6F,
    0x4A74_84AA,
    0x5CB0_A9DC,
    0x76F9_88DA,
    0x983E_5152,
    0xA831_C66D,
    0xB003_27C8,
    0xBF59_7FC7,
    0xC6E0_0BF3,
    0xD5A7_9147,
    0x06CA_6351,
    0x1429_2967,
    0x27B7_0A85,
    0x2E1B_2138,
    0x4D2C_6DFC,
    0x5338_0D13,
    0x650A_7354,
    0x766A_0ABB,
    0x81C2_C92E,
    0x9272_2C85,
    0xA2BF_E8A1,
    0xA81A_664B,
    0xC24B_8B70,
    0xC76C_51A3,
    0xD192_E819,
    0xD699_0624,
    0xF40E_3585,
    0x106A_A070,
    0x19A4_C116,
    0x1E37_6C08,
    0x2748_774C,
    0x34B0_BCB5,
    0x391C_0CB3,
    0x4ED8_AA4A,
    0x5B9C_CA4F,
    0x682E_6FF3,
    0x748F_82EE,
    0x78A5_636F,
    0x84C8_7814,
    0x8CC7_0208,
    0x90BE_FFFA,
    0xA450_6CEB,
    0xBEF9_A3F7,
    0xC671_78F2,
];

/// A streaming, one-shot-capable digest over a byte message.
///
/// Implementations are the only place a digest is produced; the typed
/// identity layers consume this trait rather than raw byte loops.
pub trait DigestHasher {
    /// Fixed-width digest produced by this algorithm.
    type Output;

    /// Start a fresh digest state.
    fn new() -> Self;

    /// Absorb the next contiguous chunk of the message.
    fn update(&mut self, chunk: &[u8]);

    /// Pad the message and produce the digest.
    fn finish(self) -> Self::Output;
}

fn message_byte_count(chunk: &[u8]) -> u64 {
    u64::try_from(chunk.len()).expect("a slice length always fits in u64 on supported targets")
}

/// FIPS 180-4 SHA-1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sha1Hasher {
    state: [u32; 5],
    buffer: [u8; BLOCK_BYTES],
    buffered: usize,
    message_bytes: u64,
    block_index: u64,
}

impl Default for Sha1Hasher {
    fn default() -> Self {
        Self::initial()
    }
}

impl Sha1Hasher {
    const fn initial() -> Self {
        Self {
            state: SHA1_INITIAL_STATE,
            buffer: [0; BLOCK_BYTES],
            buffered: 0,
            message_bytes: 0,
            block_index: 0,
        }
    }

    /// Start a fresh SHA-1 state.
    #[must_use]
    pub const fn new() -> Self {
        Self::initial()
    }

    /// Absorb a chunk, forwarding every completed block to `observer`.
    ///
    /// Returns the first non-clean verdict the observer produced; absorption
    /// stops at that block so a caller can fail closed without consuming the
    /// rest of a hostile message.
    pub(crate) fn update_observed<O: BlockObserver>(
        &mut self,
        chunk: &[u8],
        observer: &mut O,
    ) -> BlockVerdict {
        self.message_bytes = self.message_bytes.wrapping_add(message_byte_count(chunk));
        let mut rest = chunk;
        while !rest.is_empty() {
            let free = BLOCK_BYTES - self.buffered;
            let take = free.min(rest.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&rest[..take]);
            self.buffered += take;
            rest = &rest[take..];
            if self.buffered == BLOCK_BYTES {
                let block = self.buffer;
                self.buffered = 0;
                if let BlockVerdict::Suspected(evidence) = self.compress(&block, observer) {
                    return BlockVerdict::Suspected(evidence);
                }
            }
        }
        BlockVerdict::Clean
    }

    /// Pad and absorb the final blocks, forwarding them to `observer`.
    pub(crate) fn finish_observed<O: BlockObserver>(
        mut self,
        observer: &mut O,
    ) -> Result<[u8; 20], crate::defense::CollisionEvidence> {
        let message_bits = self.message_bytes.wrapping_mul(8);
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > LENGTH_OFFSET {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            self.buffered = 0;
            if let BlockVerdict::Suspected(evidence) = self.compress(&block, observer) {
                return Err(evidence);
            }
        }
        self.buffer[self.buffered..LENGTH_OFFSET].fill(0);
        self.buffer[LENGTH_OFFSET..].copy_from_slice(&message_bits.to_be_bytes());
        let block = self.buffer;
        self.buffered = 0;
        if let BlockVerdict::Suspected(evidence) = self.compress(&block, observer) {
            return Err(evidence);
        }

        let mut digest = [0_u8; 20];
        for (slot, word) in digest.chunks_exact_mut(4).zip(self.state.iter()) {
            slot.copy_from_slice(&word.to_be_bytes());
        }
        Ok(digest)
    }

    fn compress<O: BlockObserver>(&mut self, block: &[u8; BLOCK_BYTES], observer: &mut O) -> BlockVerdict {
        let mut schedule = [0_u32; 80];
        for (word, source) in schedule.iter_mut().zip(block.chunks_exact(4)) {
            let bytes: [u8; 4] = source
                .try_into()
                .expect("chunks_exact(4) always yields four bytes");
            *word = u32::from_be_bytes(bytes);
        }
        for index in 16..80 {
            let mixed = schedule[index - 3]
                ^ schedule[index - 8]
                ^ schedule[index - 14]
                ^ schedule[index - 16];
            schedule[index] = mixed.rotate_left(1);
        }

        let context = Sha1BlockContext {
            block_index: self.block_index,
            chaining_value: self.state,
            schedule: &schedule,
        };
        let verdict = observer.observe(&context);
        self.block_index = self.block_index.wrapping_add(1);
        if let BlockVerdict::Suspected(evidence) = verdict {
            return BlockVerdict::Suspected(evidence);
        }

        let mut working = self.state;
        for (round, word) in schedule.iter().enumerate() {
            let (mixed, constant) = match round {
                0..=19 => (
                    (working[1] & working[2]) | (!working[1] & working[3]),
                    SHA1_ROUND_CONSTANTS[0],
                ),
                20..=39 => (
                    working[1] ^ working[2] ^ working[3],
                    SHA1_ROUND_CONSTANTS[1],
                ),
                40..=59 => (
                    (working[1] & working[2]) | (working[1] & working[3]) | (working[2] & working[3]),
                    SHA1_ROUND_CONSTANTS[2],
                ),
                _ => (
                    working[1] ^ working[2] ^ working[3],
                    SHA1_ROUND_CONSTANTS[3],
                ),
            };
            let temporary = working[0]
                .rotate_left(5)
                .wrapping_add(mixed)
                .wrapping_add(working[4])
                .wrapping_add(constant)
                .wrapping_add(*word);
            working[4] = working[3];
            working[3] = working[2];
            working[2] = working[1].rotate_left(30);
            working[1] = working[0];
            working[0] = temporary;
        }

        for (slot, value) in self.state.iter_mut().zip(working.iter()) {
            *slot = slot.wrapping_add(*value);
        }
        BlockVerdict::Clean
    }
}

impl DigestHasher for Sha1Hasher {
    type Output = [u8; 20];

    fn new() -> Self {
        Self::initial()
    }

    fn update(&mut self, chunk: &[u8]) {
        let verdict = self.update_observed(chunk, &mut UnobservedBlocks);
        debug_assert!(
            matches!(verdict, BlockVerdict::Clean),
            "the unscreened observer never reports collision evidence"
        );
    }

    fn finish(self) -> Self::Output {
        self.finish_observed(&mut UnobservedBlocks)
            .expect("the unscreened observer never reports collision evidence")
    }
}

/// FIPS 180-4 SHA-256.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sha256Hasher {
    state: [u32; 8],
    buffer: [u8; BLOCK_BYTES],
    buffered: usize,
    message_bytes: u64,
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::initial()
    }
}

impl Sha256Hasher {
    const fn initial() -> Self {
        Self {
            state: SHA256_INITIAL_STATE,
            buffer: [0; BLOCK_BYTES],
            buffered: 0,
            message_bytes: 0,
        }
    }

    /// Start a fresh SHA-256 state.
    #[must_use]
    pub const fn new() -> Self {
        Self::initial()
    }

    fn compress(&mut self, block: &[u8; BLOCK_BYTES]) {
        let mut schedule = [0_u32; 64];
        for (word, source) in schedule.iter_mut().zip(block.chunks_exact(4)) {
            let bytes: [u8; 4] = source
                .try_into()
                .expect("chunks_exact(4) always yields four bytes");
            *word = u32::from_be_bytes(bytes);
        }
        for index in 16..64 {
            let previous = schedule[index - 15];
            let recent = schedule[index - 2];
            let lower = previous.rotate_right(7) ^ previous.rotate_right(18) ^ (previous >> 3);
            let upper = recent.rotate_right(17) ^ recent.rotate_right(19) ^ (recent >> 10);
            schedule[index] = upper
                .wrapping_add(schedule[index - 7])
                .wrapping_add(lower)
                .wrapping_add(schedule[index - 16]);
        }

        let mut working = self.state;
        for (word, constant) in schedule.iter().zip(SHA256_ROUND_CONSTANTS.iter()) {
            let sigma_one =
                working[4].rotate_right(6) ^ working[4].rotate_right(11) ^ working[4].rotate_right(25);
            let choose = (working[4] & working[5]) ^ (!working[4] & working[6]);
            let first = working[7]
                .wrapping_add(sigma_one)
                .wrapping_add(choose)
                .wrapping_add(*constant)
                .wrapping_add(*word);
            let sigma_zero =
                working[0].rotate_right(2) ^ working[0].rotate_right(13) ^ working[0].rotate_right(22);
            let majority =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let second = sigma_zero.wrapping_add(majority);

            working[7] = working[6];
            working[6] = working[5];
            working[5] = working[4];
            working[4] = working[3].wrapping_add(first);
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[0];
            working[0] = first.wrapping_add(second);
        }

        for (slot, value) in self.state.iter_mut().zip(working.iter()) {
            *slot = slot.wrapping_add(*value);
        }
    }
}

impl DigestHasher for Sha256Hasher {
    type Output = [u8; 32];

    fn new() -> Self {
        Self::initial()
    }

    fn update(&mut self, chunk: &[u8]) {
        self.message_bytes = self.message_bytes.wrapping_add(message_byte_count(chunk));
        let mut rest = chunk;
        while !rest.is_empty() {
            let free = BLOCK_BYTES - self.buffered;
            let take = free.min(rest.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&rest[..take]);
            self.buffered += take;
            rest = &rest[take..];
            if self.buffered == BLOCK_BYTES {
                let block = self.buffer;
                self.buffered = 0;
                self.compress(&block);
            }
        }
    }

    fn finish(mut self) -> Self::Output {
        let message_bits = self.message_bytes.wrapping_mul(8);
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > LENGTH_OFFSET {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            self.buffered = 0;
            self.compress(&block);
        }
        self.buffer[self.buffered..LENGTH_OFFSET].fill(0);
        self.buffer[LENGTH_OFFSET..].copy_from_slice(&message_bits.to_be_bytes());
        let block = self.buffer;
        self.buffered = 0;
        self.compress(&block);

        let mut digest = [0_u8; 32];
        for (slot, word) in digest.chunks_exact_mut(4).zip(self.state.iter()) {
            slot.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

/// One-shot SHA-1 over a complete message.
#[must_use]
pub fn sha1_digest(message: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1Hasher::new();
    DigestHasher::update(&mut hasher, message);
    DigestHasher::finish(hasher)
}

/// One-shot SHA-256 over a complete message.
#[must_use]
pub fn sha256_digest(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256Hasher::new();
    DigestHasher::update(&mut hasher, message);
    DigestHasher::finish(hasher)
}
