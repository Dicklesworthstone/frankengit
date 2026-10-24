//! FIPS 180-4 SHA-1 and SHA-256, implemented in-tree in safe Rust.
//!
//! Both cores are scalar and portable. Their rounds are unrolled with register
//! renaming and whole input blocks are compressed in place (frankengit-0dq9);
//! the former one-round-at-a-time cores are kept under `cfg(test)` as the
//! reference every output must reproduce exactly. Correctness evidence is the
//! published FIPS 180-4 known-answer vectors plus block-boundary vectors,
//! checked in under `goldens/digest_vectors.tsv` and independently derived
//! (see the crate documentation), and the differential tests below.
//!
//! The SHA-1 core additionally exposes every compression block to a
//! [`BlockObserver`], which is how the collision-defense hook in
//! the `defense` module observes real internal state rather than a summary.

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
    #[must_use]
    fn new() -> Self;

    /// Absorb the next contiguous chunk of the message.
    fn update(&mut self, chunk: &[u8]);

    /// Pad the message and produce the digest.
    #[must_use]
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
        if self.buffered > 0 {
            let take = (BLOCK_BYTES - self.buffered).min(rest.len());
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
        if self.buffered == 0 {
            let (blocks, tail) = rest.as_chunks::<BLOCK_BYTES>();
            for block in blocks {
                if let BlockVerdict::Suspected(evidence) = self.compress(block, observer) {
                    return BlockVerdict::Suspected(evidence);
                }
            }
            rest = tail;
        }
        self.buffer[self.buffered..self.buffered + rest.len()].copy_from_slice(rest);
        self.buffered += rest.len();
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
        for (slot, word) in digest
            .as_mut_slice()
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(self.state.iter())
        {
            *slot = word.to_be_bytes();
        }
        Ok(digest)
    }

    fn compress<O: BlockObserver>(
        &mut self,
        block: &[u8; BLOCK_BYTES],
        observer: &mut O,
    ) -> BlockVerdict {
        if !O::INSPECTS_BLOCKS {
            // Its verdict is always clean, so only the rounds remain.
            self.block_index = self.block_index.wrapping_add(1);
            self.state = sha1_rounds_streamed(self.state, block);
            return BlockVerdict::Clean;
        }
        let schedule = sha1_schedule(block);
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
        self.state = sha1_rounds(self.state, &schedule);
        BlockVerdict::Clean
    }
}

/// The fully expanded SHA-1 message schedule, which the collision-detector
/// hook observes.
fn sha1_schedule(block: &[u8; BLOCK_BYTES]) -> [u32; 80] {
    let mut schedule = [0_u32; 80];
    for (word, source) in schedule.iter_mut().zip(block.as_slice().as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*source);
    }
    for index in 16..80 {
        let mixed =
            schedule[index - 3] ^ schedule[index - 8] ^ schedule[index - 14] ^ schedule[index - 16];
        schedule[index] = mixed.rotate_left(1);
    }
    schedule
}

#[inline]
const fn sha1_choose(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[inline]
const fn sha1_parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline]
const fn sha1_majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

/// One SHA-1 round with the working variables renamed rather than shifted:
/// `$e` receives the new first word and `$b` its rotation, so the next round
/// names them `($e, $a, $b, $c, $d)`.
macro_rules! sha1_round {
    ($function:ident, $constant:expr, $word:expr, $a:ident, $b:ident, $c:ident, $d:ident, $e:ident) => {
        $e = $e
            .wrapping_add($a.rotate_left(5))
            .wrapping_add($function($b, $c, $d))
            .wrapping_add($constant)
            .wrapping_add($word);
        $b = $b.rotate_left(30);
    };
}

/// Twenty rounds of one SHA-1 phase, five renamings per pass. `$word` yields
/// round `n`'s schedule word and is called for rounds in increasing order.
macro_rules! sha1_phase {
    ($function:ident, $constant:expr, $word:ident, $first:expr, $a:ident, $b:ident, $c:ident, $d:ident, $e:ident) => {
        let mut round = $first;
        while round < $first + 20 {
            sha1_round!($function, $constant, $word(round), $a, $b, $c, $d, $e);
            sha1_round!($function, $constant, $word(round + 1), $e, $a, $b, $c, $d);
            sha1_round!($function, $constant, $word(round + 2), $d, $e, $a, $b, $c);
            sha1_round!($function, $constant, $word(round + 3), $c, $d, $e, $a, $b);
            sha1_round!($function, $constant, $word(round + 4), $b, $c, $d, $e, $a);
            round += 5;
        }
    };
}

/// The 80 SHA-1 rounds over a materialised `schedule`, added into `state`.
fn sha1_rounds(state: [u32; 5], schedule: &[u32; 80]) -> [u32; 5] {
    sha1_rounds_with(state, |round| schedule[round])
}

/// The 80 SHA-1 rounds with each schedule word computed as it is needed from
/// a ring of the last sixteen: `W[t]` replaces `W[t - 16]`, and
/// `W[t - 3]`, `W[t - 8]` and `W[t - 14]` sit at `t + 13`, `t + 8` and
/// `t + 2` modulo 16.
fn sha1_rounds_streamed(state: [u32; 5], block: &[u8; BLOCK_BYTES]) -> [u32; 5] {
    let mut ring = [0_u32; 16];
    for (word, source) in ring.iter_mut().zip(block.as_slice().as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*source);
    }
    sha1_rounds_with(state, |round| {
        if round < 16 {
            return ring[round];
        }
        let next = (ring[(round + 13) & 15]
            ^ ring[(round + 8) & 15]
            ^ ring[(round + 2) & 15]
            ^ ring[round & 15])
            .rotate_left(1);
        ring[round & 15] = next;
        next
    })
}

/// The 80 SHA-1 rounds, added into `state`; `word(n)` is called once per
/// round, in order. `wa`..`we` are FIPS 180-4's working variables a..e.
#[inline]
fn sha1_rounds_with(state: [u32; 5], mut word: impl FnMut(usize) -> u32) -> [u32; 5] {
    let [mut wa, mut wb, mut wc, mut wd, mut we] = state;
    sha1_phase!(
        sha1_choose,
        SHA1_ROUND_CONSTANTS[0],
        word,
        0,
        wa,
        wb,
        wc,
        wd,
        we
    );
    sha1_phase!(
        sha1_parity,
        SHA1_ROUND_CONSTANTS[1],
        word,
        20,
        wa,
        wb,
        wc,
        wd,
        we
    );
    sha1_phase!(
        sha1_majority,
        SHA1_ROUND_CONSTANTS[2],
        word,
        40,
        wa,
        wb,
        wc,
        wd,
        we
    );
    sha1_phase!(
        sha1_parity,
        SHA1_ROUND_CONSTANTS[3],
        word,
        60,
        wa,
        wb,
        wc,
        wd,
        we
    );
    [
        state[0].wrapping_add(wa),
        state[1].wrapping_add(wb),
        state[2].wrapping_add(wc),
        state[3].wrapping_add(wd),
        state[4].wrapping_add(we),
    ]
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

/// One SHA-256 round with the working variables renamed rather than shifted:
/// `$d` receives the new fifth word and `$h` the new first, so the next round
/// names them `($h, $a, $b, $c, $d, $e, $f, $g)`.
macro_rules! sha256_round {
    ($word:ident, $round:expr, $a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident) => {
        let first = $h
            .wrapping_add($e.rotate_right(6) ^ $e.rotate_right(11) ^ $e.rotate_right(25))
            .wrapping_add(($e & $f) ^ (!$e & $g))
            .wrapping_add(SHA256_ROUND_CONSTANTS[$round])
            .wrapping_add($word($round));
        let second = ($a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22))
            .wrapping_add(($a & $b) ^ ($a & $c) ^ ($b & $c));
        $d = $d.wrapping_add(first);
        $h = first.wrapping_add(second);
    };
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

    /// One block. Each schedule word is computed as its round needs it from
    /// a ring of the last sixteen: `W[t]` replaces `W[t - 16]`, and
    /// `W[t - 2]`, `W[t - 7]` and `W[t - 15]` sit at `t + 14`, `t + 9` and
    /// `t + 1` modulo 16 (frankengit-0dq9). `wa`..`wh` are FIPS 180-4's
    /// working variables a..h.
    fn compress(&mut self, block: &[u8; BLOCK_BYTES]) {
        let mut ring = [0_u32; 16];
        for (word, source) in ring.iter_mut().zip(block.as_slice().as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*source);
        }
        let mut word = |round: usize| {
            if round < 16 {
                return ring[round];
            }
            let previous = ring[(round + 1) & 15];
            let recent = ring[(round + 14) & 15];
            let lower = previous.rotate_right(7) ^ previous.rotate_right(18) ^ (previous >> 3);
            let upper = recent.rotate_right(17) ^ recent.rotate_right(19) ^ (recent >> 10);
            let next = upper
                .wrapping_add(ring[(round + 9) & 15])
                .wrapping_add(lower)
                .wrapping_add(ring[round & 15]);
            ring[round & 15] = next;
            next
        };
        let [
            mut wa,
            mut wb,
            mut wc,
            mut wd,
            mut we,
            mut wf,
            mut wg,
            mut wh,
        ] = self.state;
        let mut round = 0;
        while round < 64 {
            sha256_round!(word, round, wa, wb, wc, wd, we, wf, wg, wh);
            sha256_round!(word, round + 1, wh, wa, wb, wc, wd, we, wf, wg);
            sha256_round!(word, round + 2, wg, wh, wa, wb, wc, wd, we, wf);
            sha256_round!(word, round + 3, wf, wg, wh, wa, wb, wc, wd, we);
            sha256_round!(word, round + 4, we, wf, wg, wh, wa, wb, wc, wd);
            sha256_round!(word, round + 5, wd, we, wf, wg, wh, wa, wb, wc);
            sha256_round!(word, round + 6, wc, wd, we, wf, wg, wh, wa, wb);
            sha256_round!(word, round + 7, wb, wc, wd, we, wf, wg, wh, wa);
            round += 8;
        }
        for (slot, value) in self.state.iter_mut().zip([wa, wb, wc, wd, we, wf, wg, wh]) {
            *slot = slot.wrapping_add(value);
        }
    }
}

impl DigestHasher for Sha256Hasher {
    type Output = [u8; 32];

    fn new() -> Self {
        Self::initial()
    }

    fn update(&mut self, chunk: &[u8]) {
        let mut rest = chunk;
        if self.buffered > 0 {
            let take = (BLOCK_BYTES - self.buffered).min(rest.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&rest[..take]);
            self.buffered += take;
            rest = &rest[take..];
            if self.buffered == BLOCK_BYTES {
                let block = self.buffer;
                self.buffered = 0;
                self.compress(&block);
            }
        }
        if self.buffered == 0 {
            let (blocks, tail) = rest.as_chunks::<BLOCK_BYTES>();
            for block in blocks {
                self.compress(block);
            }
            rest = tail;
        }
        self.buffer[self.buffered..self.buffered + rest.len()].copy_from_slice(rest);
        self.buffered += rest.len();
        self.message_bytes = self.message_bytes.wrapping_add(message_byte_count(chunk));
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
        for (slot, word) in digest
            .as_mut_slice()
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(self.state.iter())
        {
            *slot = word.to_be_bytes();
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

#[cfg(test)]
mod tests {
    use super::{
        BLOCK_BYTES, BlockObserver, BlockVerdict, DigestHasher, SHA1_INITIAL_STATE,
        SHA1_ROUND_CONSTANTS, SHA256_INITIAL_STATE, SHA256_ROUND_CONSTANTS, Sha1BlockContext,
        Sha1Hasher, Sha256Hasher, sha1_schedule,
    };
    use crate::defense::CollisionEvidence;

    /// The one-round-at-a-time cores exactly as they were before
    /// frankengit-0dq9, with plain FIPS 180-4 padding: the reference.
    mod reference {
        use super::{BLOCK_BYTES, SHA1_ROUND_CONSTANTS, SHA256_ROUND_CONSTANTS};

        pub(super) fn sha1_compress(state: [u32; 5], block: &[u8; BLOCK_BYTES]) -> [u32; 5] {
            let mut schedule = [0_u32; 80];
            for (word, source) in schedule.iter_mut().zip(block.as_slice().as_chunks::<4>().0) {
                *word = u32::from_be_bytes(*source);
            }
            for index in 16..80 {
                let mixed = schedule[index - 3]
                    ^ schedule[index - 8]
                    ^ schedule[index - 14]
                    ^ schedule[index - 16];
                schedule[index] = mixed.rotate_left(1);
            }
            let mut working = state;
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
                        (working[1] & working[2])
                            | (working[1] & working[3])
                            | (working[2] & working[3]),
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
            let mut next = state;
            for (slot, value) in next.iter_mut().zip(working.iter()) {
                *slot = slot.wrapping_add(*value);
            }
            next
        }

        pub(super) fn sha256_compress(state: [u32; 8], block: &[u8; BLOCK_BYTES]) -> [u32; 8] {
            let mut schedule = [0_u32; 64];
            for (word, source) in schedule.iter_mut().zip(block.as_slice().as_chunks::<4>().0) {
                *word = u32::from_be_bytes(*source);
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
            let mut working = state;
            for (word, constant) in schedule.iter().zip(SHA256_ROUND_CONSTANTS.iter()) {
                let sigma_one = working[4].rotate_right(6)
                    ^ working[4].rotate_right(11)
                    ^ working[4].rotate_right(25);
                let choose = (working[4] & working[5]) ^ (!working[4] & working[6]);
                let first = working[7]
                    .wrapping_add(sigma_one)
                    .wrapping_add(choose)
                    .wrapping_add(*constant)
                    .wrapping_add(*word);
                let sigma_zero = working[0].rotate_right(2)
                    ^ working[0].rotate_right(13)
                    ^ working[0].rotate_right(22);
                let majority = (working[0] & working[1])
                    ^ (working[0] & working[2])
                    ^ (working[1] & working[2]);
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
            let mut next = state;
            for (slot, value) in next.iter_mut().zip(working.iter()) {
                *slot = slot.wrapping_add(*value);
            }
            next
        }

        /// The FIPS 180-4 padded blocks of `message`.
        pub(super) fn padded_blocks(message: &[u8]) -> Vec<[u8; BLOCK_BYTES]> {
            let mut padded = message.to_vec();
            padded.push(0x80);
            while padded.len() % BLOCK_BYTES != 56 {
                padded.push(0);
            }
            padded.extend_from_slice(&((message.len() as u64) * 8).to_be_bytes());
            padded.as_chunks::<BLOCK_BYTES>().0.to_vec()
        }
    }

    fn random_bytes(seed: &mut u64, length: usize) -> Vec<u8> {
        (0..length)
            .map(|_| {
                *seed ^= *seed << 13;
                *seed ^= *seed >> 7;
                *seed ^= *seed << 17;
                (*seed >> 24) as u8
            })
            .collect()
    }

    fn words<const N: usize>(seed: &mut u64) -> [u32; N] {
        let bytes = random_bytes(seed, N * 4);
        let mut out = [0_u32; N];
        for (slot, chunk) in out.iter_mut().zip(bytes.as_chunks::<4>().0) {
            *slot = u32::from_be_bytes(*chunk);
        }
        out
    }

    fn block(seed: &mut u64) -> [u8; BLOCK_BYTES] {
        random_bytes(seed, BLOCK_BYTES)
            .try_into()
            .expect("one block")
    }

    fn reference_sha1(message: &[u8]) -> [u8; 20] {
        let state = reference::padded_blocks(message)
            .iter()
            .fold(SHA1_INITIAL_STATE, |state, block| {
                reference::sha1_compress(state, block)
            });
        let mut digest = [0_u8; 20];
        for (slot, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(state) {
            *slot = word.to_be_bytes();
        }
        digest
    }

    fn reference_sha256(message: &[u8]) -> [u8; 32] {
        let state = reference::padded_blocks(message)
            .iter()
            .fold(SHA256_INITIAL_STATE, |state, block| {
                reference::sha256_compress(state, block)
            });
        let mut digest = [0_u8; 32];
        for (slot, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(state) {
            *slot = word.to_be_bytes();
        }
        digest
    }

    /// frankengit-0dq9: the unrolled compressions equal the reference cores
    /// on random chaining values and blocks.
    #[test]
    fn unrolled_compression_equals_the_reference_cores() {
        let mut seed = 0x0dd9_5eed_1234_5678_u64;
        for _ in 0..20_000 {
            let block = block(&mut seed);
            let state1: [u32; 5] = words(&mut seed);
            let expected = reference::sha1_compress(state1, &block);
            assert_eq!(super::sha1_rounds(state1, &sha1_schedule(&block)), expected);
            assert_eq!(super::sha1_rounds_streamed(state1, &block), expected);
            let state256: [u32; 8] = words(&mut seed);
            let mut hasher = Sha256Hasher::new();
            hasher.state = state256;
            hasher.compress(&block);
            assert_eq!(hasher.state, reference::sha256_compress(state256, &block));
        }
    }

    /// Every message length from empty to past seventeen blocks, absorbed
    /// whole, byte by byte, and split around block boundaries, digests as the
    /// reference does.
    #[test]
    fn digests_equal_the_reference_for_every_length_and_split() {
        let mut seed = 0x51ed_270b_c6d1_a4e3_u64;
        for length in 0..=1_100 {
            let message = random_bytes(&mut seed, length);
            let expected1 = reference_sha1(&message);
            let expected256 = reference_sha256(&message);
            for splits in [
                vec![],
                vec![1],
                vec![63, 1, 64],
                vec![65, 127],
                vec![length / 2, 3],
            ] {
                let mut hasher1 = Sha1Hasher::new();
                let mut hasher256 = Sha256Hasher::new();
                let mut rest = message.as_slice();
                for split in
                    splits
                        .iter()
                        .copied()
                        .cycle()
                        .take(if splits.is_empty() { 0 } else { 2_000 })
                {
                    if rest.is_empty() {
                        break;
                    }
                    let take = split.max(1).min(rest.len());
                    DigestHasher::update(&mut hasher1, &rest[..take]);
                    DigestHasher::update(&mut hasher256, &rest[..take]);
                    rest = &rest[take..];
                }
                DigestHasher::update(&mut hasher1, rest);
                DigestHasher::update(&mut hasher256, rest);
                assert_eq!(
                    DigestHasher::finish(hasher1),
                    expected1,
                    "{length} {splits:?}"
                );
                assert_eq!(
                    DigestHasher::finish(hasher256),
                    expected256,
                    "{length} {splits:?}"
                );
            }
        }
    }

    struct Recording {
        seen: Vec<(u64, [u32; 5], [u32; 80])>,
        suspect_at: Option<u64>,
    }

    impl BlockObserver for Recording {
        fn observe(&mut self, context: &Sha1BlockContext<'_>) -> BlockVerdict {
            self.seen.push((
                context.block_index,
                context.chaining_value,
                *context.schedule,
            ));
            if self.suspect_at == Some(context.block_index) {
                return BlockVerdict::Suspected(CollisionEvidence {
                    block_index: context.block_index,
                    disturbance_vector: None,
                    detail: "planted",
                });
            }
            BlockVerdict::Clean
        }
    }

    /// The collision hook sees every block in order with the reference
    /// chaining value and full schedule, whatever the chunking, and a suspect
    /// verdict stops absorption at that block.
    #[test]
    fn the_collision_observer_sees_the_reference_blocks_in_order() {
        let mut seed = 0x7777_1234_abcd_0001_u64;
        let message = random_bytes(&mut seed, 10 * BLOCK_BYTES + 17);
        let blocks = reference::padded_blocks(&message);
        let mut expected = Vec::new();
        let mut state = SHA1_INITIAL_STATE;
        for (index, block) in blocks.iter().enumerate() {
            expected.push((index as u64, state, sha1_schedule(block)));
            state = reference::sha1_compress(state, block);
        }
        for chunk in [message.len(), 1, 64, 100] {
            let mut observer = Recording {
                seen: Vec::new(),
                suspect_at: None,
            };
            let mut hasher = Sha1Hasher::new();
            for piece in message.chunks(chunk) {
                assert!(matches!(
                    hasher.update_observed(piece, &mut observer),
                    BlockVerdict::Clean
                ));
            }
            assert_eq!(
                hasher.finish_observed(&mut observer).ok(),
                Some(reference_sha1(&message))
            );
            assert_eq!(observer.seen, expected, "chunk {chunk}");
        }
        for chunk in [message.len(), 1, 64, 100] {
            let mut observer = Recording {
                seen: Vec::new(),
                suspect_at: Some(3),
            };
            let mut hasher = Sha1Hasher::new();
            let mut suspected = false;
            for piece in message.chunks(chunk) {
                if matches!(
                    hasher.update_observed(piece, &mut observer),
                    BlockVerdict::Suspected(_)
                ) {
                    suspected = true;
                    break;
                }
            }
            assert!(suspected, "chunk {chunk}");
            assert_eq!(observer.seen.len(), 4, "chunk {chunk}");
            assert_eq!(observer.seen, expected[..4], "chunk {chunk}");
        }
    }
}
