#![forbid(unsafe_code)]
//! A deliberately dispersed object set for the first-clone ordering seam.
//!
//! Four independently seeded binary files have eight closely related versions
//! each. Their real native IDs fall into successive even high-nibble bands;
//! 33 unrelated small blobs occupy each intervening odd band. This makes the
//! all-zero-hint order miss every related version under V5's 32-entry window.
//! A bounded nonce search changes actual blob bytes to select each band; no
//! claimed ID is substituted for the hash of those bytes.
//!
//! The candidate changes only basename hints. Both arms use the frozen V5
//! profile, the native deterministic encoder, the streamed writer, and the
//! same exact objects. Native unpacking then reconstructs and rehashes every
//! object without taking identities or types from a pack plan.
//!
//! This is a synthetic component regression, not a whole-repository clone
//! benchmark. The ignored A/B/A measurement excludes fixture/key preparation
//! and includes streamed materialization into memory. It has no timing gates
//! and makes no claim about network, disk, RSS, or multi-gigabyte clone speed.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use fgit_git_object::ObjectType;
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, DeterministicPackEncoder, NativeChecksumVerifier,
    ObjectFormat, ObjectId, PackArtifactSink, PackLimits, PackOrderKey, PackOrderingSource,
    PackPlanner, PackWriteError, PackWriteProfile, PackWriteReceipt, PackWriter, ParsedDeltaBase,
    ScalarResolver, basename_path_hash, read_verified_pack,
};

const PROFILE: PackWriteProfile = PackWriteProfile::COMPRESSED_V5;
const VERSIONS: usize = 8;
const VERSION_BYTES: usize = 16 * 1024;
const INTERVENING_BLOBS: usize = 33;
const NOISE_BYTES: usize = 64;
const NONCE_ATTEMPTS: u64 = 4096;
const FAMILY_SEEDS: [u64; 4] = [
    0x243f_6a88_85a3_08d3,
    0x1319_8a2e_0370_7344,
    0xa409_3822_299f_31d0,
    0x082e_fa98_ec4e_6c89,
];
const BASENAMES: [&[u8]; 4] = [b"atlas.bin", b"bravo.bin", b"charlie.bin", b"delta.bin"];

struct FixtureBlob {
    body: Vec<u8>,
    basename: Vec<u8>,
    family: Option<usize>,
}

struct Fixture {
    format: ObjectFormat,
    blobs: BTreeMap<ObjectId, FixtureBlob>,
}

impl CanonicalObjectSource for Fixture {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        let blob = self
            .blobs
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            *id,
            ObjectType::Blob,
            blob.body.clone(),
            Vec::new(),
            0,
            0,
        ))
    }
}

impl Fixture {
    fn new(format: ObjectFormat) -> Self {
        let mut blobs = BTreeMap::new();
        for (family, seed) in FAMILY_SEEDS.into_iter().enumerate() {
            let original = random_bytes(seed, VERSION_BYTES);
            for version in 0..VERSIONS {
                let mut body = original.clone();
                let edit = random_bytes(seed ^ (version as u64 + 1), 64);
                let start = 256 + version * 128;
                body[start..start + edit.len()].copy_from_slice(&edit);
                let (id, body) = blob_in_band(format, body, version * 2);
                assert!(
                    blobs
                        .insert(
                            id,
                            FixtureBlob {
                                body,
                                basename: BASENAMES[family].to_vec(),
                                family: Some(family),
                            },
                        )
                        .is_none(),
                    "the fixture must contain distinct native objects"
                );
            }
        }
        for gap in 0..VERSIONS - 1 {
            for index in 0..INTERVENING_BLOBS {
                let ordinal = gap * INTERVENING_BLOBS + index;
                let seed = 0x4528_21e6_38d0_1377_u64
                    .wrapping_add((ordinal as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
                let (id, body) = blob_in_band(format, random_bytes(seed, NOISE_BYTES), gap * 2 + 1);
                assert!(
                    blobs
                        .insert(
                            id,
                            FixtureBlob {
                                body,
                                basename: format!("unrelated-{gap:02}-{index:02}.bin").into_bytes(),
                                family: None,
                            },
                        )
                        .is_none(),
                    "the unrelated objects must also have distinct native identities"
                );
            }
        }
        let fixture = Self { format, blobs };
        fixture.assert_identity_and_spread();
        fixture
    }

    fn assert_identity_and_spread(&self) {
        assert_eq!(PROFILE.delta_window, 32);
        assert_eq!(PROFILE.delta_window_bytes, Some(128 * 1024 * 1024));
        const { assert!(INTERVENING_BLOBS > PROFILE.delta_window) };
        assert_eq!(
            self.blobs.len(),
            FAMILY_SEEDS.len() * VERSIONS + (VERSIONS - 1) * INTERVENING_BLOBS
        );
        for (id, blob) in &self.blobs {
            assert_eq!(
                *id,
                fgit_crypto::git_object_id(self.format, ObjectType::Blob, &blob.body),
                "ordering metadata must never stand in for a native object identity"
            );
        }
        // With zero hints all blobs have the same type/recency/path key, so
        // BTreeMap's native-ID order is exactly the baseline emission order.
        for family in 0..FAMILY_SEEDS.len() {
            let positions: Vec<usize> = self
                .blobs
                .values()
                .enumerate()
                .filter_map(|(index, blob)| (blob.family == Some(family)).then_some(index))
                .collect();
            assert_eq!(positions.len(), VERSIONS);
            for adjacent in positions.windows(2) {
                assert!(
                    adjacent[1] - adjacent[0] > INTERVENING_BLOBS,
                    "related native IDs must lie beyond the actual frozen delta window"
                );
            }
        }
        let family_hashes: BTreeSet<u64> = BASENAMES.into_iter().map(basename_path_hash).collect();
        assert_eq!(family_hashes.len(), FAMILY_SEEDS.len());
    }

    fn keys(&self, grouped: bool) -> BTreeMap<ObjectId, PackOrderKey> {
        self.blobs
            .iter()
            .map(|(id, blob)| {
                (
                    *id,
                    PackOrderKey {
                        id: *id,
                        object_type: ObjectType::Blob,
                        recency: 0,
                        path_hash: if grouped {
                            basename_path_hash(&blob.basename)
                        } else {
                            0
                        },
                    },
                )
            })
            .collect()
    }

    fn input_bytes(&self) -> usize {
        self.blobs.values().map(|blob| blob.body.len()).sum()
    }
}

fn random_bytes(mut state: u64, length: usize) -> Vec<u8> {
    (0..length)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            (state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

fn blob_in_band(
    format: ObjectFormat,
    mut body: Vec<u8>,
    high_nibble: usize,
) -> (ObjectId, Vec<u8>) {
    let original = u64::from_le_bytes(body[..8].try_into().expect("eight nonce bytes"));
    for attempt in 0..NONCE_ATTEMPTS {
        // Mix the nonce into existing random bytes: unrelated blobs should
        // not gain a shared zero-filled prefix from the fixture generator.
        let nonce = original ^ attempt.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        body[..8].copy_from_slice(&nonce.to_le_bytes());
        let id = fgit_crypto::git_object_id(format, ObjectType::Blob, &body);
        if usize::from(id.as_bytes()[0] >> 4) == high_nibble {
            return (id, body);
        }
    }
    panic!("bounded fixture nonce search exhausted for {format:?} band {high_nibble}");
}

fn limits() -> PackLimits {
    PackLimits {
        max_input_bytes: 4 * 1024 * 1024,
        max_entries: 1024,
        max_object_bytes: 64 * 1024,
        max_total_expanded_bytes: 8 * 1024 * 1024,
        ..PackLimits::default()
    }
}

#[derive(Default)]
struct MemorySink {
    promoted: Option<Vec<u8>>,
}

impl PackArtifactSink for MemorySink {
    type Temporary = Vec<u8>;

    fn create_temporary(&mut self) -> Result<Self::Temporary, PackWriteError> {
        Ok(Vec::new())
    }

    fn write_temporary(
        &mut self,
        temporary: &mut Self::Temporary,
        bytes: &[u8],
    ) -> Result<(), PackWriteError> {
        temporary.extend_from_slice(bytes);
        Ok(())
    }

    fn promote_temporary(&mut self, temporary: &mut Self::Temporary) -> Result<(), PackWriteError> {
        assert!(self.promoted.is_none());
        self.promoted = Some(std::mem::take(temporary));
        Ok(())
    }

    fn abort_temporary(&mut self, _temporary: Self::Temporary) {}
}

struct WrittenPack {
    bytes: Vec<u8>,
    receipt: PackWriteReceipt,
}

fn write_pack(
    fixture: &Fixture,
    keys: &BTreeMap<ObjectId, PackOrderKey>,
    selected: &[ObjectId],
) -> WrittenPack {
    let lookup = |id: &ObjectId| keys.get(id).copied();
    let source = PackOrderingSource::new(fixture, &lookup);
    let order: Vec<PackOrderKey> = selected.iter().map(|id| keys[id]).collect();
    let planner = PackPlanner::new(fixture.format, PROFILE, limits());
    let writer = PackWriter::new(limits());
    let mut encoder = DeterministicPackEncoder::for_profile(PROFILE);
    let mut sink = MemorySink::default();
    let receipt = planner
        .stream_selected_thin(
            &source,
            &order,
            &[],
            &writer,
            &mut encoder,
            &mut sink,
            &mut || true,
        )
        .expect("native V5 streamed materialization");
    let bytes = sink.promoted.expect("only a promoted pack is consumable");
    assert_eq!(receipt.profile, PROFILE);
    assert_eq!(receipt.object_count as usize, fixture.blobs.len());
    assert_eq!(receipt.total_object_bytes, fixture.input_bytes());
    assert_eq!(receipt.output_bytes, bytes.len());
    WrittenPack { bytes, receipt }
}

fn assert_exact_native_roundtrip(fixture: &Fixture, written: &WrittenPack) {
    let limits = limits();
    let pack = read_verified_pack(
        &written.bytes,
        fixture.format,
        &limits,
        &mut || true,
        &NativeChecksumVerifier,
    )
    .expect("native reader must authenticate and inflate the emitted pack");
    assert_eq!(pack.trailer, written.receipt.checksum);
    assert_eq!(pack.entries().len(), fixture.blobs.len());
    assert_eq!(
        pack.entries()
            .iter()
            .filter(|entry| entry.delta_base.is_some())
            .count(),
        written.receipt.delta_count
    );
    let mut positions_and_depths = BTreeMap::new();
    let mut offsets = Vec::new();
    for (index, entry) in pack.entries().iter().enumerate() {
        let depth = match &entry.delta_base {
            None => 0,
            Some(ParsedDeltaBase::Ofs { base_offset, .. }) => {
                let (base_index, base_depth) = positions_and_depths[base_offset];
                assert!(index - base_index <= PROFILE.delta_window);
                base_depth + 1
            }
            Some(ParsedDeltaBase::Ref { .. }) => panic!("this cold pack must be self-contained"),
        };
        assert!(depth <= PROFILE.max_delta_depth);
        positions_and_depths.insert(entry.offset, (index, depth));
        offsets.push(entry.offset);
    }
    // There is deliberately no plan-derived offset-to-ID association. OFS
    // reconstruction supplies the native kind; hashing the result supplies ID.
    let objects = pack.into_scalar_objects(|_| None).expect("scalar entries");
    let resolver =
        ScalarResolver::new(&objects, &(), &limits, &mut || true).expect("native resolver");
    let mut actual = BTreeMap::new();
    for offset in offsets {
        let (kind, body) = resolver
            .resolve_offset_typed(offset, &mut || true)
            .expect("reconstruct the exact native object");
        let id = fgit_crypto::git_object_id(fixture.format, kind, &body);
        assert!(
            actual.insert(id, (kind, body)).is_none(),
            "every requested native object must occur exactly once"
        );
    }
    let expected: BTreeMap<_, _> = fixture
        .blobs
        .iter()
        .map(|(id, blob)| (*id, (ObjectType::Blob, blob.body.clone())))
        .collect();
    assert_eq!(actual, expected);
}

fn assert_grouping_recovers_deltas(baseline: &WrittenPack, grouped: &WrittenPack) {
    assert_eq!(
        baseline.receipt.delta_count, 0,
        "the all-zero hints must leave related versions outside the frozen window"
    );
    assert!(
        grouped.receipt.delta_count >= FAMILY_SEEDS.len() * (VERSIONS - 1),
        "basename grouping must recover deltas for the related versions"
    );
    assert!(
        grouped.bytes.len() * 2 < baseline.bytes.len(),
        "grouping must materially reduce emitted bytes: {} vs {}",
        grouped.bytes.len(),
        baseline.bytes.len()
    );
}

fn exercise_format(format: ObjectFormat) {
    let fixture = Fixture::new(format);
    let zero_keys = fixture.keys(false);
    let grouped_keys = fixture.keys(true);
    let selected: Vec<_> = fixture.blobs.keys().copied().collect();
    let baseline = write_pack(&fixture, &zero_keys, &selected);
    let grouped = write_pack(&fixture, &grouped_keys, &selected);
    assert_grouping_recovers_deltas(&baseline, &grouped);
    assert_exact_native_roundtrip(&fixture, &baseline);
    assert_exact_native_roundtrip(&fixture, &grouped);

    let repeat = write_pack(&fixture, &grouped_keys, &selected);
    assert_eq!(repeat.bytes, grouped.bytes);
    assert_eq!(repeat.receipt, grouped.receipt);
    let reversed: Vec<_> = selected.into_iter().rev().collect();
    let reordered = write_pack(&fixture, &grouped_keys, &reversed);
    assert_eq!(reordered.bytes, grouped.bytes);
    assert_eq!(reordered.receipt, grouped.receipt);
}

#[test]
fn basename_grouping_recovers_dispersed_versions_sha1() {
    exercise_format(ObjectFormat::Sha1);
}

#[test]
fn basename_grouping_recovers_dispersed_versions_sha256() {
    exercise_format(ObjectFormat::Sha256);
}

/// Run with `cargo test -p fgit-pack --test path_grouping -- --ignored --nocapture`.
/// Every sample creates a new planner/encoder with no pack computation cache.
/// A/A brackets B in each round; fixture preparation and native verification
/// are outside the timed region. Raw elapsed samples are evidence, not gates.
#[test]
#[ignore = "reports native V5 materialization samples for interleaved zero/basename/zero hints"]
fn measure_basename_grouping_interleaved_a_b_a() {
    eprintln!("format,round,arm,objects,input_bytes,deltas,output_bytes,elapsed_ns");
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let fixture = Fixture::new(format);
        let selected: Vec<_> = fixture.blobs.keys().copied().collect();
        let zero_keys = fixture.keys(false);
        let grouped_keys = fixture.keys(true);
        let mut control: Option<WrittenPack> = None;
        let mut candidate: Option<WrittenPack> = None;
        for round in 0..3 {
            for (label, grouped, keys) in [
                ("a_before", false, &zero_keys),
                ("b_basename", true, &grouped_keys),
                ("a_after", false, &zero_keys),
            ] {
                let start = Instant::now();
                let written = write_pack(&fixture, keys, &selected);
                let elapsed = start.elapsed();
                eprintln!(
                    "{format:?},{round},{label},{},{},{},{},{}",
                    written.receipt.object_count,
                    written.receipt.total_object_bytes,
                    written.receipt.delta_count,
                    written.receipt.output_bytes,
                    elapsed.as_nanos(),
                );
                let first = if grouped {
                    &mut candidate
                } else {
                    &mut control
                };
                if let Some(previous) = first {
                    assert_eq!(written.bytes, previous.bytes);
                    assert_eq!(written.receipt, previous.receipt);
                } else {
                    assert_exact_native_roundtrip(&fixture, &written);
                    *first = Some(written);
                }
            }
        }
        assert_grouping_recovers_deltas(
            control.as_ref().expect("measured zero-hint control"),
            candidate.as_ref().expect("measured basename candidate"),
        );
    }
}
