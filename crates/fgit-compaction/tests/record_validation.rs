#![forbid(unsafe_code)]
//! Every refusal `CompactionRecord::validate` can produce (`frankengit-rqin`).
//!
//! Compaction rewrites history: it replaces a range of decisions with a
//! compacted generation. What makes that safe is the **totality accounting** —
//! every source accounted for exactly once, every declared output actually
//! used, every referenced output actually declared. Before this file, three of
//! the crate's twenty-six constructed refusal variants were named by a test,
//! and none of the eight in this chain.
//!
//! `validate` is an **ordered** chain:
//!
//! ```text
//! 1  DecisionRange::new(first, last)  -> DecisionRangeReversed
//! 2  outputs.validate_shape()         -> OutputLayoutEmpty
//!                                     -> DuplicateOutput{field} (three axes)
//! 3  equivalence_proof.verify()       -> LogicalEquivalenceMismatch
//! 4  totality.validate_shape()        -> TotalityMapEmpty, SourceAccountedMoreThanOnce
//! 5  its own cross-check              -> OutputReferenceUnknown, OutputNotAccountedFor
//! ```
//!
//! # The pair that carries this file
//!
//! Stage 5 is **bidirectional**, and the two halves fail in opposite
//! directions:
//!
//! - `OutputReferenceUnknown` — a totality entry names a pack or manifest the
//!   record never declared. Compaction **inventing** an output.
//! - `OutputNotAccountedFor` — a declared output is never referenced by any
//!   entry. Compaction **losing** an output.
//!
//! Testing one without the other leaves half the invariant unpinned.
//!
//! # Which arms are reachable through `validate`, and which are not
//!
//! Established by reading field visibility, before writing any probe:
//!
//! - `DecisionRange`, `CompactionOutputs` and `LogicalEquivalenceProof` all
//!   have **public fields**, so a record carrying an invalid one is
//!   constructible by struct literal and stages 1, 2, 3 and 5 are genuinely
//!   reachable through `validate`.
//! - `SourceOutputTotalityMap` keeps its entries **private** and validates in
//!   `new`, so by the time `validate` re-checks it the map is already known
//!   good. Stage 4 is therefore **defensive through this path**. Its two arms
//!   are probed through `SourceOutputTotalityMap::new` directly, where they are
//!   reachable, and that is stated rather than papered over.
//!
//! # Ordering
//!
//! Each stage runs only if every earlier one passed, so a probe for a later
//! stage must satisfy the earlier ones. Every probe here starts from
//! [`coherent_record`] and changes exactly one thing;
//! [`the_unmodified_record_validates`] proves that base actually passes, without
//! which every refusal below could be an earlier stage firing.
//!
//! Every probe drives the public API; nothing here modifies
//! `crates/fgit-compaction/src/**`.

use fgit_compaction::{
    CompactionAlgorithm, CompactionOutputs, CompactionProfile, CompactionRecord, CompactionRefusal,
    DecisionRange, LogicalEquivalenceProof, OutputDisposition, SourceEntry,
    SourceOutputTotalityMap, TotalityEntry,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionSequence, Digest, DigestAlgorithmId, DigestBytes, GitOid,
    GitOidSha1, HeadGeneration, RepositoryAuthorityHeadId, SegmentManifestId,
};

/// A corpus-reserved digest algorithm slot. Never a real algorithm identifier.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

macro_rules! derived {
    ($ty:ty, $tag:expr) => {
        <$ty>::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("nonzero corpus fixture algorithm slot"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[$tag; 32]).expect("32-byte corpus fixture body"),
        )
    };
}

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

const fn object(tag: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([tag; GitOidSha1::LEN]))
}

fn manifest(tag: u8) -> SegmentManifestId {
    derived!(SegmentManifestId, tag)
}

/// A record that passes every stage of the chain.
///
/// One pack, one manifest, one index root, and two totality entries: one source
/// stored into that pack and manifest, one documented drop. Every declared
/// output is referenced, and every reference resolves.
fn coherent_record() -> CompactionRecord {
    CompactionRecord {
        input_head: derived!(RepositoryAuthorityHeadId, 0x10),
        input_head_generation: HeadGeneration::FIRST,
        decision_range: DecisionRange::new(DecisionSequence::FIRST, DecisionSequence::FIRST)
            .expect("one decision is an increasing range"),
        input_segment_root: digest(0x20),
        input_decision_root: digest(0x21),
        algorithm: CompactionAlgorithm::DeterministicReencodeV1,
        profile: CompactionProfile::ConservativeInterimV1,
        toolchain_fingerprint: digest(0x22),
        outputs: CompactionOutputs {
            pack_roots: vec![digest(0x30)],
            segment_manifests: vec![manifest(0x51)],
            index_roots: vec![digest(0x31)],
        },
        equivalence_proof: LogicalEquivalenceProof::construct(
            digest(0x40),
            digest(0x40),
            digest(0x41),
        )
        .expect("equal reconstructed logical roots prove equivalence"),
        totality: SourceOutputTotalityMap::new(vec![
            TotalityEntry {
                source: SourceEntry::Object(object(0x73)),
                disposition: OutputDisposition::Stored {
                    pack_root: digest(0x30),
                    segment_manifest: manifest(0x51),
                },
            },
            TotalityEntry {
                source: SourceEntry::Decision(DecisionSequence::FIRST),
                disposition: OutputDisposition::DocumentedDrop {
                    evidence_root: digest(0x42),
                },
            },
        ])
        .expect("each source is accounted for once"),
        resource_receipt_root: digest(0x43),
        rejected_layout_evidence_root: digest(0x44),
    }
}

/// The base passes every stage.
///
/// Without this, each refusal below could be an earlier stage firing on a
/// broken fixture rather than the stage the test is named for.
#[test]
fn the_unmodified_record_validates() {
    coherent_record()
        .validate()
        .expect("the base fixture must satisfy every stage of the chain");
}

// ---------------------------------------------------------------------------
// Stage 1 — the decision range
// ---------------------------------------------------------------------------

/// A record whose decision range runs backwards is refused.
///
/// Constructed by struct literal: `DecisionRange` has public fields, so an
/// invalid range can exist in a record even though `DecisionRange::new` refuses
/// to build one. That is exactly why `validate` re-checks it.
#[test]
fn a_reversed_decision_range_is_refused() {
    let mut record = coherent_record();
    record.decision_range = DecisionRange {
        first: DecisionSequence::FIRST.next().expect("a second sequence"),
        last: DecisionSequence::FIRST,
    };
    let refusal = record
        .validate()
        .expect_err("a range whose last precedes its first covers nothing");
    assert!(
        matches!(refusal, CompactionRefusal::DecisionRangeReversed),
        "a reversed range must refuse as itself, got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// Stage 2 — output layout shape
// ---------------------------------------------------------------------------

/// A record declaring no output packs is refused.
///
/// Passes stage 1. `OutputLayoutEmpty` guards two fields; this is the pack half.
#[test]
fn a_record_declaring_no_output_packs_is_refused() {
    let mut record = coherent_record();
    record.outputs.pack_roots.clear();
    let refusal = record
        .validate()
        .expect_err("a compaction producing no output packs has produced nothing");
    assert!(
        matches!(refusal, CompactionRefusal::OutputLayoutEmpty),
        "an empty pack list must refuse as an empty layout, got {refusal:?}"
    );
}

/// The second field the same guard covers: no segment manifests.
///
/// Probed separately because one guard covering two fields is two axes, and a
/// probe emptying only one leaves the other unexercised.
#[test]
fn a_record_declaring_no_segment_manifests_is_refused() {
    let mut record = coherent_record();
    record.outputs.segment_manifests.clear();
    let refusal = record
        .validate()
        .expect_err("a layout with no segment manifests cannot describe its packs");
    assert!(
        matches!(refusal, CompactionRefusal::OutputLayoutEmpty),
        "an empty manifest list must refuse as an empty layout, got {refusal:?}"
    );
}

/// A duplicated pack root is refused, and the refusal names the field.
///
/// The field label is asserted because one variant covers three lists, and a
/// guard reporting the wrong list would otherwise pass.
#[test]
fn a_duplicated_pack_root_is_refused_naming_that_field() {
    let mut record = coherent_record();
    record.outputs.pack_roots.push(digest(0x30));
    let refusal = record
        .validate()
        .expect_err("one pack root declared twice is not a layout");
    assert!(
        matches!(
            refusal,
            CompactionRefusal::DuplicateOutput {
                field: "pack_roots"
            }
        ),
        "a duplicate pack root must name pack_roots, got {refusal:?}"
    );
}

/// The second axis of the same variant.
#[test]
fn a_duplicated_segment_manifest_is_refused_naming_that_field() {
    let mut record = coherent_record();
    record.outputs.segment_manifests.push(manifest(0x51));
    let refusal = record
        .validate()
        .expect_err("one segment manifest declared twice is not a layout");
    assert!(
        matches!(
            refusal,
            CompactionRefusal::DuplicateOutput {
                field: "segment_manifests"
            }
        ),
        "a duplicate manifest must name segment_manifests, got {refusal:?}"
    );
}

/// The third axis. Index roots are rebuildable, but a duplicate still indicates
/// a layout the record cannot describe honestly.
#[test]
fn a_duplicated_index_root_is_refused_naming_that_field() {
    let mut record = coherent_record();
    record.outputs.index_roots.push(digest(0x31));
    let refusal = record
        .validate()
        .expect_err("one index root declared twice is not a layout");
    assert!(
        matches!(
            refusal,
            CompactionRefusal::DuplicateOutput {
                field: "index_roots"
            }
        ),
        "a duplicate index root must name index_roots, got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// Stage 3 — logical equivalence
// ---------------------------------------------------------------------------

/// A record whose outputs reconstruct a different logical root than its inputs
/// is refused.
///
/// This is the obligation that compaction preserved meaning, not merely bytes.
/// Constructed by struct literal because `LogicalEquivalenceProof::construct`
/// refuses to build a mismatched proof — which is why `validate` re-verifies
/// one it was handed.
#[test]
fn a_proof_whose_roots_disagree_is_refused() {
    let mut record = coherent_record();
    record.equivalence_proof = LogicalEquivalenceProof {
        source_logical_root: digest(0x40),
        output_logical_root: digest(0x45),
        proof_root: digest(0x41),
    };
    let refusal = record
        .validate()
        .expect_err("outputs reconstructing a different logical root are not equivalent");
    assert!(
        matches!(refusal, CompactionRefusal::LogicalEquivalenceMismatch),
        "disagreeing logical roots must refuse as an equivalence mismatch, got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// Stage 4 — probed at its own constructor, where it is reachable
// ---------------------------------------------------------------------------

/// An empty totality map is refused at construction.
///
/// Probed through `SourceOutputTotalityMap::new` rather than through
/// `validate`: the map keeps its entries private and validates in `new`, so by
/// the time `validate` re-checks it the map is already known good. The arm
/// inside `validate` is defensive through that path.
#[test]
fn an_empty_totality_map_is_refused_at_construction() {
    let refusal = SourceOutputTotalityMap::new(Vec::new())
        .expect_err("a compaction accounting for no sources accounts for nothing");
    assert!(
        matches!(refusal, CompactionRefusal::TotalityMapEmpty),
        "an empty map must refuse as itself, got {refusal:?}"
    );
}

/// One source accounted for twice is refused at construction.
///
/// This is the half of the totality invariant that stops a source being
/// double-counted, which would let a compaction claim to have retained
/// something it dropped.
#[test]
fn a_source_accounted_for_twice_is_refused_at_construction() {
    let entry = || TotalityEntry {
        source: SourceEntry::Object(object(0x73)),
        disposition: OutputDisposition::Stored {
            pack_root: digest(0x30),
            segment_manifest: manifest(0x51),
        },
    };
    let refusal = SourceOutputTotalityMap::new(vec![entry(), entry()])
        .expect_err("one source accounted for twice is not an accounting");
    assert!(
        matches!(
            refusal,
            CompactionRefusal::SourceAccountedMoreThanOnce { .. }
        ),
        "a repeated source must refuse as itself, got {refusal:?}"
    );
}

/// The permitted twin for both stage-4 arms: distinct sources build a map.
///
/// Without it, the two refusals are consistent with a constructor that rejects
/// every map.
#[test]
fn a_map_of_distinct_sources_is_admitted() {
    SourceOutputTotalityMap::new(vec![
        TotalityEntry {
            source: SourceEntry::Object(object(0x73)),
            disposition: OutputDisposition::DocumentedDrop {
                evidence_root: digest(0x42),
            },
        },
        TotalityEntry {
            source: SourceEntry::Object(object(0x74)),
            disposition: OutputDisposition::DocumentedDrop {
                evidence_root: digest(0x42),
            },
        },
    ])
    .expect("distinct sources each accounted for once must build a map");
}

// ---------------------------------------------------------------------------
// Stage 5 — the bidirectional accounting, both directions
// ---------------------------------------------------------------------------

/// **Compaction inventing an output.** A totality entry naming a pack the record
/// never declared is refused.
///
/// Passes stages 1 to 4: the layout is well formed, the proof agrees, and the
/// map is internally consistent. Only the cross-reference fails.
#[test]
fn a_totality_entry_naming_an_undeclared_pack_is_refused() {
    let mut record = coherent_record();
    record.totality = SourceOutputTotalityMap::new(vec![TotalityEntry {
        source: SourceEntry::Object(object(0x73)),
        disposition: OutputDisposition::Stored {
            pack_root: digest(0x99),
            segment_manifest: manifest(0x51),
        },
    }])
    .expect("a single source accounted once is a well-formed map");

    let refusal = record
        .validate()
        .expect_err("an entry may not name an output the record never declared");
    assert!(
        matches!(refusal, CompactionRefusal::OutputReferenceUnknown),
        "an unknown output reference must refuse as itself, got {refusal:?}"
    );
}

/// **Compaction losing an output.** A declared pack that no entry references is
/// refused.
///
/// The opposite direction of the same invariant, and the reason both halves are
/// needed: this record's references all resolve, so the previous guard is
/// silent here.
#[test]
fn a_declared_pack_no_entry_references_is_refused() {
    let mut record = coherent_record();
    record.outputs.pack_roots.push(digest(0x32));

    let refusal = record
        .validate()
        .expect_err("a declared output that nothing accounts for has been lost");
    assert!(
        matches!(refusal, CompactionRefusal::OutputNotAccountedFor),
        "an unreferenced declared output must refuse as unaccounted, got {refusal:?}"
    );
}

/// The same, for the manifest half of the accounting.
///
/// `used_segments != segments` is a separate comparison from `used_packs !=
/// packs`, so a probe exercising only the pack side leaves this one unpinned.
#[test]
fn a_declared_manifest_no_entry_references_is_refused() {
    let mut record = coherent_record();
    record.outputs.segment_manifests.push(manifest(0x52));

    let refusal = record
        .validate()
        .expect_err("a declared manifest that nothing accounts for has been lost");
    assert!(
        matches!(refusal, CompactionRefusal::OutputNotAccountedFor),
        "an unreferenced declared manifest must refuse as unaccounted, got {refusal:?}"
    );
}

/// The two halves of stage 5 are told apart, not merely both refused.
///
/// Both inputs refuse; what is asserted is that they refuse for *different*
/// reasons. Collapsing them would hide either direction — an invented output
/// and a lost one are opposite faults.
#[test]
fn inventing_and_losing_an_output_refuse_differently() {
    let mut inventing = coherent_record();
    inventing.totality = SourceOutputTotalityMap::new(vec![TotalityEntry {
        source: SourceEntry::Object(object(0x73)),
        disposition: OutputDisposition::Stored {
            pack_root: digest(0x99),
            segment_manifest: manifest(0x51),
        },
    }])
    .expect("well-formed map");

    let mut losing = coherent_record();
    losing.outputs.pack_roots.push(digest(0x32));

    let invented = inventing.validate().expect_err("inventing must refuse");
    let lost = losing.validate().expect_err("losing must refuse");

    assert!(
        matches!(invented, CompactionRefusal::OutputReferenceUnknown),
        "got {invented:?}"
    );
    assert!(
        matches!(lost, CompactionRefusal::OutputNotAccountedFor),
        "got {lost:?}"
    );
}
