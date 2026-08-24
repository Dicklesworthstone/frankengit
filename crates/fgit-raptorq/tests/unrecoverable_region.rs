#![forbid(unsafe_code)]
//! The profile's repair envelope has an explicit, typed terminal verdict.
//!
//! The paired cases deliberately use the same protected segment.  Keeping all
//! eight repair symbols and losing eight source symbols is within the declared
//! envelope; losing one more source leaves fewer than the source-symbol count
//! even after every repair symbol was accepted, which is a proven
//! `UnrecoverableRegion`, not a generic decoder failure.

use asupersync::security::SecurityContext;
use fgit_object_fabric::{
    CryptoDigest, DigestAlgorithm, MicrosegmentBuilder, ObjectEnvelope, ObjectKind, SegmentLimits,
    SegmentRecordInput,
};
use fgit_raptorq::{
    MicrosegmentRaptorProfile, ProtectedMicrosegment, RaptorRefusal, ScopedSymbol,
    protect_microsegment, reconstruct_microsegment,
};
use fgit_types::{GitOid, GitOidSha1};

fn security() -> SecurityContext {
    SecurityContext::for_testing(0xB0AD)
}

fn canonical_segment(payload: &[u8]) -> Vec<u8> {
    let limits = SegmentLimits::default();
    let digest = CryptoDigest;
    let envelope = ObjectEnvelope::new(
        b"unrecoverable-region".to_vec(),
        GitOid::Sha1(GitOidSha1::from_bytes([0xB0; GitOidSha1::LEN])),
        ObjectKind::Blob,
        u64::try_from(payload.len()).expect("payload length fits u64"),
        digest
            .payload_commitment(ObjectKind::Blob, payload)
            .expect("payload has a native commitment"),
        b"canonical-codec".to_vec(),
        [0xCD; 32],
        None,
        &limits,
    )
    .expect("envelope is canonical");
    let mut builder = MicrosegmentBuilder::new(&digest, limits);
    builder
        .push(SegmentRecordInput {
            envelope,
            payload: payload.to_vec(),
        })
        .expect("record is canonical");
    builder
        .build()
        .expect("microsegment builds")
        .as_bytes()
        .to_vec()
}

fn protect(bytes: &[u8]) -> ProtectedMicrosegment {
    protect_microsegment(bytes, &SegmentLimits::default(), &security())
        .expect("canonical microsegment is profile-admitted")
}

fn source_symbol_count(protected: &ProtectedMicrosegment) -> usize {
    protected
        .symbols()
        .iter()
        .filter(|scoped| scoped.symbol().kind().is_source())
        .count()
}

fn drop_source_symbols(protected: &ProtectedMicrosegment, count: u32) -> Vec<ScopedSymbol> {
    protected
        .symbols()
        .iter()
        .filter(|scoped| {
            !(scoped.symbol().kind().is_source() && scoped.symbol().id().esi() < count)
        })
        .cloned()
        .collect()
}

#[test]
fn repair_envelope_has_a_permitted_twin_and_a_typed_beyond_budget_verdict() {
    // This intentionally makes a source block larger than the eight-symbol
    // repair budget, so both sides exercise the same non-vacuous boundary.
    let bytes = canonical_segment(&vec![0x5A; 4 * 1024]);
    let protected = protect(&bytes);
    let source_symbols = source_symbol_count(&protected);
    let repair_symbols = MicrosegmentRaptorProfile::REPAIR_SYMBOLS;
    assert!(
        source_symbols > repair_symbols,
        "the fixture must retain source symbols after an envelope-sized loss"
    );

    let within_budget = drop_source_symbols(
        &protected,
        u32::try_from(repair_symbols).expect("repair budget fits u32"),
    );
    let verified = reconstruct_microsegment(
        protected.scope(),
        &within_budget,
        &SegmentLimits::default(),
        &security(),
    )
    .expect("losing exactly the declared repair budget reconstructs");
    assert_eq!(
        verified.bytes(),
        bytes,
        "the permitted twin is byte-identical"
    );

    let beyond_budget = drop_source_symbols(
        &protected,
        u32::try_from(repair_symbols + 1).expect("repair budget plus one fits u32"),
    );
    let refusal = reconstruct_microsegment(
        protected.scope(),
        &beyond_budget,
        &SegmentLimits::default(),
        &security(),
    )
    .expect_err("all repair symbols cannot recover one additional source loss");

    match refusal {
        RaptorRefusal::UnrecoverableRegion {
            scope,
            symbols_available,
            symbols_required,
            repair_budget_consumed,
        } => {
            assert_eq!(scope, *protected.scope(), "the verdict names this region");
            assert_eq!(
                symbols_available,
                source_symbols - 1,
                "the decoder proves that one independent symbol remains missing"
            );
            assert_eq!(
                symbols_required,
                u16::try_from(source_symbols).expect("profile count fits u16")
            );
            assert_eq!(
                repair_budget_consumed, repair_symbols,
                "the typed verdict is reserved for an exhausted repair envelope"
            );
        }
        RaptorRefusal::DecodeFailed => {
            panic!("the proven beyond-budget path must not collapse into DecodeFailed")
        }
        other => panic!("expected UnrecoverableRegion, got {other:?}"),
    }
}
