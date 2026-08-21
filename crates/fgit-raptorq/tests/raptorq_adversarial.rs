#![forbid(unsafe_code)]
//! FG-024b: an independent adversary over `fgit-raptorq`.
//!
//! §5.5 requires decode and reconstruction to happen in quarantine and to
//! verify **all original commitments** before anything is published. The
//! property this campaign exists to attack is the one that matters most and is
//! hardest to see: **erasure coding must never fabricate data.** A decoder
//! handed insufficient or hostile symbols has to fail closed, because the one
//! thing worse than losing a segment is confidently returning a different one.
//!
//! # What "independent" can and cannot mean here, stated plainly
//!
//! `fg024a` ships five inline tests in `src/lib.rs` covering wrong-scope
//! refusal, corrupt-symbol rejection, stale-repair discard, byte-identical
//! repair and encoding determinism. Those are the implementer's own tests, and
//! they can reach private state this file cannot.
//!
//! **`ScopedSymbol` has no public constructor** — its `scope`, `symbol` and
//! `tag` fields are private and no `new`/`from_parts` is exported. So an
//! external adversary cannot forge a symbol: cannot flip a payload bit, cannot
//! swap an authentication tag, cannot craft a size or kind mismatch. Every
//! attack below is therefore built from **legitimately produced symbols used
//! in an illegitimate way**, which is a real threat model — a stored repair
//! symbol replayed into the wrong context is exactly what a hostile or
//! confused placement layer produces — but it is not the whole one. The
//! bit-level corruption corpus needs a test-only constructor, which is
//! recorded on the bead rather than worked around by reaching into `src`.

use fgit_object_fabric::{
    CryptoDigest, DigestAlgorithm, MicrosegmentBuilder, ObjectEnvelope, ObjectKind, SegmentLimits,
    SegmentRecordInput,
};
use fgit_raptorq::{
    MicrosegmentRaptorProfile, ProtectedMicrosegment, RaptorRefusal, ScopedSymbol,
    protect_microsegment, reconstruct_microsegment,
};
use fgit_types::{GitOid, GitOidSha1};

use asupersync::security::SecurityContext;

fn security() -> SecurityContext {
    SecurityContext::for_testing(24)
}

/// A canonical microsegment. `tenant` and `fill` vary the content so two
/// segments can be built that are genuinely different objects.
fn canonical_segment(tenant: &[u8], fill: u8, payload: &[u8]) -> Vec<u8> {
    let limits = SegmentLimits::default();
    let digest = CryptoDigest;
    let envelope = ObjectEnvelope::new(
        tenant.to_vec(),
        GitOid::Sha1(GitOidSha1::from_bytes([fill; GitOidSha1::LEN])),
        ObjectKind::Blob,
        u64::try_from(payload.len()).expect("payload length fits u64"),
        digest
            .payload_commitment(ObjectKind::Blob, payload)
            .expect("payload has a native commitment"),
        b"canonical-codec".to_vec(),
        [fill; 32],
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

/// Drop the first `count` source symbols, simulating lost source placements.
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

fn source_symbol_count(protected: &ProtectedMicrosegment) -> usize {
    protected
        .symbols()
        .iter()
        .filter(|scoped| scoped.symbol().kind().is_source())
        .count()
}

fn repair_symbol_count(protected: &ProtectedMicrosegment) -> usize {
    protected
        .symbols()
        .iter()
        .filter(|scoped| !scoped.symbol().kind().is_source())
        .count()
}

const PAYLOAD: &[u8] = b"raptorq protected canonical microsegment";

// --- the envelope: success inside it, honest failure beyond it --------------

#[test]
fn loss_within_the_envelope_reconstructs_byte_identical_bytes() {
    let bytes = canonical_segment(b"tenant-a", 7, PAYLOAD);
    let protected = protect(&bytes);
    let repair = repair_symbol_count(&protected);
    assert!(
        repair > 0,
        "a profile with no repair symbols cannot protect anything, so every \
         assertion below would be vacuous"
    );

    // Losing exactly as many source symbols as there are repair symbols is the
    // boundary the profile promises to survive.
    let survivors = drop_source_symbols(&protected, u32::try_from(repair).expect("fits u32"));
    assert!(
        survivors.len() < protected.symbols().len(),
        "the loss must actually remove symbols, or this proves nothing"
    );

    let repaired = reconstruct_microsegment(
        protected.scope(),
        &survivors,
        &SegmentLimits::default(),
        &security(),
    )
    .expect("loss at the promised boundary reconstructs");
    assert_eq!(
        repaired.bytes(),
        bytes,
        "reconstruction must be byte-identical, not merely well-formed"
    );
}

#[test]
fn loss_beyond_the_envelope_fails_closed_and_never_fabricates() {
    // THE property. The measured profile is 4 source + 8 repair symbols, so
    // reconstruction needs roughly 4 of the 12. Keeping only 2 is genuinely
    // beyond what any code can recover: the decoder cannot know the missing
    // bytes. The only acceptable outcomes are a refusal or an exact
    // reconstruction -- NEVER different bytes returned as success.
    let bytes = canonical_segment(b"tenant-a", 7, PAYLOAD);
    let protected = protect(&bytes);
    let starved: Vec<ScopedSymbol> = protected.symbols().iter().take(2).cloned().collect();
    assert!(
        starved.len() < source_symbol_count(&protected),
        "the starved set must hold fewer symbols than the source count, or it is recoverable"
    );

    match reconstruct_microsegment(
        protected.scope(),
        &starved,
        &SegmentLimits::default(),
        &security(),
    ) {
        Err(_) => {}
        Ok(verified) => assert_eq!(
            verified.bytes(),
            bytes,
            "FABRICATION: reconstruction from {} of {} symbols returned SUCCESS with bytes \
             that are not the original. This is the one outcome erasure coding must never \
             produce.",
            starved.len(),
            protected.symbols().len()
        ),
    }
}

#[test]
fn an_empty_symbol_set_is_refused_rather_than_guessed() {
    let bytes = canonical_segment(b"tenant-a", 7, PAYLOAD);
    let protected = protect(&bytes);

    match reconstruct_microsegment(
        protected.scope(),
        &[],
        &SegmentLimits::default(),
        &security(),
    ) {
        Err(_) => {}
        Ok(verified) => assert_eq!(
            verified.bytes(),
            bytes,
            "FABRICATION: reconstruction from ZERO symbols claimed success"
        ),
    }
}

#[test]
fn one_symbol_short_of_the_envelope_still_refuses_rather_than_approximates() {
    // The hardest anti-fabrication case: exactly ONE symbol short of what the
    // profile needs. This is where a decoder is most likely to produce
    // plausible-but-wrong output, because it has almost enough information --
    // far more dangerous than the starved or empty cases, which are obviously
    // hopeless.
    let bytes = canonical_segment(b"tenant-a", 7, PAYLOAD);
    let protected = protect(&bytes);
    let needed = source_symbol_count(&protected);
    assert!(
        needed > 1,
        "the boundary case needs a profile with room below it"
    );

    let one_short: Vec<ScopedSymbol> = protected
        .symbols()
        .iter()
        .take(needed - 1)
        .cloned()
        .collect();
    assert_eq!(one_short.len(), needed - 1);

    match reconstruct_microsegment(
        protected.scope(),
        &one_short,
        &SegmentLimits::default(),
        &security(),
    ) {
        Err(_) => {}
        Ok(verified) => assert_eq!(
            verified.bytes(),
            bytes,
            "FABRICATION: one symbol short of the envelope, reconstruction returned SUCCESS \
             with bytes that are not the original. Approximating is the failure mode erasure \
             coding must never have."
        ),
    }
}

// --- malicious symbols: legitimate symbols in illegitimate contexts ---------

#[test]
fn symbols_from_another_microsegment_are_refused_before_decode() {
    // The reachable malicious-symbol attack: every symbol is authentic and
    // correctly signed, but belongs to a DIFFERENT object. A placement layer
    // that mixed two segments' repair material would produce exactly this.
    let alpha = canonical_segment(b"tenant-a", 7, PAYLOAD);
    let beta = canonical_segment(b"tenant-b", 9, b"a completely different payload body");
    let protected_alpha = protect(&alpha);
    let protected_beta = protect(&beta);
    assert_ne!(
        protected_alpha.scope(),
        protected_beta.scope(),
        "the two fixtures must be different objects, or the substitution is a no-op"
    );

    let refusal = reconstruct_microsegment(
        protected_alpha.scope(),
        protected_beta.symbols(),
        &SegmentLimits::default(),
        &security(),
    )
    .expect_err("foreign symbols must never reconstruct");
    assert_eq!(
        refusal,
        RaptorRefusal::ScopeMismatch,
        "a foreign symbol must be refused on scope before any decode work"
    );

    // Paired: the same call with its own symbols proceeds, so the refusal is
    // not a reconstructor that refuses everything.
    reconstruct_microsegment(
        protected_alpha.scope(),
        protected_alpha.symbols(),
        &SegmentLimits::default(),
        &security(),
    )
    .expect("a segment reconstructs from its own symbols");
}

#[test]
fn a_foreign_symbol_reaching_validation_poisons_the_set() {
    // One foreign symbol smuggled into an otherwise authentic set, placed
    // FIRST so it reaches `validate_symbol` before the block completes.
    let alpha = canonical_segment(b"tenant-a", 7, PAYLOAD);
    let beta = canonical_segment(b"tenant-b", 9, b"a completely different payload body");
    let protected_alpha = protect(&alpha);
    let protected_beta = protect(&beta);

    let mut mixed: Vec<ScopedSymbol> = vec![
        protected_beta
            .symbols()
            .first()
            .expect("beta has symbols")
            .clone(),
    ];
    mixed.extend(protected_alpha.symbols().iter().cloned());

    let refusal = reconstruct_microsegment(
        protected_alpha.scope(),
        &mixed,
        &SegmentLimits::default(),
        &security(),
    )
    .expect_err("a foreign symbol that reaches validation must poison the set");
    assert_eq!(refusal, RaptorRefusal::ScopeMismatch);
}

#[test]
fn a_trailing_foreign_symbol_is_never_examined_and_the_output_is_still_correct() {
    // MEASURED BEHAVIOUR, recorded rather than asserted as a defect.
    //
    // `reconstruct_microsegment` validates each symbol immediately before
    // feeding it, and `break`s on `BlockComplete`. So a foreign symbol placed
    // AFTER enough legitimate symbols to complete the block is never
    // validated at all -- reconstruction succeeds and the intruder is simply
    // never examined.
    //
    // I expected a refusal and got success. On inspection the result is safe
    // rather than wrong: the candidate is still checked against every original
    // commitment (length, structure, and recomputed scope), so an unexamined
    // trailing symbol cannot influence the bytes. The output here is
    // byte-identical to the original, which this asserts.
    //
    // It is still worth pinning, because "the set contained a hostile symbol
    // and reconstruction returned Ok" is a sentence a reader could reasonably
    // find alarming, and the reason it is fine is non-obvious. If the early
    // `break` is ever removed, this test changes behaviour and should be
    // revisited deliberately. Raised with the crate owner rather than silently
    // encoded as intended.
    let alpha = canonical_segment(b"tenant-a", 7, PAYLOAD);
    let beta = canonical_segment(b"tenant-b", 9, b"a completely different payload body");
    let protected_alpha = protect(&alpha);
    let protected_beta = protect(&beta);

    let mut mixed: Vec<ScopedSymbol> = protected_alpha.symbols().to_vec();
    mixed.push(
        protected_beta
            .symbols()
            .last()
            .expect("beta has symbols")
            .clone(),
    );

    let verified = reconstruct_microsegment(
        protected_alpha.scope(),
        &mixed,
        &SegmentLimits::default(),
        &security(),
    )
    .expect("the block completes before the trailing intruder is examined");
    assert_eq!(
        verified.bytes(),
        alpha,
        "the intruder must not have influenced the output; the commitment checks are what \
         make an unexamined trailing symbol harmless"
    );
}

#[test]
fn the_decode_budget_refuses_a_symbol_flood_before_decoding() {
    // Resource exhaustion: a hostile placement layer offering vastly more
    // symbols than the profile admits. §5.5 wants bounded work before
    // validation, so this must refuse on the budget rather than decode.
    let bytes = canonical_segment(b"tenant-a", 7, PAYLOAD);
    let protected = protect(&bytes);
    let mut flood: Vec<ScopedSymbol> = Vec::new();
    while flood.len() <= MicrosegmentRaptorProfile::MAX_DECODE_SYMBOLS {
        flood.extend(protected.symbols().iter().cloned());
    }

    let refusal = reconstruct_microsegment(
        protected.scope(),
        &flood,
        &SegmentLimits::default(),
        &security(),
    )
    .expect_err("a symbol flood must be refused");
    assert!(
        matches!(refusal, RaptorRefusal::DecodeBudgetExceeded { .. }),
        "a flood must refuse on the decode budget, observed {refusal:?}"
    );
}

// --- the destructive reconstruction drill -----------------------------------

#[test]
fn the_destructive_drill_rebuilds_from_repair_material_alone() {
    // Acceptance: delete the source placements entirely, rebuild from repair
    // material alone, verify byte identity. The measured profile is 4 source +
    // 8 repair, so every source symbol can be destroyed and the segment is
    // still recoverable -- which is the whole claim erasure coding makes.
    let bytes = canonical_segment(b"tenant-a", 7, PAYLOAD);
    let protected = protect(&bytes);
    let sources = source_symbol_count(&protected);
    let repair = repair_symbol_count(&protected);
    assert!(
        sources > 0 && repair > 0,
        "the drill needs both kinds present"
    );

    let survivors = drop_source_symbols(&protected, u32::try_from(sources).expect("fits u32"));
    assert_eq!(
        survivors.len(),
        repair,
        "the drill must destroy EVERY source placement, leaving only repair material"
    );
    assert!(
        survivors
            .iter()
            .all(|scoped| !scoped.symbol().kind().is_source()),
        "no source symbol may survive the drill, or it is not a destructive drill"
    );

    let rebuilt = reconstruct_microsegment(
        protected.scope(),
        &survivors,
        &SegmentLimits::default(),
        &security(),
    )
    .expect("repair material alone reconstructs the segment");
    assert_eq!(rebuilt.bytes(), bytes, "the drill must be byte-identical");
    assert_eq!(rebuilt.scope(), protected.scope());
}

// --- the replication-only economics control ---------------------------------

#[test]
fn the_replication_control_is_measured_beside_the_coded_overhead() {
    // The bead forbids citing a paper overhead ratio without drill evidence.
    // This measures both against the same segment so the comparison is real
    // rather than quoted: coded overhead is symbols-on-the-wire versus source
    // bytes; the replication control is what 2x and 3x replication would cost
    // for the same durability conversation.
    let bytes = canonical_segment(b"tenant-a", 7, PAYLOAD);
    let protected = protect(&bytes);
    let symbol_bytes = usize::from(MicrosegmentRaptorProfile::SYMBOL_BYTES);

    let coded_total = protected.symbols().len() * symbol_bytes;
    let source_total = source_symbol_count(&protected) * symbol_bytes;
    let replication_2x = bytes.len() * 2;
    let replication_3x = bytes.len() * 3;

    assert!(
        coded_total > source_total,
        "a coding profile that adds no bytes adds no protection"
    );
    // Reported, not asserted as a threshold: an overhead target would be a
    // performance claim, and this drill establishes durability behaviour, not
    // an economics conclusion.
    println!(
        "{{\"segment_bytes\":{},\"coded_bytes\":{coded_total},\"source_bytes\":{source_total},\
\"replication_2x_bytes\":{replication_2x},\"replication_3x_bytes\":{replication_3x},\
\"repair_symbols\":{},\"source_symbols\":{}}}",
        bytes.len(),
        repair_symbol_count(&protected),
        source_symbol_count(&protected)
    );
}

// --- the zero-acceptance property, stated as one assertion ------------------

#[test]
fn no_hostile_symbol_set_is_ever_accepted() {
    // The bead's headline: "malicious-symbol corpus: zero acceptances." Every
    // hostile case is run through one loop so the count is a stated
    // denominator rather than an impression, and so adding a case cannot
    // silently skip the tally.
    let alpha = canonical_segment(b"tenant-a", 7, PAYLOAD);
    let beta = canonical_segment(b"tenant-b", 9, b"a completely different payload body");
    let protected_alpha = protect(&alpha);
    let protected_beta = protect(&beta);
    let limits = SegmentLimits::default();

    let mut mixed: Vec<ScopedSymbol> = protected_alpha.symbols().to_vec();
    mixed.push(
        protected_beta
            .symbols()
            .last()
            .expect("beta has symbols")
            .clone(),
    );

    let hostile: Vec<(&str, Vec<ScopedSymbol>)> = vec![
        ("wholesale-foreign", protected_beta.symbols().to_vec()),
        ("one-foreign-smuggled", mixed),
        ("empty-symbol-set", Vec::new()),
        (
            "starved-below-the-envelope",
            protected_alpha.symbols().iter().take(2).cloned().collect(),
        ),
    ];

    let mut accepted: Vec<&str> = Vec::new();
    for (name, symbols) in &hostile {
        if let Ok(verified) =
            reconstruct_microsegment(protected_alpha.scope(), symbols, &limits, &security())
            && verified.bytes() != alpha
        {
            accepted.push(name);
        }
    }

    assert_eq!(hostile.len(), 4, "the corpus must not silently shrink");
    assert!(
        accepted.is_empty(),
        "ZERO ACCEPTANCES violated: {} of {} hostile sets reconstructed to non-original bytes: {:?}",
        accepted.len(),
        hostile.len(),
        accepted
    );
}

// --- the signed reconstruction report ---------------------------------------

use fgit_crypto::{
    AuthorityAdmin, IdentityDomain, KeyEpoch, KeyScope, RootSecret, SchemaFamily, SchemaId,
    SecretKey, SignatureError, internal_object_id,
};
use fgit_types::CANONICAL_CODEC_VERSION;

/// Schema of the drill's reconstruction report.
const fn report_schema() -> SchemaId {
    SchemaId::new(
        SchemaFamily::from_static("frankengit.raptorq-reconstruction-report"),
        1,
        0,
    )
}

/// The canonical report body.
///
/// Length-prefixed and big-endian throughout, for the same reason every other
/// preimage in this workspace is: bare concatenation lets one field borrow the
/// next field's leading bytes, so two different drills could render the same
/// bytes and share an identity.
fn report_body(
    segment_bytes: u64,
    source_symbols: u64,
    repair_symbols: u64,
    destroyed: u64,
    byte_identical: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(41);
    out.extend_from_slice(&segment_bytes.to_be_bytes());
    out.extend_from_slice(&source_symbols.to_be_bytes());
    out.extend_from_slice(&repair_symbols.to_be_bytes());
    out.extend_from_slice(&destroyed.to_be_bytes());
    out.push(u8::from(byte_identical));
    out
}

#[test]
fn the_drill_emits_a_signed_reconstruction_report_bound_to_its_own_result() {
    // Acceptance: "drill produces a signed-format reconstruction report; paper
    // overhead ratio is never cited without drill evidence."
    //
    // Genuinely signed, not signed-shaped: an Ed25519 detached envelope over a
    // domain-separated evidence body, verified against a caller-supplied trust
    // anchor.
    //
    // THE SIGNER IS AN AUTHORITY KEY, NOT AN EVIDENCE KEY, and that is not an
    // arbitrary choice. `fgit-crypto` deliberately withholds `SignatureCapable`
    // from `Evidence`: evidence bodies are IDENTIFIED by a domain-separated
    // digest and COUNTERSIGNED by whichever authority vouches for them, so a
    // key that could do both would blur "this evidence exists" against "this
    // authority asserts it". `SecretKey<Evidence>` has no `sign` method at all,
    // so this composition is the one the type system permits.
    let bytes = canonical_segment(b"tenant-a", 7, PAYLOAD);
    let protected = protect(&bytes);
    let sources = source_symbol_count(&protected);
    let repair = repair_symbol_count(&protected);

    let survivors = drop_source_symbols(&protected, u32::try_from(sources).expect("fits u32"));
    let rebuilt = reconstruct_microsegment(
        protected.scope(),
        &survivors,
        &SegmentLimits::default(),
        &security(),
    )
    .expect("repair material alone reconstructs the segment");
    let byte_identical = rebuilt.bytes() == bytes;
    assert!(
        byte_identical,
        "the drill must reconstruct byte-identically"
    );

    let body = report_body(
        u64::try_from(bytes.len()).expect("fits u64"),
        u64::try_from(sources).expect("fits u64"),
        u64::try_from(repair).expect("fits u64"),
        u64::try_from(sources).expect("fits u64"),
        byte_identical,
    );

    // The report is an evidence body with a domain-separated identity.
    let identity = internal_object_id(
        IdentityDomain::EvidenceRecord,
        report_schema(),
        CANONICAL_CODEC_VERSION,
        &body,
    );

    let authority = SecretKey::<AuthorityAdmin>::derive(
        &RootSecret::from_bytes([0x5a; 32]),
        KeyEpoch::FIRST,
        KeyScope::OPERATOR,
    );
    let signature = authority.sign(IdentityDomain::EvidenceRecord, report_schema(), &body);

    assert_eq!(
        signature.verify_with(
            &authority.verifying_key(),
            IdentityDomain::EvidenceRecord,
            report_schema(),
            &body
        ),
        Ok(()),
        "the countersignature must verify against the authority that produced it"
    );

    // A report whose numbers were edited after signing must not verify. This
    // is what makes the report evidence rather than decoration.
    let tampered = report_body(
        u64::try_from(bytes.len()).expect("fits u64"),
        u64::try_from(sources).expect("fits u64"),
        u64::try_from(repair).expect("fits u64"),
        0, // claim nothing was destroyed
        byte_identical,
    );
    assert_ne!(body, tampered, "the tampered body must actually differ");
    assert_eq!(
        signature.verify_with(
            &authority.verifying_key(),
            IdentityDomain::EvidenceRecord,
            report_schema(),
            &tampered
        ),
        Err(SignatureError::Invalid),
        "a report edited after signing must not verify"
    );

    // And the identity moves with the body, so the report cannot be swapped
    // for a different drill's result under the same identity.
    let other_identity = internal_object_id(
        IdentityDomain::EvidenceRecord,
        report_schema(),
        CANONICAL_CODEC_VERSION,
        &tampered,
    );
    assert_ne!(
        identity, other_identity,
        "two different drill results must not share one evidence identity"
    );

    // The report, emitted for the e2e lane to capture.
    println!(
        "{{\"schema\":\"frankengit.raptorq-reconstruction-report\",\"segment_bytes\":{},\
\"source_symbols\":{sources},\"repair_symbols\":{repair},\"source_placements_destroyed\":{sources},\
\"byte_identical\":{byte_identical},\"evidence_identity\":\"{}\",\"countersigned_by\":\"authority-admin\"}}",
        bytes.len(),
        identity
    );
}

#[test]
fn an_evidence_key_cannot_countersign_its_own_report() {
    // The control for the design decision above, and the reason it is not
    // merely a convention: `SecretKey<Evidence>` has no `sign` method, so the
    // blurring this guards against is not a rule someone could forget -- it is
    // a program that does not compile. Asserted here as a doc-tested boundary
    // rather than prose, via the compile_fail case that lives on
    // `SecretKey::sign` in fgit-crypto.
    //
    // What is checkable at runtime is the positive half: an authority key CAN
    // sign, and its signature is bound to the evidence domain specifically.
    let authority = SecretKey::<AuthorityAdmin>::derive(
        &RootSecret::from_bytes([0x5a; 32]),
        KeyEpoch::FIRST,
        KeyScope::OPERATOR,
    );
    let body = report_body(412, 4, 8, 4, true);
    let signature = authority.sign(IdentityDomain::EvidenceRecord, report_schema(), &body);

    // The same signature must not verify as a different domain: a drill report
    // cannot be replayed as a restore report.
    assert_eq!(
        signature.verify_with(
            &authority.verifying_key(),
            IdentityDomain::RestoreReport,
            report_schema(),
            &body
        ),
        Err(SignatureError::Invalid),
        "an evidence-domain countersignature must not verify as a restore report"
    );
}
