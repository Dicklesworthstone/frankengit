#![forbid(unsafe_code)]

//! frankengit-raptor-decode-budget-v579: the decode budget's PAYLOAD, and the
//! geometry that makes the bound what it is.
//!
//! `RaptorRefusal::DecodeBudgetExceeded { offered, maximum }` is raised at five
//! sites. Two are reachable — the reconstruct paths, where a caller supplies an
//! arbitrary symbol vector — and both were already driven. What no assertion
//! anywhere read was the **payload**: every existing check is
//! `matches!(refusal, DecodeBudgetExceeded { .. })`, which discards both fields.
//! So nothing pinned *which* bound was reported or how many symbols were
//! offered, and a site reporting a wrong maximum would pass every test.
//!
//! # The other three sites are unreachable, and this file does not probe them
//!
//! Recorded so the next reader does not re-derive it, and deliberately **not**
//! counted as coverage:
//!
//! ```text
//! SYMBOL_BYTES = 128,  MAX_SOURCE_BYTES = 8192,  REPAIR_SYMBOLS = 8
//! 8192 / 128 = 64 source symbols, + 8 repair = 72 produced at most
//! the guard is `symbols.len() > 72`, and 72 > 72 is false
//! ```
//!
//! Both `protect_*` paths generate their own symbols from an input already
//! capped at `MAX_SOURCE_BYTES`, so neither can construct a 73rd symbol.
//! `repair_microsegment`'s site fires only when `u32::try_from(symbols.len())`
//! fails, which needs over four billion symbols in one `Vec`.
//!
//! # Why the geometry is asserted here
//!
//! `MAX_DECODE_SYMBOLS` is not an independent limit — it is exactly the largest
//! legitimate output of the profile. Nothing enforced that relationship. Raise
//! `MAX_SOURCE_BYTES` to 16 KiB without raising `MAX_DECODE_SYMBOLS` and
//! `protect_*` begins refusing every large-but-valid input with
//! `DecodeBudgetExceeded`: a silent capability regression, and those unreachable
//! guards quietly become reachable. `checkpoint.rs` calls these "a second set of
//! tuning constants to keep in sync", which names the hazard without enforcing
//! it. The first test enforces it.

use asupersync::security::SecurityContext;
use fgit_raptorq::checkpoint::{
    CheckpointClass, CheckpointRaptorProfile, ProtectedCheckpoint, ScopedCheckpointSymbol,
    protect_checkpoint, reconstruct_checkpoint,
};
use fgit_raptorq::{MicrosegmentRaptorProfile, RaptorRefusal};

fn security() -> SecurityContext {
    SecurityContext::for_testing(24)
}

/// Arbitrary but deterministic checkpoint bytes.
fn canonical(fill: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| fill ^ u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

fn protected() -> ProtectedCheckpoint {
    protect_checkpoint(
        CheckpointClass::ForgeEvent,
        &canonical(0xb2, 600),
        &security(),
    )
    .expect("a canonical checkpoint well inside MAX_SOURCE_BYTES must protect")
}

/// Exactly `count` symbols, cycled from a legitimately produced set.
///
/// Cycling real symbols rather than forging them matters: `ScopedCheckpointSymbol`
/// has no public constructor, so an external test cannot mint one. Duplicates are
/// the only way to exceed the budget from outside, and they are also the shape a
/// hostile placement layer would actually offer.
fn symbols_numbering(source: &ProtectedCheckpoint, count: usize) -> Vec<ScopedCheckpointSymbol> {
    let mut flood: Vec<ScopedCheckpointSymbol> = Vec::new();
    while flood.len() < count {
        flood.extend(source.symbols().iter().cloned());
    }
    flood.truncate(count);
    assert_eq!(flood.len(), count, "the fixture must offer exactly {count}");
    flood
}

/// The bound is the profile's geometry, and now it has to stay that way.
///
/// Asserted for both profiles independently rather than for one and assumed for
/// the other — they are separate constant sets that happen to agree.
#[test]
fn the_decode_budget_is_exactly_the_profiles_largest_legitimate_output() {
    let checkpoint_source = CheckpointRaptorProfile::MAX_SOURCE_BYTES
        / usize::from(CheckpointRaptorProfile::SYMBOL_BYTES);
    assert_eq!(
        CheckpointRaptorProfile::MAX_DECODE_SYMBOLS,
        checkpoint_source + CheckpointRaptorProfile::REPAIR_SYMBOLS,
        "the checkpoint decode budget must admit exactly a full-size protect output; if these \
         drift apart, protect_checkpoint starts refusing valid inputs on the decode budget",
    );

    let microsegment_source = MicrosegmentRaptorProfile::MAX_SOURCE_BYTES
        / usize::from(MicrosegmentRaptorProfile::SYMBOL_BYTES);
    assert_eq!(
        MicrosegmentRaptorProfile::MAX_DECODE_SYMBOLS,
        microsegment_source + MicrosegmentRaptorProfile::REPAIR_SYMBOLS,
        "the microsegment decode budget must admit exactly a full-size protect output",
    );
}

/// One symbol past the budget, and the refusal must name the real numbers.
///
/// This is the assertion the existing `matches!(.., { .. })` checks cannot make:
/// it pins that `offered` is the count actually presented and `maximum` is the
/// profile's bound, so a site reporting some other figure fails here.
#[test]
fn a_flood_one_past_the_budget_reports_the_exact_offered_and_maximum() {
    let source = protected();
    let over = CheckpointRaptorProfile::MAX_DECODE_SYMBOLS + 1;

    let refusal = reconstruct_checkpoint(
        source.scope(),
        &symbols_numbering(&source, over),
        &security(),
        None,
    )
    .expect_err("one symbol past the decode budget must refuse");

    assert_eq!(
        refusal,
        RaptorRefusal::DecodeBudgetExceeded {
            offered: over,
            maximum: CheckpointRaptorProfile::MAX_DECODE_SYMBOLS,
        },
        "the refusal must carry the count offered and the bound applied, not merely the variant",
    );
}

/// The permitted twin at the exact inclusive boundary.
///
/// The existing in-src twin offers "the legitimate set, well inside the budget",
/// which cannot detect an off-by-one. Exactly `MAX_DECODE_SYMBOLS` must not be
/// refused *on the budget*; whether those duplicate symbols then decode is a
/// different question, so this asserts only that the budget was not what
/// refused.
#[test]
fn exactly_the_budget_is_not_refused_on_the_budget() {
    let source = protected();
    let at = CheckpointRaptorProfile::MAX_DECODE_SYMBOLS;

    if let Err(refusal) = reconstruct_checkpoint(
        source.scope(),
        &symbols_numbering(&source, at),
        &security(),
        None,
    ) {
        assert!(
            !matches!(refusal, RaptorRefusal::DecodeBudgetExceeded { .. }),
            "exactly MAX_DECODE_SYMBOLS is within budget and must not be refused by the budget \
             guard; observed {refusal:?}",
        );
    }
}
