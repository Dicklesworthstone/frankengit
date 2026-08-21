//! FG-005b: the concurrency envelope, derived from the specification.
//!
//! # Why this exists alongside `envelope_admission.rs`
//!
//! Same reason as `retry_law_independent.rs`: the crate's own envelope tests
//! are written by the author of the code they test, so they cannot catch a
//! misreading of the clause. In particular they assert against
//! `MAX_ADMITTED_AUTOCOMMIT_WRITERS`, which means they would keep passing if
//! that constant were wrong.
//!
//! The numbers below are derived from
//! `docs/ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md` §3.5, not copied
//! from the implementation.
//!
//! # The derivation, so a reader can check it without trusting me
//!
//! §3.5 says:
//!
//! > The reviewed upstream contract does not yet support a blanket claim for
//! > ten or more concurrent implicit-autocommit writers.
//!
//! "Ten or more" is unsupported. Nine is therefore the largest admissible
//! count, and ten is the first refusal. That boundary is the whole content of
//! the clause, and it is the one thing an implementer could get off by one
//! while every implementer-written test still passed.
//!
//! §3.5 also says the caller "does not extrapolate from smaller tests", and
//! limits multi-process writer claims "to the exact tested profile".
//!
//! Written by a pane that did not implement this crate; nothing here edits
//! `fgit-authority-fsqlite/src`.
//!
//! # What this does NOT claim
//!
//! That the admitted topologies actually behave correctly under load. This
//! checks the **admission rule** — which topologies the profile agrees to
//! attempt — and says nothing about what happens once one is running. Two of
//! the six scenarios §3.5 lists (checkpoint under load, and process
//! crash/reopen/recovery) are behavioural; the crash/reopen half is covered by
//! `crash_equivalence.rs`, and checkpoint-under-load cannot be driven at all.
//!
//! That last one used to be recorded here as "the store publishes no checkpoint
//! operation", which invites the wrong repair: add one. It is not reachable
//! from `fsqlite` either. Its sole WAL-checkpoint trigger is
//! `Command::Close { checkpoint: bool }` — there is no `Command::Checkpoint` —
//! so every public path that checkpoints also closes the connection, and
//! closing it ends the load. No method added to `FsqliteAuthorityStore` can
//! reach the cell. This is a permanent typed non-claim, not a gap: see
//! `NEG-022` in `registries/negative_evidence.tsv` and the crate-level docs,
//! which carry the measurement and the revisit condition.

use fgit_authority_fsqlite::{
    ConcurrencyEnvelope, EnvelopeRefusal, MAX_ADMITTED_AUTOCOMMIT_WRITERS, WriterTopology,
};

/// The largest implicit-autocommit writer count §3.5 permits.
///
/// Derived, not copied: the clause withholds the claim at "ten or more", so
/// the last admissible value is nine.
const SPEC_MAX_AUTOCOMMIT_WRITERS: u32 = 9;

/// The first count §3.5 refuses.
const SPEC_FIRST_UNPROVEN_COUNT: u32 = 10;

fn autocommit(writers: u32) -> WriterTopology {
    WriterTopology {
        connections: writers,
        writers,
        implicit_autocommit: true,
        multi_process: false,
    }
}

#[test]
fn the_published_cap_is_the_one_the_clause_implies() {
    // The single most valuable assertion in this file. `envelope_admission.rs`
    // tests behaviour *against* this constant, so if the constant were 10 --
    // an entirely natural off-by-one from "ten or more" -- every
    // implementer-written test would still pass while the profile claimed
    // support the upstream contract does not give.
    assert_eq!(
        MAX_ADMITTED_AUTOCOMMIT_WRITERS, SPEC_MAX_AUTOCOMMIT_WRITERS,
        "§3.5 withholds the claim at ten or more concurrent implicit-autocommit writers, so the \
         published cap must be {SPEC_MAX_AUTOCOMMIT_WRITERS}, not {MAX_ADMITTED_AUTOCOMMIT_WRITERS}"
    );
}

#[test]
fn nine_autocommit_writers_are_admitted_and_ten_are_refused() {
    // The boundary itself, exercised from both sides rather than asserted
    // about the constant. A cap that is correct as a number but not consulted
    // at admission would pass the test above and fail here.
    let admitted = ConcurrencyEnvelope::admit(autocommit(SPEC_MAX_AUTOCOMMIT_WRITERS));
    assert!(
        admitted.is_ok(),
        "{SPEC_MAX_AUTOCOMMIT_WRITERS} implicit-autocommit writers are inside the reviewed \
         envelope and must be admitted; got {admitted:?}"
    );

    let refused = ConcurrencyEnvelope::admit(autocommit(SPEC_FIRST_UNPROVEN_COUNT));
    let Err(refusal) = refused else {
        panic!(
            "{SPEC_FIRST_UNPROVEN_COUNT} implicit-autocommit writers must be refused: §3.5 \
             withholds the claim at ten or more, and admitting it extrapolates from smaller tests"
        );
    };
    assert!(
        matches!(refusal, EnvelopeRefusal::AutocommitWritersUnproven { .. }),
        "the refusal must name the unproven autocommit count rather than some incidental limit, \
         or an operator cannot tell which claim is missing; got {refusal:?}"
    );
}

#[test]
fn refusal_is_typed_rather_than_a_silent_cap() {
    // A profile that quietly clamped an over-large topology to the proven one
    // would satisfy "never exceeds the envelope" while lying to its caller
    // about what it is running. §3.5's whole posture is that unproven
    // topologies are refused, not adjusted.
    let requested = SPEC_FIRST_UNPROVEN_COUNT + 5;
    match ConcurrencyEnvelope::admit(autocommit(requested)) {
        Ok(envelope) => panic!(
            "a topology of {requested} autocommit writers was admitted as {:?}; an unproven \
             topology must be refused, never silently clamped to a proven one",
            envelope.topology()
        ),
        Err(EnvelopeRefusal::AutocommitWritersUnproven { .. }) => {}
        Err(other) => panic!("expected the unproven-autocommit refusal, got {other:?}"),
    }
}

#[test]
fn explicit_transactions_are_not_bound_by_the_autocommit_cap() {
    // §3.5's withheld claim is specifically about *implicit-autocommit*
    // writers. Applying the cap to explicit transactions too would be the
    // conservative direction, but it would be a different rule than the one
    // written, and a profile that refuses admissible work is as wrong as one
    // that admits inadmissible work -- just less dangerously.
    let explicit = WriterTopology {
        connections: SPEC_FIRST_UNPROVEN_COUNT + 2,
        writers: SPEC_FIRST_UNPROVEN_COUNT + 2,
        implicit_autocommit: false,
        multi_process: false,
    };
    assert!(
        ConcurrencyEnvelope::admit(explicit).is_ok(),
        "the ten-or-more withholding is scoped to implicit autocommit; explicit transactions must \
         not inherit it"
    );
}

#[test]
fn the_first_named_scenario_is_admitted() {
    // §3.5's support matrix opens with "one connection and one writer". If the
    // profile's own first listed scenario were refused, the matrix would be
    // describing something the code does not implement.
    assert!(
        ConcurrencyEnvelope::admit(WriterTopology::SINGLE_WRITER).is_ok(),
        "one connection with one writer is the first scenario §3.5 publishes and must be admitted"
    );
}

#[test]
fn writers_may_not_outnumber_connections() {
    // Not from §3.5's prose but from arithmetic it presumes: a writer needs a
    // connection to write through. This is the sanity floor under the whole
    // matrix -- "multiple connections with readers plus bounded writers" is
    // incoherent if writers can exceed connections.
    let impossible = WriterTopology::bounded_writers(2, 5);
    assert!(
        matches!(
            ConcurrencyEnvelope::admit(impossible),
            Err(EnvelopeRefusal::WritersExceedConnections { .. })
        ),
        "five writers over two connections must be refused: a writer cannot write without a \
         connection to write through"
    );
}

#[test]
fn a_lane_with_no_connection_is_refused() {
    let none = WriterTopology::bounded_writers(0, 0);
    assert!(
        matches!(
            ConcurrencyEnvelope::admit(none),
            Err(EnvelopeRefusal::NoConnection)
        ),
        "a lane holding no connection cannot be admitted to any scenario in the matrix"
    );
}

#[test]
fn multi_process_writing_is_refused_rather_than_assumed() {
    // §3.5: "Multi-process writer and checkpoint claims are likewise limited
    // to the exact tested profile." Multi-process writing is the claim most
    // likely to be assumed by analogy with single-process concurrency, which
    // is exactly the extrapolation the clause forbids.
    let cross_process = WriterTopology {
        connections: 2,
        writers: 2,
        implicit_autocommit: false,
        multi_process: true,
    };
    assert!(
        matches!(
            ConcurrencyEnvelope::admit(cross_process),
            Err(EnvelopeRefusal::MultiProcessWritersUnproven { .. })
        ),
        "multi-process writing must be refused as unproven; admitting it by analogy with \
         single-process concurrency is the extrapolation §3.5 forbids"
    );
}
