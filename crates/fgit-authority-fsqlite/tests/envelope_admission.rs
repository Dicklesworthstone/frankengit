//! The concurrency envelope refuses what the upstream review does not support.
//!
//! Every refusal below is paired with the nearest admitted topology, so the
//! tests show where the boundary is rather than only that one exists.

use fgit_authority_fsqlite::{
    ConcurrencyEnvelope, EnvelopeRefusal, MAX_ADMITTED_AUTOCOMMIT_WRITERS, WriterTopology,
};

fn autocommit(writers: u32) -> WriterTopology {
    WriterTopology {
        connections: writers,
        writers,
        implicit_autocommit: true,
        multi_process: false,
    }
}

#[test]
fn the_single_writer_scenario_is_admitted() {
    let envelope =
        ConcurrencyEnvelope::admit(WriterTopology::SINGLE_WRITER).expect("one writer is proven");
    assert_eq!(envelope.required_workers(), 1);
    assert_eq!(envelope.topology(), WriterTopology::SINGLE_WRITER);
}

#[test]
fn readers_plus_bounded_writers_are_admitted() {
    let envelope = ConcurrencyEnvelope::admit(WriterTopology::bounded_writers(8, 2))
        .expect("readers plus bounded writers is a named scenario");
    assert_eq!(
        envelope.required_workers(),
        8,
        "one dedicated worker per connection; a raw connection is not Send"
    );
}

#[test]
fn a_lane_with_no_connection_is_refused() {
    let refusal = ConcurrencyEnvelope::admit(WriterTopology::bounded_writers(0, 0))
        .expect_err("a lane with no connection serves nothing");
    assert_eq!(refusal, EnvelopeRefusal::NoConnection);

    ConcurrencyEnvelope::admit(WriterTopology::bounded_writers(1, 0))
        .expect("a read-only lane with one connection is fine");
}

#[test]
fn writers_may_not_outnumber_connections() {
    let refusal = ConcurrencyEnvelope::admit(WriterTopology::bounded_writers(2, 3))
        .expect_err("writers cannot share a connection");
    assert_eq!(
        refusal,
        EnvelopeRefusal::WritersExceedConnections {
            writers: 3,
            connections: 2
        }
    );

    ConcurrencyEnvelope::admit(WriterTopology::bounded_writers(3, 3))
        .expect("one writer per connection is the boundary and it is admitted");
}

#[test]
fn the_unproven_autocommit_writer_count_is_refused_at_admission() {
    // The profile withholds the blanket claim at ten or more, so nine is
    // admitted and ten is refused. The pair is the point: the boundary is
    // evidence, not a round number someone liked.
    ConcurrencyEnvelope::admit(autocommit(MAX_ADMITTED_AUTOCOMMIT_WRITERS))
        .expect("nine concurrent autocommit writers is within the reviewed contract");

    let refusal = ConcurrencyEnvelope::admit(autocommit(MAX_ADMITTED_AUTOCOMMIT_WRITERS + 1))
        .expect_err("ten or more is beyond the reviewed contract");
    assert_eq!(
        refusal,
        EnvelopeRefusal::AutocommitWritersUnproven {
            writers: MAX_ADMITTED_AUTOCOMMIT_WRITERS + 1,
            admitted: MAX_ADMITTED_AUTOCOMMIT_WRITERS,
        }
    );
    assert!(
        refusal.to_string().contains("extrapolated"),
        "the refusal must say why: {refusal}"
    );
}

#[test]
fn explicit_transactions_are_not_bound_by_the_autocommit_limit() {
    // The withheld claim is specifically about implicit-autocommit writers, so
    // an explicitly transacted lane of the same width is a different question.
    let wide = WriterTopology {
        connections: 32,
        writers: 32,
        implicit_autocommit: false,
        multi_process: false,
    };
    ConcurrencyEnvelope::admit(wide)
        .expect("the autocommit bound must not be applied to a shape it was not measured on");
}

#[test]
fn multi_process_writing_is_limited_to_the_tested_profile() {
    let single = WriterTopology {
        connections: 1,
        writers: 1,
        implicit_autocommit: false,
        multi_process: true,
    };
    ConcurrencyEnvelope::admit(single).expect("single-writer multi-process is the tested shape");

    let refusal = ConcurrencyEnvelope::admit(WriterTopology {
        connections: 2,
        writers: 2,
        implicit_autocommit: false,
        multi_process: true,
    })
    .expect_err("multi-process multi-writer is outside the tested profile");
    assert_eq!(
        refusal,
        EnvelopeRefusal::MultiProcessWritersUnproven { writers: 2 }
    );
}

#[test]
fn an_admitted_envelope_is_the_only_way_to_name_a_topology() {
    // ConcurrencyEnvelope has no public constructor other than admit, so a lane
    // cannot be opened against a topology nobody checked. The observable form
    // of that claim is that every envelope in hand came from a checked call.
    let envelope = ConcurrencyEnvelope::admit(WriterTopology::bounded_writers(4, 1))
        .expect("an admitted topology");
    assert_eq!(envelope.topology().writers, 1);
    assert_eq!(envelope.topology().connections, 4);
}
