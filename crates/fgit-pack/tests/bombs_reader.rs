#![forbid(unsafe_code)]

mod fixtures;

use fgit_deflate::{DeflateLimits, DeflateProfile, InflateRefusal, Resource, deflate_zlib};
use fgit_pack::{
    ObjectFormat, PackError, PackTrailerVerifier, QuarantinedPack, parse_quarantined_pack,
    read_verified_pack,
};

struct ExactTrailer;

impl PackTrailerVerifier for ExactTrailer {
    fn verify(&self, _body: &[u8], trailer: &[u8], _format: ObjectFormat) -> bool {
        trailer == fixtures::SHA1_TRAILER
    }
}

struct RejectTrailer;

impl PackTrailerVerifier for RejectTrailer {
    fn verify(&self, _body: &[u8], _trailer: &[u8], _format: ObjectFormat) -> bool {
        false
    }
}

fn visible_quarantine_bytes(result: &Result<QuarantinedPack, PackError>) -> usize {
    result.as_ref().map_or(0, |pack| {
        pack.entries()
            .iter()
            .map(|entry| entry.inflated.len())
            .sum()
    })
}

#[test]
fn declared_size_and_aggregate_bombs_trip_before_entry_output_allocation() {
    let mut object_limited = fixtures::limits();
    object_limited.max_object_bytes = 16;
    let declared = object_limited.max_object_bytes + 1;
    let oversized = fixtures::pack_with_entries(&[fixtures::declared_entry(3, declared, &[])]);
    let refusal = parse_quarantined_pack(
        &oversized,
        ObjectFormat::Sha1,
        &object_limited,
        &mut fixtures::always,
    );
    assert_eq!(
        refusal,
        Err(PackError::ObjectSizeLimit {
            actual: declared,
            limit: object_limited.max_object_bytes,
        })
    );
    assert_eq!(visible_quarantine_bytes(&refusal), 0);

    let accepted = fixtures::pack_with_entries(&[fixtures::entry(3, &[7; 16])]);
    let parsed = parse_quarantined_pack(
        &accepted,
        ObjectFormat::Sha1,
        &object_limited,
        &mut fixtures::always,
    )
    .expect("near-identical entry at the declared-size ceiling is admitted to quarantine");
    assert_eq!(
        parsed.entries()[0].inflated.len(),
        object_limited.max_object_bytes
    );

    let mut aggregate_limited = fixtures::limits();
    aggregate_limited.max_object_bytes = 16;
    aggregate_limited.max_total_expanded_bytes = 15;
    let aggregate = fixtures::pack_with_entries(&[fixtures::entry(3, &[1; 16])]);
    let refusal = parse_quarantined_pack(
        &aggregate,
        ObjectFormat::Sha1,
        &aggregate_limited,
        &mut fixtures::always,
    );
    assert_eq!(
        refusal,
        Err(PackError::TotalExpandedLimit {
            actual: 16,
            limit: 15,
        })
    );
    assert_eq!(visible_quarantine_bytes(&refusal), 0);

    aggregate_limited.max_total_expanded_bytes = 16;
    assert!(
        parse_quarantined_pack(
            &aggregate,
            ObjectFormat::Sha1,
            &aggregate_limited,
            &mut fixtures::always,
        )
        .is_ok(),
        "the same entry is admissible at the aggregate-byte ceiling"
    );
}

#[test]
fn entry_and_input_budgets_refuse_before_a_quarantined_pack_is_constructed() {
    let pack = fixtures::pack_with_entries(&[fixtures::entry(3, b"ok")]);

    let mut entry_limited = fixtures::limits();
    entry_limited.max_entries = 0;
    let refusal = parse_quarantined_pack(
        &pack,
        ObjectFormat::Sha1,
        &entry_limited,
        &mut fixtures::always,
    );
    assert_eq!(
        refusal,
        Err(PackError::EntryCountLimit {
            actual: 1,
            limit: 0,
        })
    );
    assert_eq!(visible_quarantine_bytes(&refusal), 0);

    entry_limited.max_entries = 1;
    assert!(
        parse_quarantined_pack(
            &pack,
            ObjectFormat::Sha1,
            &entry_limited,
            &mut fixtures::always,
        )
        .is_ok(),
        "the same one-entry pack is admitted at the entry ceiling"
    );

    let mut input_limited = fixtures::limits();
    input_limited.max_input_bytes = pack.len() - 1;
    let refusal = parse_quarantined_pack(
        &pack,
        ObjectFormat::Sha1,
        &input_limited,
        &mut fixtures::always,
    );
    assert_eq!(
        refusal,
        Err(PackError::InputLimit {
            actual: pack.len(),
            limit: input_limited.max_input_bytes,
        })
    );
    assert_eq!(visible_quarantine_bytes(&refusal), 0);
}

#[test]
fn ratio_bomb_refuses_during_inflate_and_a_permitted_member_quarantines() {
    let payload = vec![0_u8; 2_048];
    let member = deflate_zlib(&payload, DeflateLimits::GIT_OBJECT, DeflateProfile::DEFAULT)
        .expect("deterministic test bomb member");
    let pack = fixtures::pack_with_entries(&[fixtures::declared_entry(3, payload.len(), &member)]);

    let mut ratio_limited = fixtures::limits();
    ratio_limited.max_object_bytes = payload.len();
    ratio_limited.max_total_expanded_bytes = payload.len();
    ratio_limited.max_expansion_ratio = 1;
    let refusal = parse_quarantined_pack(
        &pack,
        ObjectFormat::Sha1,
        &ratio_limited,
        &mut fixtures::always,
    );
    assert!(matches!(
        refusal,
        Err(PackError::Inflate(InflateRefusal::ResourceLimit {
            resource: Resource::ExpansionRatio,
            ..
        }))
    ));

    ratio_limited.max_expansion_ratio = 256;
    let parsed = parse_quarantined_pack(
        &pack,
        ObjectFormat::Sha1,
        &ratio_limited,
        &mut fixtures::always,
    )
    .expect("the same member is accepted under the declared compatibility ratio");
    assert_eq!(parsed.entries()[0].inflated, payload);
}

#[test]
fn truncated_or_untrusted_trailer_keeps_refused_pack_unobservable() {
    let valid = fixtures::pack_with_entries(&[fixtures::entry(3, &[])]);
    let parsed = read_verified_pack(
        &valid,
        ObjectFormat::Sha1,
        &fixtures::limits(),
        &mut fixtures::always,
        &ExactTrailer,
    )
    .expect("zero-length blob remains a valid near-neighbor pack");
    assert_eq!(parsed.entries()[0].inflated, b"");

    let truncated = valid[..12].to_vec();
    let refusal = read_verified_pack(
        &truncated,
        ObjectFormat::Sha1,
        &fixtures::limits(),
        &mut fixtures::always,
        &ExactTrailer,
    );
    assert_eq!(
        refusal,
        Err(PackError::Truncated {
            context: "pack trailer",
        })
    );
    assert_eq!(visible_quarantine_bytes(&refusal), 0);

    let refusal = read_verified_pack(
        &valid,
        ObjectFormat::Sha1,
        &fixtures::limits(),
        &mut fixtures::always,
        &RejectTrailer,
    );
    assert_eq!(refusal, Err(PackError::TrailerChecksumMismatch));
    assert_eq!(visible_quarantine_bytes(&refusal), 0);
}
