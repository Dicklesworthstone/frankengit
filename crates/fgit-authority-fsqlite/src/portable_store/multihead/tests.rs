use super::*;
use crate::{ExportBundle, export_bundle, import_bundle};

pub(super) fn sample() -> MultiHeadSnapshot {
    let rows = [
        (b"a".as_slice(), 5, b"a-old".as_slice()),
        (b"b", 1, b"b-old"),
        (b"a", 9, b"a-new"),
        (b"b", 2, b"b-new"),
    ];
    let issuance: Vec<_> = rows
        .into_iter()
        .enumerate()
        .map(|(index, (key, generation, body))| {
            let sequence = index as u64 + 1;
            ExportedIssuance {
                token: mint_token(
                    StoreInstanceId::from_raw(41),
                    IssuanceSequence::new(sequence).unwrap(),
                )
                .to_opaque_bytes()
                .to_vec(),
                sequence,
                head_key: key.to_vec(),
                generation,
                body: body.to_vec(),
            }
        })
        .collect();
    let heads = [2, 3]
        .map(|index| {
            let row = &issuance[index];
            ExportedHead {
                key: row.head_key.clone(),
                token: row.token.clone(),
                generation: row.generation,
                body: row.body.clone(),
            }
        })
        .to_vec();
    MultiHeadSnapshot {
        schema_version: SCHEMA_VERSION,
        instance: 41,
        bodies: vec![
            ExportedBody {
                key: vec![0],
                body: b"binary\0\xff".to_vec(),
            },
            ExportedBody {
                key: vec![255],
                body: b"another body".to_vec(),
            },
        ],
        heads,
        issuance,
    }
}
fn validate(value: &MultiHeadSnapshot) -> Result<(), PortableStoreError> {
    value.validate(MultiHeadLimits::default(), AuthorityLimits::default())
}
fn encoded(value: &MultiHeadSnapshot) -> Vec<u8> {
    encode_multi_head_snapshot(value, Default::default(), Default::default()).unwrap()
}
fn decode(bytes: &[u8]) -> Result<MultiHeadSnapshot, PortableStoreError> {
    decode_multi_head_snapshot(bytes, Default::default(), Default::default())
}
fn fields(value: &MultiHeadSnapshot) -> u64 {
    value
        .bodies
        .iter()
        .map(|row| (row.key.len() + row.body.len()) as u64)
        .sum::<u64>()
        + value
            .heads
            .iter()
            .map(|row| (row.key.len() + row.token.len() + row.body.len()) as u64)
            .sum::<u64>()
        + value
            .issuance
            .iter()
            .map(|row| (row.head_key.len() + row.token.len() + row.body.len()) as u64)
            .sum::<u64>()
}

#[test]
fn interleaved_histories_have_per_slot_not_global_generation_order() {
    let snapshot = sample();
    validate(&snapshot).unwrap();
    assert_eq!(
        snapshot
            .issuance
            .iter()
            .map(|row| row.generation)
            .collect::<Vec<_>>(),
        [5, 1, 9, 2]
    );
    assert_eq!(decode(&encoded(&snapshot)).unwrap(), snapshot);
    assert_eq!(encoded(&snapshot), encoded(&snapshot));
}

#[test]
fn schema_v2_does_not_reinterpret_or_rewrite_v1() {
    let snapshot = sample();
    assert!(import_bundle(&encoded(&snapshot)).is_err());
    let old = ExportBundle {
        schema_version: SCHEMA_VERSION,
        instance: 41,
        bodies: snapshot.bodies,
        head: None,
        issuance: vec![],
    };
    let bytes = export_bundle(&old).unwrap();
    assert_eq!(import_bundle(&bytes).unwrap(), old);
    assert!(decode(&bytes).is_err());
    assert_eq!(export_bundle(&old).unwrap(), bytes);
}

#[test]
fn missing_extra_old_and_contradictory_heads_are_rejected() {
    for mutation in 0..7 {
        let mut value = sample();
        match mutation {
            0 => {
                value.heads.pop();
            }
            1 => {
                let mut extra = value.heads[1].clone();
                extra.key = b"c".to_vec();
                value.heads.push(extra);
            }
            2 => {
                let old = &value.issuance[0];
                value.heads[0].token = old.token.clone();
                value.heads[0].generation = old.generation;
                value.heads[0].body = old.body.clone();
            }
            3 => value.heads[0].body.push(0),
            4 => value.heads[0].generation += 1,
            5 => value.heads[0].token[0] ^= 1,
            _ => value.heads[0].key = Vec::new(),
        }
        assert!(validate(&value).is_err(), "head mutation {mutation}");
        let malformed = fgit_codec::encode_body(&value).unwrap();
        assert!(decode(&malformed).is_err(), "decode mutation {mutation}");
    }
    validate(&sample()).unwrap();
}

#[test]
fn global_ledger_gaps_foreign_tokens_and_per_slot_rollback_are_rejected() {
    for mutation in 0..7 {
        let mut value = sample();
        match mutation {
            0 => {
                value.issuance.remove(1);
            }
            1 => value.issuance.swap(0, 1),
            2 => value.issuance[1].head_key = b"missing".to_vec(),
            3 => value.issuance[2].generation = value.issuance[0].generation,
            4 => {
                value.issuance[0].token =
                    mint_token(StoreInstanceId::from_raw(42), IssuanceSequence::FIRST)
                        .to_opaque_bytes()
                        .to_vec();
            }
            5 => value.issuance[1].generation = 0,
            _ => value.issuance[1].generation = u64::MAX,
        }
        assert!(validate(&value).is_err(), "ledger mutation {mutation}");
    }
}

#[test]
fn duplicated_and_misordered_keys_refuse_with_distinct_diagnostics() {
    let mut duplicate = sample();
    duplicate.heads[1] = duplicate.heads[0].clone();
    assert!(
        matches!(validate(&duplicate), Err(PortableStoreError::Bundle(error))
        if matches!(*error, BundleRefusal::Duplicated { collection: "heads" }))
    );
    let mut unordered = sample();
    unordered.heads.swap(0, 1);
    assert!(
        matches!(validate(&unordered), Err(PortableStoreError::Bundle(error))
        if matches!(*error, BundleRefusal::OutOfOrder { collection: "heads" }))
    );
    let mut duplicate = sample();
    duplicate.bodies[1] = duplicate.bodies[0].clone();
    assert!(validate(&duplicate).is_err());
    let mut unordered = sample();
    unordered.bodies.swap(0, 1);
    assert!(validate(&unordered).is_err());
}

#[test]
fn exact_limits_pass_but_each_independent_overage_refuses() {
    let value = sample();
    let exact = MultiHeadLimits {
        max_heads: 2,
        portable: PortableStoreLimits {
            max_bodies: 2,
            max_issuance: 4,
            max_field_bytes: fields(&value),
        },
    };
    value.validate(exact, Default::default()).unwrap();
    for limits in [
        MultiHeadLimits {
            max_heads: 1,
            ..exact
        },
        MultiHeadLimits {
            portable: PortableStoreLimits {
                max_bodies: 1,
                ..exact.portable
            },
            ..exact
        },
        MultiHeadLimits {
            portable: PortableStoreLimits {
                max_issuance: 3,
                ..exact.portable
            },
            ..exact
        },
        MultiHeadLimits {
            portable: PortableStoreLimits {
                max_field_bytes: fields(&value) - 1,
                ..exact.portable
            },
            ..exact
        },
    ] {
        assert!(matches!(
            value.validate(limits, Default::default()),
            Err(PortableStoreError::Limit(_))
        ));
    }
    for authority in [
        AuthorityLimits {
            head_slots: 1,
            ..Default::default()
        },
        AuthorityLimits {
            immutable_slots: 1,
            ..Default::default()
        },
        AuthorityLimits {
            version_tokens: 3,
            ..Default::default()
        },
        AuthorityLimits {
            body_bytes: 1,
            ..Default::default()
        },
    ] {
        assert!(value.validate(exact, authority).is_err());
    }
    assert!(
        value
            .validate(
                MultiHeadLimits {
                    max_heads: MAX_MULTI_HEADS + 1,
                    ..exact
                },
                Default::default()
            )
            .is_err()
    );
}

#[test]
fn empty_and_body_only_stores_are_supported_without_invented_heads() {
    let mut value = sample();
    value.heads.clear();
    value.issuance.clear();
    validate(&value).unwrap();
    assert_eq!(decode(&encoded(&value)).unwrap(), value);
    value.bodies.clear();
    value
        .validate(
            MultiHeadLimits {
                max_heads: 0,
                ..Default::default()
            },
            Default::default(),
        )
        .unwrap();
    assert_eq!(decode(&encoded(&value)).unwrap(), value);
}

#[test]
fn every_truncation_and_trailing_data_refuses() {
    let bytes = encoded(&sample());
    for end in 0..bytes.len() {
        assert!(decode(&bytes[..end]).is_err(), "truncated at {end}");
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(decode(&extra).is_err());
}

#[test]
fn validation_checkpoints_every_collection_and_never_changes_input() {
    let value = sample();
    let original = value.clone();
    let mut calls = 0;
    value
        .validate_with(Default::default(), Default::default(), || {
            calls += 1;
            Ok(())
        })
        .unwrap();
    assert!(calls >= value.bodies.len() + value.heads.len() * 2 + value.issuance.len());
    for stop in 1..=calls {
        let mut step = 0;
        assert!(
            value
                .validate_with(Default::default(), Default::default(), || {
                    step += 1;
                    if step == stop {
                        Err(PortableStoreError::Limit("injected checkpoint"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        assert_eq!(value, original);
    }
}
