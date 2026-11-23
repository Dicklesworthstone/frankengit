use super::*;
use crate::outcome::{AuthorityVersionToken, fold_outcome_index};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionOutcome, DecisionSequence, RefusalCode, RefusalRecordId,
    RepositoryCommitId,
};

fn token(value: u8) -> AuthorityVersionToken {
    AuthorityVersionToken::from_opaque_bytes([value; crate::tokens::VERSION_TOKEN_BYTES])
}

fn entry(identity: u64) -> (TxId, TerminalOutcome) {
    let mut bytes = [0x19; 32];
    bytes[24..].copy_from_slice(&identity.to_be_bytes());
    let bytes = DigestBytes::try_new(&bytes).unwrap();
    let tx_id = TxId::from_digest(
        IdentityDomain::RefTransaction.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        bytes,
    );
    let outcome = if identity.is_multiple_of(2) {
        DecisionOutcome::Committed {
            repository_commit_id: RepositoryCommitId::from_digest(
                IdentityDomain::RepositoryCommitRecord.algorithm().id(),
                CANONICAL_CODEC_VERSION,
                bytes,
            ),
        }
    } else {
        DecisionOutcome::Refused {
            code: RefusalCode::QuotaExceeded,
            refusal_record_id: RefusalRecordId::from_digest(
                IdentityDomain::RefusalRecord.algorithm().id(),
                CANONICAL_CODEC_VERSION,
                bytes,
            ),
        }
    };
    (
        tx_id,
        TerminalOutcome {
            decision_sequence: DecisionSequence::try_new(identity + 1).unwrap(),
            outcome,
        },
    )
}

#[test]
fn prepared_folds_and_lookups_match_reference_for_permuted_mixed_outcomes() {
    for length in [0, 1, 2, 3, 7, 32, 257] {
        let mut entries: Vec<_> = (0..length).map(entry).collect();
        for _ in 0..3 {
            let retained = CumulativeOutcomes::from_collected(token(1), entries.clone());
            assert_eq!(
                retained.fold_against(token(1), &[]),
                fold_outcome_index(&entries, &[])
            );
            for (tx_id, outcome) in &entries {
                assert_eq!(retained.decision_for(*tx_id), Some(*outcome));
            }
            assert_eq!(retained.decision_for(entry(length + 100).0), None);
            for added in [1, 3, 8] {
                let stamped: Vec<_> = (length..length + added).rev().map(entry).collect();
                assert_eq!(
                    retained.fold_against(token(1), &stamped),
                    fold_outcome_index(&entries, &stamped),
                );
            }
            entries.reverse();
            if !entries.is_empty() {
                entries.rotate_left(1);
            }
        }
    }
}

#[test]
fn corrupt_carried_histories_preserve_first_duplicate_and_first_read() {
    let mut changed = entry(9);
    changed.1.decision_sequence = DecisionSequence::try_new(100).unwrap();
    // The higher identity duplicates first in source order. A sorted scan that
    // simply reports the first equal key would instead report identity 1.
    for entries in [
        vec![entry(9), entry(1), changed, entry(1)],
        vec![entry(9), changed, entry(9)],
        vec![entry(1), entry(9), entry(1), changed],
    ] {
        let retained = CumulativeOutcomes::from_collected(token(1), entries.clone());
        for stamped in [vec![], vec![entry(0)], vec![entry(1), entry(1)]] {
            assert_eq!(
                retained.fold_against(token(1), &stamped),
                fold_outcome_index(&entries, &stamped),
            );
        }
        assert_eq!(
            retained.decision_for(entry(9).0),
            entries
                .iter()
                .find(|(tx_id, _)| *tx_id == entry(9).0)
                .map(|(_, outcome)| *outcome),
        );
    }
}

#[test]
fn new_batch_duplicates_preserve_reference_refusals_after_cache_warming() {
    let entries = vec![entry(9), entry(1), entry(5)];
    let retained = CumulativeOutcomes::from_collected(token(1), entries.clone());
    retained.fold_against(token(1), &[]).unwrap();
    for stamped in [
        vec![entry(2), entry(2)],
        vec![entry(9)],
        vec![entry(2), entry(1), entry(2)],
        vec![entry(2), entry(2), entry(1)],
    ] {
        assert_eq!(
            retained.fold_against(token(1), &stamped),
            fold_outcome_index(&entries, &stamped),
        );
        assert!(matches!(
            retained.fold_against(token(2), &stamped),
            Err(OutcomeFailure::CumulativeIndexStale { .. }),
        ));
    }
    assert_eq!(retained.len(), entries.len());
    assert_eq!(retained.decision_for(entry(2).0), None);
}

#[test]
fn incremental_indices_match_full_folds_and_do_not_change_older_clones() {
    let mut retained = CumulativeOutcomes::from_collected(token(1), Vec::new());
    let mut reference = Vec::new();
    for step in 0..16 {
        let older = retained.clone();
        let previous = retained.fold_against(token(1), &[]).unwrap();
        assert_eq!(
            retained, older,
            "warming computations does not change the witness"
        );
        let stamped: Vec<_> = (step * 7..(step + 1) * 7).rev().map(entry).collect();
        let prepared = retained.prepare_extension(&stamped).unwrap();
        reference.extend(stamped.iter().copied());
        assert_eq!(
            prepared.root(),
            fold_outcome_index(&reference, &[]).unwrap()
        );
        retained.retain_extension(stamped, prepared);
        assert_eq!(older.fold_against(token(1), &[]).unwrap(), previous);
        assert_eq!(older.decision_for(entry(step * 7).0), None);
        for (tx_id, outcome) in &reference {
            assert_eq!(retained.decision_for(*tx_id), Some(*outcome));
        }
        assert_eq!(
            retained.fold_against(token(1), &[]),
            fold_outcome_index(&reference, &[]),
        );
    }
}

#[test]
fn concurrent_first_use_preserves_one_exact_snapshot() {
    let entries: Vec<_> = (0..257).rev().map(entry).collect();
    let expected = fold_outcome_index(&entries, &[]).unwrap();
    let retained = CumulativeOutcomes::from_collected(token(1), entries);
    std::thread::scope(|scope| {
        for offset in 0..8 {
            let retained = &retained;
            scope.spawn(move || {
                assert_eq!(retained.fold_against(token(1), &[]).unwrap(), expected);
                for identity in (offset..257).step_by(8) {
                    let (tx_id, outcome) = entry(identity);
                    assert_eq!(retained.decision_for(tx_id), Some(outcome));
                }
            });
        }
    });
}

/// An explicit local CPU comparison, not a repository throughput claim.
#[test]
#[ignore = "run explicitly to compare retained-index CPU work with its reference fold"]
fn retained_index_workload_timings() {
    use std::hint::black_box;
    use std::time::Instant;

    let entries: Vec<_> = (0..4096).rev().map(entry).collect();
    let retained = CumulativeOutcomes::from_collected(token(1), entries.clone());
    let stamped = vec![entry(4096), entry(4097), entry(4098)];
    let expected = fold_outcome_index(&entries, &stamped).unwrap();
    assert_eq!(retained.fold_against(token(1), &stamped).unwrap(), expected);
    for sample in 0..5 {
        for variant in ["reference-a", "reference-control", "prepared"] {
            let start = Instant::now();
            for _ in 0..16 {
                let root = if variant == "prepared" {
                    retained
                        .fold_against(token(1), black_box(&stamped))
                        .unwrap()
                } else {
                    fold_outcome_index(black_box(&entries), black_box(&stamped)).unwrap()
                };
                assert_eq!(black_box(root), expected);
                for identity in (0..4096).step_by(16) {
                    let requested = black_box(entry(identity).0);
                    let result = if variant == "prepared" {
                        retained.decision_for(requested)
                    } else {
                        entries
                            .iter()
                            .find(|(tx_id, _)| *tx_id == requested)
                            .map(|(_, outcome)| *outcome)
                    };
                    assert_eq!(black_box(result), Some(entry(identity).1));
                }
            }
            eprintln!(
                "retained_index sample={sample} variant={variant} entries=4096 folds=16 lookups=4096 elapsed_us={}",
                start.elapsed().as_micros()
            );
        }
    }
}
