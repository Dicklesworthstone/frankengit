//! Sparse in-batch snapshot updates retain every intermediate committed state.

use super::*;
use fgit_codec::RepositoryCommitRecord;

fn committed_records(
    authority: &Authority,
    context: &AdmissionContext,
) -> Vec<RepositoryCommitRecord> {
    let mut current = head(&authority.inner, context);
    let mut batches = Vec::new();
    while let Some(predecessor) = current.predecessor_head_id {
        let previous = read_authority_head_body(&authority.inner, predecessor).unwrap();
        let batch =
            read_decision_batch_body(&authority.inner, current.decision_tail_id.unwrap()).unwrap();
        verify_pair(
            &CryptoBodyIdentity,
            &PublicationBasis::new(predecessor, previous.clone()),
            &batch,
            &current,
        )
        .unwrap();
        batches.push(batch);
        current = previous;
    }
    batches
        .into_iter()
        .rev()
        .flat_map(|batch| batch.committed_rcrs)
        .collect()
}

#[test]
fn sparse_updates_preserve_large_inherited_maps_and_every_sequential_rcr() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let context = context(format, b"sparse-ref-state-equivalence");
        let inherited = (0..1024)
            .map(|index| format!("refs/heads/inherited-{index:04}"))
            .collect::<Vec<_>>();
        let mut initial = inherited
            .iter()
            .map(|key| (key.as_str(), 1))
            .collect::<Vec<_>>();
        initial.push(("refs/heads/main", 1));
        let mut commands = inherited[..64]
            .iter()
            .map(|key| command(format, key, 1, 2))
            .collect::<Vec<_>>();
        commands.extend([
            // The next chunk must start from the first chunk's exact state.
            command(format, &inherited[0], 2, 3),
            command(format, &inherited[0], 2, 4),
            command(format, &inherited[0], 3, 0),
            command(format, &inherited[0], 0, 0),
            command(format, &inherited[0], 0, 4),
            command(format, &format!("{}/child", inherited[0]), 0, 2),
            command(format, "refs/heads/main", 1, 0),
            command(format, &inherited[1023], 1, 3),
        ]);
        let input = receive(format, commands, false);
        let (reference, reference_bodies, reference_projection) =
            setup(&context, &initial, Some("refs/heads/main"));
        let expected = admit_validated_receive(
            &reference.inner,
            &context,
            &input,
            AdmissionLimits::default(),
            &Sequential(&reference_projection),
        )
        .unwrap();
        let expected_refs = refs(&reference.inner, &reference_bodies, &context);
        let expected_records = committed_records(&reference, &context);

        for blocking in [false, true] {
            let (authority, staging, projection) =
                setup(&context, &initial, Some("refs/heads/main"));
            let initial_versions = authority.inner.issued_versions();
            let actual = if blocking {
                admit_validated_receive(
                    &authority.inner,
                    &context,
                    &input,
                    AdmissionLimits::default(),
                    &projection,
                )
                .unwrap()
            } else {
                let result = run(&authority, &context, &input, &projection);
                assert_eq!(authority.publications.load(Ordering::SeqCst), 2);
                result
            };
            assert_eq!(actual.session, expected.session);
            assert_eq!(actual.command_statuses(), expected.command_statuses());
            assert_eq!(codes(&actual), codes(&expected));
            assert_eq!(refs(&authority.inner, &staging, &context), expected_refs);
            assert_eq!(
                committed_records(&authority, &context),
                expected_records,
                "every RCR and its intermediate ref commitment must match the sequential oracle"
            );
            assert_eq!(
                authority.inner.issued_versions(),
                initial_versions + 2,
                "both drivers must publish exactly two new head versions"
            );
            verify_outcomes(&authority.inner, &context, &actual);
        }
        assert_eq!(
            codes(&expected)[65],
            Some(RefusalCode::ExpectedOldRefMismatch)
        );
        assert_eq!(codes(&expected)[69], Some(RefusalCode::RefNameConflict));
        assert_eq!(
            codes(&expected)[70],
            Some(RefusalCode::ProtectedRefTransitionDenied)
        );
        assert_eq!(expected_refs.refs().len(), initial.len());
        assert_eq!(expected_refs.refs()[&name(&inherited[0])], oid(format, 4));
        for key in &inherited[64..1023] {
            assert_eq!(expected_refs.refs()[&name(key)], oid(format, 1));
        }
    }
}

fn name(value: &str) -> RefName {
    RefName::try_new(value.as_bytes()).unwrap()
}
