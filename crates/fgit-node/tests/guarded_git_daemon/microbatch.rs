//! Independent receive transactions share one durable publication while each
//! retains its own status, seal, decision and restart recovery identity.
//!
//! All requests use the real TCP receiver, native pack validation and embedded
//! authority. Generation assertions measure publication count, not throughput.

use super::*;
use fgit_authority::key_recovery::RequestRecovery;
use fgit_codec::RepositoryAuthorityHeadBody;
use std::collections::BTreeSet;

fn head(node: &OneNode) -> RepositoryAuthorityHeadBody {
    node.runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .body()
        .unwrap()
}

fn shared_successor(
    before: &RepositoryAuthorityHeadBody,
    after: &RepositoryAuthorityHeadBody,
    result: &AdmissionResult,
) {
    assert!(!result.session.atomic);
    assert_eq!(after.generation.get(), before.generation.get() + 1);
    assert_eq!(
        after.predecessor_head_id,
        Some(fgit_authority::authority_head_identity(before).unwrap()),
        "every logical decision must belong to this one successor"
    );
    let prior_decisions = before
        .latest_decision_sequence
        .map_or(0, |value| value.get());
    assert_eq!(
        after.latest_decision_sequence.unwrap().get(),
        prior_decisions + u64::try_from(result.commands.len()).unwrap()
    );
    assert_eq!(
        result
            .session
            .tx_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len(),
        result.commands.len(),
        "a physical batch must not collapse independent transaction identities"
    );
    for (index, command) in result.commands.iter().enumerate() {
        assert_eq!(command.tx_id, result.session.tx_ids[index]);
        assert_eq!(
            command.terminal.decision_sequence.get(),
            prior_decisions + u64::try_from(index).unwrap() + 1,
            "terminal decisions preserve wire order"
        );
    }
    let commits = result
        .commands
        .iter()
        .filter_map(|command| match command.terminal.outcome {
            DecisionOutcome::Committed {
                repository_commit_id,
            } => Some(repository_commit_id),
            DecisionOutcome::Refused { .. } => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        commits.iter().copied().collect::<BTreeSet<_>>().len(),
        commits.len()
    );
    assert_eq!(
        after
            .latest_repository_sequence
            .map_or(0, |value| value.get()),
        before
            .latest_repository_sequence
            .map_or(0, |value| value.get())
            + u64::try_from(commits.len()).unwrap(),
        "every accepted command retains its own repository commit record"
    );
}

fn exact_recovery(
    node: &OneNode,
    path: &str,
    prefix: &[u8],
    commands: &[(GitOid, GitOid, &str)],
    expected: &AdmissionResult,
) -> SessionRecovery {
    let before = head(node);
    let observed = node
        .runtime()
        .block_on(node.recover_receive_session_in(&node.request_context(), &session(path, prefix)))
        .unwrap();
    let SessionRecovery::Recovered(known) = &observed else {
        panic!("a published non-atomic session must have a recoverable descriptor");
    };
    assert!(known.all_terminal());
    assert_eq!(known.commands().len(), commands.len());
    for (index, (command, result)) in known.commands().iter().zip(&expected.commands).enumerate() {
        assert_eq!(command.index(), index);
        assert_eq!(command.reference().as_bytes(), commands[index].2.as_bytes());
        let RequestRecovery::Recovered(request) = command.recovery() else {
            panic!("each terminal decision must be bound to its original seal");
        };
        assert_eq!(request.tx_id(), result.tx_id);
        assert_eq!(command.recovery().terminal(), Some(result.terminal));
    }
    assert_eq!(head(node), before, "read-only recovery must not republish");
    observed
}

#[test]
fn sixty_four_native_refs_share_one_publication_and_recover_exactly_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = scratch.config(format, true);
        let node = start(config.clone(), false);
        let path = route(&node);
        let before = head(&node);
        let (oid, zero, pack) = pack(format);
        // Reverse order distinguishes original wire order from the canonical
        // ordering of the whole-request descriptor and final ref map.
        let names = (0..64)
            .rev()
            .map(|index| format!("refs/tags/batch-{index:02}"))
            .collect::<Vec<_>>();
        let commands = names
            .iter()
            .map(|name| (zero, oid, name.as_str()))
            .collect::<Vec<_>>();
        let prefix = prefix(format, &commands, false);
        let (node, result, rows) = push(node, &prefix, &pack, false);
        let result = result.unwrap().unwrap();
        assert_eq!(result.commands.len(), 64);
        assert!(
            result.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        let mut expected_rows = vec![b"unpack ok\n".to_vec()];
        expected_rows.extend(names.iter().map(|name| format!("ok {name}\n").into_bytes()));
        assert_eq!(rows, expected_rows);
        let published = head(&node);
        shared_successor(&before, &published, &result);
        let expected_refs = names
            .iter()
            .map(|name| (RefName::try_new(name.as_bytes()).unwrap(), oid))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(state(&node).1, expected_refs);
        let recovery = exact_recovery(&node, &path, &prefix, &commands, &result);
        node.shutdown().unwrap();

        let node = start(config, true);
        assert_eq!(head(&node), published);
        assert_eq!(state(&node).1, expected_refs);
        assert_eq!(
            exact_recovery(&node, &path, &prefix, &commands, &result),
            recovery
        );
        let (node, repeated, repeated_rows) = push(node, &prefix, &pack, false);
        assert_eq!(repeated.unwrap().unwrap(), result);
        assert_eq!(repeated_rows, rows);
        assert_eq!(head(&node), published);
        assert_eq!(state(&node).1, expected_refs);
        node.shutdown().unwrap();
    }
}

#[test]
fn native_many_ref_receive_uses_bounded_chunks_and_recovers_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = scratch.config(format, true);
        let node = start(config.clone(), false);
        let path = route(&node);
        let before = head(&node);
        let (oid, zero, pack) = pack(format);
        // Cross two physical chunk boundaries while distinguishing wire order
        // from the canonical order of the sealed request and final ref map.
        let names = (0..129)
            .rev()
            .map(|index| format!("refs/tags/chunked-{index:03}"))
            .collect::<Vec<_>>();
        let commands = names
            .iter()
            .map(|name| (zero, oid, name.as_str()))
            .collect::<Vec<_>>();
        let prefix = prefix(format, &commands, false);
        let (node, result, rows) = push(node, &prefix, &pack, false);
        let result = result.unwrap().unwrap();
        assert!(!result.session.atomic);
        assert_eq!(result.commands.len(), commands.len());
        assert_eq!(result.session.tx_ids.len(), commands.len());
        assert_eq!(
            result
                .session
                .tx_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            commands.len(),
            "chunking must preserve independent transaction identities"
        );
        let mut expected_rows = vec![b"unpack ok\n".to_vec()];
        expected_rows.extend(names.iter().map(|name| format!("ok {name}\n").into_bytes()));
        assert_eq!(rows, expected_rows);

        let published = head(&node);
        assert_eq!(published.generation.get(), before.generation.get() + 3);
        let prior_decisions = before
            .latest_decision_sequence
            .map_or(0, |sequence| sequence.get());
        assert_eq!(
            published.latest_decision_sequence.unwrap().get(),
            prior_decisions + 129
        );
        assert_eq!(
            published.latest_repository_sequence.unwrap().get(),
            before
                .latest_repository_sequence
                .map_or(0, |sequence| sequence.get())
                + 129
        );

        // This production API authenticates every predecessor, batch and
        // committed evidence object. Inspect the actual immutable batches,
        // rather than inferring their boundaries from the final generation.
        let history = node
            .runtime()
            .block_on(node.snapshot_history_in(&node.request_context()))
            .unwrap();
        let batches = history
            .iter()
            .filter(|entry| entry.resulting_head_generation > before.generation)
            .collect::<Vec<_>>();
        assert_eq!(
            batches
                .iter()
                .map(|entry| entry.batch.decisions.len())
                .collect::<Vec<_>>(),
            [64, 64, 1]
        );
        assert_eq!(
            batches
                .iter()
                .map(|entry| entry.batch.committed_rcrs.len())
                .collect::<Vec<_>>(),
            [64, 64, 1]
        );
        for (index, entry) in batches.iter().enumerate() {
            assert_eq!(
                entry.resulting_head_generation.get(),
                before.generation.get() + u64::try_from(index).unwrap() + 1
            );
        }
        assert_eq!(
            batches.last().unwrap().resulting_head_id,
            fgit_authority::authority_head_identity(&published).unwrap()
        );
        let decisions = batches
            .iter()
            .flat_map(|entry| &entry.batch.decisions)
            .collect::<Vec<_>>();
        let mut repository_commits = BTreeSet::new();
        for (index, (decision, command)) in decisions.iter().zip(&result.commands).enumerate() {
            assert_eq!(command.tx_id, result.session.tx_ids[index]);
            assert_eq!(decision.tx_id, command.tx_id);
            assert_eq!(
                decision.decision_sequence,
                command.terminal.decision_sequence
            );
            assert_eq!(decision.outcome, command.terminal.outcome);
            assert_eq!(
                command.terminal.decision_sequence.get(),
                prior_decisions + u64::try_from(index).unwrap() + 1,
                "chunk continuation must preserve original wire order"
            );
            let DecisionOutcome::Committed {
                repository_commit_id,
            } = command.terminal.outcome
            else {
                panic!("every native tag create must commit");
            };
            assert!(repository_commits.insert(repository_commit_id));
        }
        let expected_refs = names
            .iter()
            .map(|name| (RefName::try_new(name.as_bytes()).unwrap(), oid))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(state(&node).1, expected_refs);
        let recovery = exact_recovery(&node, &path, &prefix, &commands, &result);
        let (node, repeated, repeated_rows) = push(node, &prefix, &pack, false);
        assert_eq!(repeated.unwrap().unwrap(), result);
        assert_eq!(repeated_rows, rows);
        assert_eq!(head(&node), published);
        node.shutdown().unwrap();

        let node = start(config, true);
        assert_eq!(head(&node), published);
        assert_eq!(state(&node).1, expected_refs);
        assert_eq!(
            node.runtime()
                .block_on(node.snapshot_history_in(&node.request_context()))
                .unwrap(),
            history
        );
        assert_eq!(
            exact_recovery(&node, &path, &prefix, &commands, &result),
            recovery
        );
        let (node, repeated, repeated_rows) = push(node, &prefix, &pack, false);
        assert_eq!(repeated.unwrap().unwrap(), result);
        assert_eq!(repeated_rows, rows);
        assert_eq!(head(&node), published);
        assert_eq!(state(&node).1, expected_refs);
        node.shutdown().unwrap();
    }
}

#[test]
fn native_mixed_batch_reads_prior_refs_without_poisoning_accepted_siblings() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = scratch.config(format, true);
        let node = start(config.clone(), false);
        let path = route(&node);
        let (oid, zero, pack) = pack(format);
        let seed = prefix(format, &[(zero, oid, "refs/tags/existing")], true);
        let (node, seeded, _) = push(node, &seed, &pack, false);
        assert!(matches!(
            seeded.unwrap().unwrap().commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let before = head(&node);
        let commands = [
            (oid, oid, "refs/tags/stale"),
            (zero, oid, "refs/tags/tree"),
            (zero, oid, "refs/tags/tree/child"),
            (zero, zero, "refs/tags/absent"),
            (oid, zero, "refs/tags/existing"),
            (zero, oid, "refs/tags/after"),
        ];
        let prefix = prefix(format, &commands, false);
        let (node, result, rows) = push(node, &prefix, &pack, false);
        let result = result.unwrap().unwrap();
        let codes = result
            .commands
            .iter()
            .map(|command| match command.terminal.outcome {
                DecisionOutcome::Committed { .. } => None,
                DecisionOutcome::Refused { code, .. } => Some(code),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            [
                Some(RefusalCode::ExpectedOldRefMismatch),
                None,
                Some(RefusalCode::RefNameConflict),
                None,
                None,
                None,
            ],
            "the namespace conflict must observe the earlier create, and each later sibling must still be evaluated"
        );
        assert_eq!(
            rows,
            [
                b"unpack ok\n".to_vec(),
                b"ng refs/tags/stale stale info\n".to_vec(),
                b"ok refs/tags/tree\n".to_vec(),
                b"ng refs/tags/tree/child refname conflict\n".to_vec(),
                b"ok refs/tags/absent\n".to_vec(),
                b"ok refs/tags/existing\n".to_vec(),
                b"ok refs/tags/after\n".to_vec(),
            ]
        );
        let published = head(&node);
        shared_successor(&before, &published, &result);
        let expected_refs = BTreeMap::from([
            (RefName::try_new(b"refs/tags/tree").unwrap(), oid),
            (RefName::try_new(b"refs/tags/after").unwrap(), oid),
        ]);
        assert_eq!(state(&node).1, expected_refs);
        let recovery = exact_recovery(&node, &path, &prefix, &commands, &result);
        node.shutdown().unwrap();

        let node = start(config, true);
        assert_eq!(head(&node), published);
        assert_eq!(
            exact_recovery(&node, &path, &prefix, &commands, &result),
            recovery
        );
        let (node, repeated, repeated_rows) = push(node, &prefix, &pack, false);
        assert_eq!(repeated.unwrap().unwrap(), result);
        assert_eq!(repeated_rows, rows);
        assert_eq!(head(&node), published);
        assert_eq!(state(&node).1, expected_refs);
        node.shutdown().unwrap();
    }
}
