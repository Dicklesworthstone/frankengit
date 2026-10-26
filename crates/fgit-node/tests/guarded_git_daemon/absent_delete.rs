//! Conditional absent-ref deletion through a real receive session (l6mb).

use super::*;

#[test]
fn absent_delete_and_create_report_success_and_recover_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for atomic in [false, true] {
            let scratch = Scratch::new();
            let config = scratch.config(format, true);
            let node = start(config.clone(), false);
            let path = route(&node);
            let (oid, zero, pack) = pack(format);
            let delete = prefix(format, &[(zero, zero, "refs/tags/absent")], atomic);
            let (node, result, rows) = push(node, &delete, &[], false);
            let deleted = result.unwrap().unwrap();
            assert_eq!(
                rows,
                [b"unpack ok\n".to_vec(), b"ok refs/tags/absent\n".to_vec()]
            );
            assert!(state(&node).1.is_empty());
            if !atomic {
                recovered(&node, &path, &delete, &deleted);
            }

            let commands = prefix(
                format,
                &[
                    (zero, zero, "refs/tags/absent"),
                    (zero, oid, "refs/tags/created"),
                ],
                atomic,
            );
            let (node, result, rows) = push(node, &commands, &pack, false);
            let admitted = result.unwrap().unwrap();
            assert_eq!(
                rows,
                [
                    b"unpack ok\n".to_vec(),
                    b"ok refs/tags/absent\n".to_vec(),
                    b"ok refs/tags/created\n".to_vec(),
                ]
            );
            assert_eq!(
                state(&node).1,
                BTreeMap::from([(RefName::try_new(b"refs/tags/created").unwrap(), oid,)])
            );
            if !atomic {
                recovered(&node, &path, &commands, &admitted);
            }
            let published = state(&node);
            node.shutdown().unwrap();

            let node = start(config, true);
            if !atomic {
                recovered(&node, &path, &delete, &deleted);
                recovered(&node, &path, &commands, &admitted);
            }
            let (node, retry, retried_rows) = push(node, &commands, &pack, false);
            assert_eq!(retry.unwrap().unwrap(), admitted);
            assert_eq!(retried_rows, rows);
            assert_eq!(state(&node), published);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn zero_old_preserves_present_refs_and_only_atomic_mode_refuses_the_other_command() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for atomic in [false, true] {
            let scratch = Scratch::new();
            let node = start(scratch.config(format, true), false);
            let (oid, zero, pack) = pack(format);
            let (node, seeded, _) = push(
                node,
                &prefix(format, &[(zero, oid, "refs/tags/present")], true),
                &pack,
                false,
            );
            assert!(matches!(
                seeded.unwrap().unwrap().commands[0].terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));

            let commands = prefix(
                format,
                &[
                    (zero, zero, "refs/tags/present"),
                    (zero, oid, "refs/tags/created"),
                ],
                atomic,
            );
            let (node, result, rows) = push(node, &commands, &pack, false);
            let result = result.unwrap().unwrap();
            assert!(matches!(
                result.commands[0].terminal.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::ExpectedOldRefMismatch,
                    ..
                }
            ));
            // Atomic wire reports deliberately normalize every rejected
            // command to the same group-abort text (receive_protocol.rs).
            // The terminal reason above remains the exact stale-old refusal.
            assert_eq!(
                rows[1],
                if atomic {
                    b"ng refs/tags/present atomic push failed\n".as_slice()
                } else {
                    b"ng refs/tags/present stale info\n".as_slice()
                }
            );
            assert_eq!(
                rows[2],
                if atomic {
                    b"ng refs/tags/created atomic push failed\n".as_slice()
                } else {
                    b"ok refs/tags/created\n".as_slice()
                }
            );
            let current = state(&node).1;
            assert_eq!(
                current.get(&RefName::try_new(b"refs/tags/present").unwrap()),
                Some(&oid)
            );
            assert_eq!(
                current.contains_key(&RefName::try_new(b"refs/tags/created").unwrap()),
                !atomic
            );

            let (node, permitted, rows) = push(
                node,
                &prefix(format, &[(oid, zero, "refs/tags/present")], atomic),
                &[],
                false,
            );
            assert!(matches!(
                permitted.unwrap().unwrap().commands[0].terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
            assert_eq!(
                rows,
                [b"unpack ok\n".to_vec(), b"ok refs/tags/present\n".to_vec()]
            );
            assert!(
                !state(&node)
                    .1
                    .contains_key(&RefName::try_new(b"refs/tags/present").unwrap())
            );
            node.shutdown().unwrap();
        }
    }
}
