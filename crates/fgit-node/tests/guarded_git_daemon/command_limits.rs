//! Real TCP command-count refusal and its just-inside permitted twin.

use super::*;
use fgit_wire::receive::{ReceiveError, ReceiveLimits};

#[test]
fn command_limit_reports_observed_and_maximum_without_any_ref_decision() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for atomic in [false, true] {
            let scratch = Scratch::new();
            let config =
                scratch
                    .config(format, true)
                    .with_git_daemon_receive_limits(ReceiveLimits {
                        max_commands: 2,
                        ..ReceiveLimits::default()
                    });
            let node = start(config, false);
            let before = state(&node);
            let (oid, zero, pack) = pack(format);
            let commands = [
                (zero, oid, "refs/tags/a"),
                (zero, oid, "refs/tags/b"),
                (zero, oid, "refs/tags/c"),
            ];
            let (node, refused, rows) =
                push(node, &prefix(format, &commands, atomic), &pack, false);
            assert!(
                matches!(refused, Err(NodeSmartHttpRefusal::Receive(error)) if matches!(*error, ReceiveError::TooManyCommands { limit: 2 }))
            );
            assert_eq!(rows.len(), 1);
            let message = std::str::from_utf8(&rows[0]).unwrap();
            assert!(message.starts_with(
                "ERR receive command count exceeded: observed at least 3; maximum 2;"
            ));
            assert!(message.contains("split the push into batches of at most 2 commands"));
            assert!(message.ends_with("no ref decision was attempted\n"));
            assert_eq!(state(&node), before);

            let (node, allowed, rows) =
                push(node, &prefix(format, &commands[..2], atomic), &pack, false);
            let allowed = allowed.unwrap().unwrap();
            assert_eq!(allowed.commands.len(), 2);
            assert!(allowed.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            )));
            assert_eq!(
                rows,
                [
                    b"unpack ok\n".to_vec(),
                    b"ok refs/tags/a\n".to_vec(),
                    b"ok refs/tags/b\n".to_vec()
                ]
            );
            assert_eq!(state(&node).1.len(), 2);
            node.shutdown().unwrap();
        }
    }
}
