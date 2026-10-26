//! The live receiver enforces a smaller configured command envelope before
//! admission and returns a bounded, actionable Git fatal packet.

use super::*;

#[test]
fn configured_command_ceiling_refuses_before_admission_and_accepts_its_boundary() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let limits = fgit_wire::receive::ReceiveLimits {
        max_commands: 2,
        ..fgit_wire::receive::ReceiveLimits::default()
    };
    let config = scratch
        .config(format, true)
        .with_git_daemon_receive_limits(limits);
    let node = start(config, false);
    let path = route(&node);
    let before = state(&node);
    let (_, zero, _) = pack(format);
    let commands = [
        (zero, zero, "refs/tags/first"),
        (zero, zero, "refs/tags/second"),
        (zero, zero, "refs/tags/excess"),
    ];
    let excess = prefix(format, &commands, false);
    let (node, refused, rows) = push(node, &excess, &[], false);
    let Err(NodeSmartHttpRefusal::Receive(error)) = refused else {
        panic!("the parser must return its typed command-count failure");
    };
    assert!(matches!(
        *error,
        fgit_wire::receive::ReceiveError::TooManyCommands { limit: 2 }
    ));
    assert_eq!(rows, [
        b"ERR receive command count exceeded: observed at least 3; maximum 2; split the push into batches of at most 2 commands; this invocation stopped before admission\n".to_vec(),
    ]);
    assert_eq!(state(&node), before);
    assert!(matches!(
        node.runtime()
            .block_on(
                node.recover_receive_session_in(&node.request_context(), &session(&path, &excess),)
            )
            .unwrap(),
        SessionRecovery::NotObserved,
    ));

    let permitted = prefix(format, &commands[..2], false);
    let (node, accepted, rows) = push(node, &permitted, &[], false);
    let accepted = accepted.unwrap().unwrap();
    assert_eq!(
        rows,
        [
            b"unpack ok\n".to_vec(),
            b"ok refs/tags/first\n".to_vec(),
            b"ok refs/tags/second\n".to_vec(),
        ]
    );
    assert_eq!(accepted.commands.len(), 2);
    assert_ne!(accepted.commands[0].tx_id, accepted.commands[1].tx_id);
    assert!(
        accepted
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    assert_eq!(state(&node), (before.0 + 1, before.1));
    recovered(&node, &path, &permitted, &accepted);
    node.shutdown().unwrap();
}
