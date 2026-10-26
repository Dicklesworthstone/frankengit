//! Cross the single-seal limit through actual HTTP intake, native admission,
//! embedded authority, restart and read-only original-key recovery.

use super::*;
use fgit_admission::policy_bridge::receive_session::recovery::SessionRecovery;
use fgit_authority::key_recovery::RequestRecovery;
use std::collections::BTreeSet;

fn original_session() -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xd3; 16]),
        IdempotencyKey::new(b"large-http-session".to_vec()).unwrap(),
    )
}

fn recover(node: &OneNode, names: &[String], expected: &AdmissionResult) {
    let before = state(node);
    // Use the finite operator-command envelope used by original-key CLI
    // recovery, covering the whole session instead of one database command.
    let request = node.command_request_context(None);
    let report = node
        .runtime()
        .block_on(node.recover_receive_session_in(&request, &original_session()))
        .unwrap();
    let SessionRecovery::Recovered(known) = report else {
        panic!("a completed large session must be recoverable by its original key");
    };
    assert!(known.all_terminal());
    assert_eq!(known.commands().len(), names.len());
    for (index, (observed, expected)) in known.commands().iter().zip(&expected.commands).enumerate()
    {
        assert_eq!(observed.index(), index);
        assert_eq!(observed.reference().as_bytes(), names[index].as_bytes());
        assert_eq!(observed.recovery().terminal(), Some(expected.terminal));
        let RequestRecovery::Recovered(request) = observed.recovery() else {
            panic!("terminal recovery must authenticate the original child seal");
        };
        assert_eq!(request.tx_id(), expected.tx_id);
    }
    assert_eq!(state(node), before, "recovery must remain read-only");
}

#[test]
fn large_non_atomic_http_session_publishes_and_recovers_across_restart() {
    const COUNT: usize = fgit_admission::MAX_ADMISSION_COMMANDS + 1;
    // Delete-only no-ops isolate session scaling from blob and ref-map growth.
    // Every command still has a real seal, canonical terminal outcome and
    // restart recovery identity through the embedded production authority.
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = config(&scratch, format);
        assert_eq!(config.authority_limits().immutable_slots, 262_144);
        let node = start(config.clone(), false);
        let (_, zero, _) = blob_pack(format);
        let names = (0..COUNT)
            .rev()
            .map(|index| format!("refs/tags/large-{index:05}"))
            .collect::<Vec<_>>();
        let commands = names
            .iter()
            .map(|name| (zero, zero, name.as_str()))
            .collect::<Vec<_>>();
        let before = state(&node);
        let decisions_before = decision_counts(&node);
        let mut output = Vec::new();
        let result = perform(
            &node,
            b"large-http-session",
            &commands,
            &[],
            false,
            true,
            &mut output,
        )
        .unwrap();
        assert!(!result.session.atomic);
        assert_eq!(result.commands.len(), COUNT);
        assert_eq!(result.session.tx_ids.len(), COUNT);
        assert_eq!(
            result.session.tx_ids.iter().collect::<BTreeSet<_>>().len(),
            COUNT
        );
        for index in 0..COUNT {
            committed(&result, index);
            assert_eq!(result.commands[index].tx_id, result.session.tx_ids[index]);
        }
        let published = state(&node);
        assert_eq!(published.1, before.1);
        assert_eq!(
            published.0.get(),
            before.0.get() + u64::try_from(COUNT.div_ceil(64)).unwrap()
        );
        assert_eq!(
            decision_counts(&node),
            (
                decisions_before.0 + COUNT as u64,
                decisions_before.1 + COUNT as u64
            )
        );
        let rows = reports(&output);
        assert_eq!(rows.len(), COUNT + 1);
        assert_eq!(rows[0], b"unpack ok\n");
        for (name, row) in names.iter().zip(&rows[1..]) {
            assert_eq!(row, format!("ok {name}\n").as_bytes());
        }
        recover(&node, &names, &result);
        node.shutdown().unwrap();

        let node = start(config, true);
        recover(&node, &names, &result);
        let repeated = perform(
            &node,
            b"large-http-session",
            &commands,
            &[],
            false,
            false,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(repeated, result);
        assert_eq!(state(&node), published);
        let mut reordered = commands.clone();
        reordered.swap(0, COUNT - 1);
        assert!(
            perform(
                &node,
                b"large-http-session",
                &reordered,
                &[],
                false,
                true,
                &mut Vec::new()
            )
            .is_err()
        );
        assert_eq!(state(&node), published);
        recover(&node, &names, &result);
        node.shutdown().unwrap();
    }
}
