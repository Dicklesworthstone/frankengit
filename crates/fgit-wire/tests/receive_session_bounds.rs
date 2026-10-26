#![forbid(unsafe_code)]
//! Large independent sessions and smaller atomic transactions share one parser
//! without sharing their command-count ceiling or changing wire-order semantics.

use fgit_wire::receive::{
    ReceiveContext, ReceiveError, ReceiveEvent, ReceiveLimits, ReceivePack, ReceivePhase,
    SignedPushProfile,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet};

fn machine(format: GitObjectFormat, session: usize, atomic: usize) -> ReceivePack {
    let limits = ReceiveLimits {
        max_commands: session,
        max_atomic_commands: atomic,
        ..ReceiveLimits::default()
    };
    let capabilities = Capabilities::parse_v1(
        format!("report-status delete-refs atomic object-format={format}").as_bytes(),
        &limits.wire,
    )
    .unwrap();
    ReceivePack::new(
        ReceiveContext::new(format, capabilities, limits, SignedPushProfile::Refuse).unwrap(),
    )
    .unwrap()
}

fn command(format: GitObjectFormat, name: usize, first: bool, atomic: bool) -> Packet {
    let old = "1".repeat(format.digest_len() * 2);
    let zero = "0".repeat(format.digest_len() * 2);
    let mut line = format!("{old} {zero} refs/tags/session-{name:05}");
    if first {
        line.push_str(&format!(
            "\0report-status object-format={format}{}",
            if atomic { " atomic" } else { "" }
        ));
    }
    Packet::Data(line.into_bytes())
}

#[test]
fn sixteen_thousand_independent_commands_preserve_wire_order_and_have_an_exact_limit() {
    const COUNT: usize = 16_384;
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut accepted = machine(format, COUNT, 4_096);
        for index in 0..COUNT {
            accepted
                .push_packet(command(format, COUNT - index, index == 0, false))
                .unwrap();
        }
        let mut exceeded = accepted.clone();
        assert_eq!(
            exceeded.push_packet(command(format, 0, false, false)),
            Err(ReceiveError::TooManyCommands { limit: COUNT })
        );
        assert_eq!(exceeded.phase(), ReceivePhase::Refused);
        assert_eq!(exceeded.quarantine_len(), 0);

        let transition = accepted.push_packet(Packet::Flush).unwrap();
        let [ReceiveEvent::RequestReady(request)] = transition.events.as_slice() else {
            panic!("the exact permitted command list must reach request readiness");
        };
        assert_eq!(request.commands.len(), COUNT);
        assert!(!request.has_capability(b"atomic"));
        for (index, command) in request.commands.iter().enumerate() {
            assert_eq!(
                command.ref_name,
                format!("refs/tags/session-{:05}", COUNT - index).as_bytes()
            );
        }
    }
}

#[test]
fn atomic_limit_is_applied_during_commands_before_any_pack_or_handoff() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut accepted = machine(format, 16_384, 4_096);
        for index in 0..4_096 {
            accepted
                .push_packet(command(format, index, index == 0, true))
                .unwrap();
        }
        let mut exceeded = accepted.clone();
        assert_eq!(
            exceeded.push_packet(command(format, 4_096, false, true)),
            Err(ReceiveError::TooManyCommands { limit: 4_096 })
        );
        assert_eq!(exceeded.phase(), ReceivePhase::Refused);
        assert_eq!(exceeded.quarantine_len(), 0);
        assert!(exceeded.push_bytes(b"unread pack bytes").is_err());
        assert_eq!(exceeded.phase(), ReceivePhase::Refused);
        assert_eq!(exceeded.quarantine_len(), 0);
        let transition = accepted.push_packet(Packet::Flush).unwrap();
        let [ReceiveEvent::RequestReady(request)] = transition.events.as_slice() else {
            panic!("atomic boundary must remain permitted");
        };
        assert!(request.has_capability(b"atomic"));
        assert_eq!(request.commands.len(), 4_096);
    }
}

#[test]
fn stricter_session_and_atomic_limits_are_independent_and_both_enforced() {
    let format = GitObjectFormat::Sha1;
    for (session, atomic_limit, atomic, expected) in [
        (2, 4, false, 2),
        (2, 4, true, 2),
        (4, 2, false, 4),
        (4, 2, true, 2),
    ] {
        let mut accepted = machine(format, session, atomic_limit);
        for index in 0..expected {
            accepted
                .push_packet(command(format, index, index == 0, atomic))
                .unwrap();
        }
        let mut exceeded = accepted.clone();
        accepted.push_packet(Packet::Flush).unwrap();
        assert_eq!(
            exceeded.push_packet(command(format, expected, false, atomic)),
            Err(ReceiveError::TooManyCommands { limit: expected })
        );
    }
}

#[test]
fn duplicate_detection_keeps_the_original_order_and_exact_refusal() {
    let format = GitObjectFormat::Sha1;
    let mut receiver = machine(format, 16_384, 4_096);
    for index in (0..4_097).rev() {
        receiver
            .push_packet(command(format, index, index == 4_096, false))
            .unwrap();
    }
    assert_eq!(
        receiver.push_packet(command(format, 2_048, false, false)),
        Err(ReceiveError::DuplicateRefCommand {
            ref_name: b"refs/tags/session-02048".to_vec(),
        })
    );
    assert_eq!(receiver.phase(), ReceivePhase::Refused);
    assert_eq!(receiver.quarantine_len(), 0);
}

#[test]
fn signed_atomic_commands_use_the_same_narrower_bound() {
    let limits = ReceiveLimits {
        max_commands: 4,
        max_atomic_commands: 2,
        ..ReceiveLimits::default()
    };
    let capabilities = Capabilities::parse_v1(
        b"delete-refs atomic push-cert=nonce-1 report-status",
        &limits.wire,
    )
    .unwrap();
    let mut receiver = ReceivePack::new(
        ReceiveContext::new(
            GitObjectFormat::Sha1,
            capabilities,
            limits,
            SignedPushProfile::ParseV1 {
                expected_nonce: b"nonce-1".to_vec(),
            },
        )
        .unwrap(),
    )
    .unwrap();
    for line in [
        b"push-cert\0push-cert atomic delete-refs".as_slice(),
        b"certificate version 0.1\n",
        b"pusher A U Thor <a@example.test> 0 +0000\n",
        b"pushee ssh://example.test/repo\n",
        b"nonce nonce-1\n",
        b"\n",
    ] {
        receiver.push_packet(Packet::Data(line.to_vec())).unwrap();
    }
    for index in 0..=2 {
        let Packet::Data(mut line) = command(GitObjectFormat::Sha1, index, false, true) else {
            unreachable!("command helper always returns data");
        };
        // Signed certificate commands are LF-terminated certificate text.
        line.push(b'\n');
        let result = receiver.push_packet(Packet::Data(line));
        if index < 2 {
            result.unwrap();
        } else {
            assert_eq!(result, Err(ReceiveError::TooManyCommands { limit: 2 }));
        }
    }
    assert_eq!(receiver.phase(), ReceivePhase::Refused);
}
