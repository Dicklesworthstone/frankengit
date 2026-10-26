#![forbid(unsafe_code)]
//! A zero/zero command is a conditional deletion of an absent ref (l6mb).
//! The wire layer preserves the assertion; only authority-backed admission
//! can decide whether it is a no-op or an expected-old mismatch.

use fgit_wire::receive::{
    QuarantineReceipt, ReceiveCommandKind, ReceiveContext, ReceiveError, ReceiveEvent,
    ReceiveLimits, ReceivePack, ReceivePhase, ReceiveQuarantineHandoff, ReceiveRequest,
    SignedPushProfile,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits};

fn context(format: GitObjectFormat, deletes: bool, max_commands: usize) -> ReceiveContext {
    let capabilities = format!(
        "report-status {}object-format={format}",
        if deletes { "delete-refs " } else { "" },
    );
    ReceiveContext::new(
        format,
        Capabilities::parse_v1(capabilities.as_bytes(), &WireLimits::default()).unwrap(),
        ReceiveLimits {
            max_commands,
            ..ReceiveLimits::default()
        },
        SignedPushProfile::Refuse,
    )
    .unwrap()
}

fn command(format: GitObjectFormat, name: &str, first: bool) -> Packet {
    let zero = match format {
        GitObjectFormat::Sha1 => "0".repeat(40),
        GitObjectFormat::Sha256 => "0".repeat(64),
    };
    let mut line = format!("{zero} {zero} {name}").into_bytes();
    if first {
        line.extend_from_slice(format!("\0report-status object-format={format}").as_bytes());
    }
    Packet::Data(line)
}

#[derive(Default)]
struct PacklessHandoff {
    calls: usize,
}

impl ReceiveQuarantineHandoff for PacklessHandoff {
    fn handoff(
        &mut self,
        request: &ReceiveRequest,
        pack: Option<&fgit_pack::QuarantinedPack>,
        receipt: &QuarantineReceipt,
    ) -> Result<(), ReceiveError> {
        assert!(pack.is_none());
        assert!(request.deletes_only());
        assert!(receipt.delete_only);
        assert_eq!(receipt.object_count, 0);
        assert_eq!(receipt.pack_bytes, 0);
        self.calls += 1;
        Ok(())
    }
}

#[test]
fn zero_pair_is_a_packless_delete_in_both_native_formats() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut machine = ReceivePack::new(context(format, true, 2)).unwrap();
        machine
            .push_packet(command(format, "refs/heads/absent", true))
            .expect("a zero/zero command must reach authority evaluation");
        let transition = machine.push_packet(Packet::Flush).unwrap();
        let Some(ReceiveEvent::RequestReady(request)) = transition.events.first() else {
            panic!("the delete request must be available after its flush");
        };
        assert_eq!(request.commands[0].kind(), ReceiveCommandKind::Delete);
        assert!(request.commands[0].old.is_zero());
        assert!(request.commands[0].new.is_zero());
        assert_eq!(request.commands[0].expected_old(), None);
        assert!(!request.requires_pack());

        let mut handoff = PacklessHandoff::default();
        machine
            .finish_with_handoff(&mut handoff, &mut || true)
            .expect("a conditional absent delete needs no pack bytes");
        assert_eq!(handoff.calls, 1);
        assert_eq!(machine.phase(), ReceivePhase::Complete);
        assert_eq!(machine.quarantine_len(), 0);
    }
}

#[test]
fn zero_pair_still_requires_the_server_to_advertise_delete_refs() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut machine = ReceivePack::new(context(format, false, 2)).unwrap();
        machine
            .push_packet(command(format, "refs/heads/absent", true))
            .unwrap();
        assert_eq!(
            machine.push_packet(Packet::Flush),
            Err(ReceiveError::DeleteRefsNotNegotiated)
        );
        assert_eq!(machine.phase(), ReceivePhase::Refused);
    }
}

#[test]
fn absent_deletes_obey_duplicate_name_and_command_bounds() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut machine = ReceivePack::new(context(format, true, 2)).unwrap();
        machine
            .push_packet(command(format, "refs/heads/absent", true))
            .unwrap();
        assert_eq!(
            machine.push_packet(command(format, "refs/heads/absent", false)),
            Err(ReceiveError::DuplicateRefCommand {
                ref_name: b"refs/heads/absent".to_vec(),
            })
        );

        let mut machine = ReceivePack::new(context(format, true, 1)).unwrap();
        machine
            .push_packet(command(format, "refs/heads/absent", true))
            .expect("the exact one-command bound permits the no-op proposal");
        assert_eq!(
            machine.push_packet(command(format, "refs/heads/other", false)),
            Err(ReceiveError::TooManyCommands { limit: 1 })
        );
        assert_eq!(machine.quarantine_len(), 0);
    }
}

#[test]
fn cancellation_before_the_packless_handoff_publishes_no_handoff() {
    let mut machine = ReceivePack::new(context(GitObjectFormat::Sha1, true, 1)).unwrap();
    machine
        .push_packet(command(GitObjectFormat::Sha1, "refs/heads/absent", true))
        .unwrap();
    machine.push_packet(Packet::Flush).unwrap();
    let mut handoff = PacklessHandoff::default();
    assert!(matches!(
        machine.finish_with_handoff(&mut handoff, &mut || false),
        Err(ReceiveError::Cancelled)
    ));
    assert_eq!(handoff.calls, 0);
    assert_eq!(machine.phase(), ReceivePhase::Refused);
    assert_eq!(machine.quarantine_len(), 0);
}
