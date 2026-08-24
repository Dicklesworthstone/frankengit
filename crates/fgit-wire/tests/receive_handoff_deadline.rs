#![forbid(unsafe_code)]

use fgit_pack::Deadline;
use fgit_wire::receive::{
    ReceiveContext, ReceiveError, ReceiveLimits, ReceivePack, ReceiveQuarantineHandoff,
    SignedPushProfile,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits};

const OLD: &str = "1111111111111111111111111111111111111111";
const ZERO: &str = "0000000000000000000000000000000000000000";

#[derive(Default)]
struct DeadlineAwareHandoff {
    deadline_checkpoints: usize,
}

impl ReceiveQuarantineHandoff for DeadlineAwareHandoff {
    fn handoff(
        &mut self,
        _request: &fgit_wire::receive::ReceiveRequest,
        _pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &fgit_wire::receive::QuarantineReceipt,
    ) -> Result<(), ReceiveError> {
        Err(ReceiveError::InvalidLimit {
            field: "deadline-aware handoff must receive the live deadline",
        })
    }

    fn handoff_with_deadline(
        &mut self,
        _request: &fgit_wire::receive::ReceiveRequest,
        pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &fgit_wire::receive::QuarantineReceipt,
        deadline: &mut dyn Deadline,
    ) -> Result<(), ReceiveError> {
        assert!(pack.is_none(), "delete-only requests carry no pack");
        assert!(deadline.checkpoint(), "the transport deadline remains live");
        self.deadline_checkpoints += 1;
        Ok(())
    }
}

#[test]
fn finish_with_handoff_forwards_its_live_deadline_to_authoritative_work() {
    let capabilities =
        Capabilities::parse_v1(b"delete-refs", &WireLimits::default()).expect("fixture caps");
    let context = ReceiveContext::new(
        GitObjectFormat::Sha1,
        capabilities,
        ReceiveLimits::default(),
        SignedPushProfile::Refuse,
    )
    .expect("fixture context");
    let mut machine = ReceivePack::new(context).expect("receive machine");
    machine
        .push_packet(Packet::Data(
            format!("{OLD} {ZERO} refs/heads/delete\0delete-refs").into_bytes(),
        ))
        .expect("delete command");
    machine.push_packet(Packet::Flush).expect("command flush");

    let mut handoff = DeadlineAwareHandoff::default();
    let mut transport_checkpoints = 0_usize;
    let mut live = || {
        transport_checkpoints += 1;
        true
    };
    machine
        .finish_with_handoff(&mut handoff, &mut live)
        .expect("deadline-aware handoff completes");

    assert_eq!(handoff.deadline_checkpoints, 1);
    assert!(
        transport_checkpoints >= 2,
        "the handoff checkpoint shares the receive transport cancellation probe"
    );
}
