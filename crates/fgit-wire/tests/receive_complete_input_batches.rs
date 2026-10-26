#![forbid(unsafe_code)]
//! Complete-input receive adapters must preserve the pkt-line decoder's
//! per-call budget when accepting a 4,096-ref request.
//!
//! This authored fixture exercises the real ReceivePack parser and quarantine
//! handoff with delete-only requests. It establishes protocol-adapter behavior;
//! it does not validate native branch publication or authority admission.

use fgit_wire::receive::{
    QuarantineReceipt, ReceiveContext, ReceiveError, ReceiveLimits, ReceivePack, ReceivePhase,
    ReceiveQuarantineHandoff, ReceiveRequest, SignedPushProfile,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireError, WireLimits, encode_packets};

const COMMAND_LIMIT: usize = 4_096;
const FRAGMENT_BYTES: usize = 16 * 1024;

fn context(format: GitObjectFormat, packets_per_push: usize) -> ReceiveContext {
    let limits = ReceiveLimits {
        max_commands: COMMAND_LIMIT,
        wire: WireLimits {
            max_packets_per_push: packets_per_push,
            ..WireLimits::default()
        },
        ..ReceiveLimits::default()
    };
    let capabilities = Capabilities::parse_v1(
        format!("delete-refs report-status atomic object-format={format}").as_bytes(),
        &limits.wire,
    )
    .unwrap();
    ReceiveContext::new(format, capabilities, limits, SignedPushProfile::Refuse).unwrap()
}

fn request(format: GitObjectFormat, atomic: bool, count: usize) -> Vec<u8> {
    let width = match format {
        GitObjectFormat::Sha1 => 40,
        GitObjectFormat::Sha256 => 64,
    };
    let old = "1".repeat(width);
    let zero = "0".repeat(width);
    let mut packets = Vec::with_capacity(count + 1);
    for index in 0..count {
        let mut line = format!("{old} {zero} refs/heads/batch/{index:04}").into_bytes();
        if index == 0 {
            line.extend_from_slice(
                format!(
                    "\0report-status object-format={format}{}",
                    if atomic { " atomic" } else { "" }
                )
                .as_bytes(),
            );
        }
        packets.push(Packet::Data(line));
    }
    packets.push(Packet::Flush);
    encode_packets(&packets, &WireLimits::default()).unwrap()
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
        assert!(request.deletes_only());
        assert!(pack.is_none());
        assert!(receipt.delete_only);
        assert_eq!(receipt.object_count, 0);
        assert_eq!(receipt.pack_bytes, 0);
        self.calls += 1;
        Ok(())
    }
}

fn finish(machine: &mut ReceivePack, format: GitObjectFormat, atomic: bool, count: usize) {
    assert_eq!(machine.phase(), ReceivePhase::Ready);
    let mut handoff = PacklessHandoff::default();
    let completion = machine
        .finish_with_handoff(&mut handoff, &mut || true)
        .expect("all commands and the closing flush must reach the real handoff");
    assert_eq!(handoff.calls, 1);
    assert_eq!(completion.quarantine.object_format, format);
    assert_eq!(completion.request.commands.len(), count);
    assert_eq!(completion.request.has_capability(b"atomic"), atomic);
    for (index, command) in completion.request.commands.iter().enumerate() {
        assert_eq!(
            command.ref_name,
            format!("refs/heads/batch/{index:04}").as_bytes()
        );
        assert!(!command.old.is_zero());
        assert!(command.new.is_zero());
    }
    assert_eq!(machine.phase(), ReceivePhase::Complete);
    assert_eq!(machine.quarantine_len(), 0);
}

fn assert_no_handoff_after_refusal(machine: &mut ReceivePack) {
    assert_eq!(machine.phase(), ReceivePhase::Refused);
    let mut handoff = PacklessHandoff::default();
    assert!(
        machine
            .finish_with_handoff(&mut handoff, &mut || true)
            .is_err()
    );
    assert_eq!(handoff.calls, 0);
    assert_eq!(machine.quarantine_len(), 0);
}

#[test]
fn the_closing_flush_counts_toward_the_default_4096_packet_batch_limit() {
    let packet_limit = WireLimits::default().max_packets_per_push;
    assert_eq!(packet_limit, 4_096);

    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for atomic in [false, true] {
            // 4,095 commands plus the flush exactly fit one decoder call.
            let mut machine = ReceivePack::new(context(format, packet_limit)).unwrap();
            machine
                .push_bytes(&request(format, atomic, COMMAND_LIMIT - 1))
                .expect("the nearest complete-input twin fits the packet batch");
            finish(&mut machine, format, atomic, COMMAND_LIMIT - 1);

            // A complete-input adapter that passes this request in one call
            // exceeds the packet batch even though its command count is valid.
            let mut machine = ReceivePack::new(context(format, packet_limit)).unwrap();
            assert_eq!(
                machine.push_bytes(&request(format, atomic, COMMAND_LIMIT)),
                Err(ReceiveError::Wire(WireError::PacketCountExceeded {
                    limit: packet_limit,
                }))
            );
            assert_no_handoff_after_refusal(&mut machine);
        }
    }
}

#[test]
fn bounded_input_fragments_admit_4095_and_4096_commands_without_raising_limits() {
    let packet_limit = WireLimits::default().max_packets_per_push;
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for atomic in [false, true] {
            for count in [COMMAND_LIMIT - 1, COMMAND_LIMIT] {
                let mut machine = ReceivePack::new(context(format, packet_limit)).unwrap();
                let input = request(format, atomic, count);
                for fragment in input.chunks(FRAGMENT_BYTES) {
                    machine
                        .push_bytes(fragment)
                        .expect("bounded fragments preserve the decoder's packet budget");
                }
                finish(&mut machine, format, atomic, count);
            }
        }
    }
}

#[test]
fn fragmentation_cannot_bypass_the_total_command_limit() {
    let packet_limit = WireLimits::default().max_packets_per_push;
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for atomic in [false, true] {
            let mut machine = ReceivePack::new(context(format, packet_limit)).unwrap();
            let input = request(format, atomic, COMMAND_LIMIT + 1);
            let refusal = input
                .chunks(FRAGMENT_BYTES)
                .find_map(|fragment| machine.push_bytes(fragment).err());
            assert_eq!(
                refusal,
                Some(ReceiveError::TooManyCommands {
                    limit: COMMAND_LIMIT,
                })
            );
            assert_no_handoff_after_refusal(&mut machine);
        }
    }
}

#[test]
fn four_byte_fragments_preserve_a_one_packet_budget_across_partial_headers() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for atomic in [false, true] {
            let mut machine = ReceivePack::new(context(format, 1)).unwrap();
            let input = request(format, atomic, 3);
            // Deliberately leave part of the first header pending before the
            // adapter's four-byte fragment cadence begins.
            machine.push_bytes(&input[..1]).unwrap();
            for fragment in input[1..].chunks(4) {
                machine
                    .push_bytes(fragment)
                    .expect("each fragment can complete at most one packet");
            }
            finish(&mut machine, format, atomic, 3);
        }
    }
}
