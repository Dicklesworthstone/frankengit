//! Bounded retention steps for caller-owned contiguous native input.
//! The native machine still owns framing and its quarantine envelope. These
//! checkpoints do not turn retained bytes into a validated or published object.

use fgit_types::RefusalCode;
use fgit_wire::WireLimits;
use fgit_wire::receive::{ReceiveError, ReceivePack};

const CHUNK_BYTES: usize = 16 * 1024;

pub fn push(
    receive: &mut ReceivePack,
    input: &[u8],
    wire: &WireLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<(), ReceiveError> {
    // The per-call decoder bound includes control packets such as the flush.
    // Four bytes is the shortest packet, including one completed from pending
    // input. Bound every call independently without changing the wire limits.
    let chunk_bytes = CHUNK_BYTES
        .min(wire.max_packet_bytes)
        .min(wire.max_packets_per_push.saturating_mul(4));
    if chunk_bytes == 0 {
        return Err(ReceiveError::InvalidLimit {
            field: "receive intake packet bound",
        });
    }
    for bytes in input.chunks(chunk_bytes) {
        if !live() {
            return Err(ReceiveError::AuthoritativeRefusal(
                RefusalCode::CancellationInProgress,
            ));
        }
        receive.push_bytes(bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest};
    use fgit_types::GitHashAlgorithm;
    use fgit_wire::receive::{ReceiveContext, ReceiveLimits, SignedPushProfile};
    use fgit_wire::{Capabilities, Packet, WireLimits, encode_packets};

    fn machine() -> ReceivePack {
        let limits = ReceiveLimits::default();
        let capabilities =
            Capabilities::parse_v1(b"report-status object-format=sha1", &limits.wire).unwrap();
        ReceivePack::new(
            ReceiveContext::new(
                GitHashAlgorithm::Sha1,
                capabilities,
                limits,
                SignedPushProfile::Refuse,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn input() -> Vec<u8> {
        let blob = vec![b'x'; 48 * 1024];
        let oid = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &blob);
        let prefix = format!(
            "{} {oid} refs/tags/input\0report-status object-format=sha1",
            "0".repeat(40)
        );
        let mut input = encode_packets(
            &[Packet::Data(prefix.into_bytes()), Packet::Flush],
            &WireLimits::default(),
        )
        .unwrap();
        let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
        let mut size = blob.len();
        let mut first = 0x30 | u8::try_from(size & 15).unwrap();
        size >>= 4;
        if size != 0 {
            first |= 0x80;
        }
        pack.push(first);
        while size != 0 {
            let mut byte = u8::try_from(size & 127).unwrap();
            size >>= 7;
            if size != 0 {
                byte |= 0x80;
            }
            pack.push(byte);
        }
        let length = u16::try_from(blob.len()).unwrap();
        pack.extend_from_slice(&[0x78, 0x01, 0x01]);
        pack.extend_from_slice(&length.to_le_bytes());
        pack.extend_from_slice(&(!length).to_le_bytes());
        pack.extend_from_slice(&blob);
        let (a, b) = blob.iter().fold((1_u32, 0_u32), |(a, b), byte| {
            let a = (a + u32::from(*byte)) % 65_521;
            (a, (b + a) % 65_521)
        });
        pack.extend_from_slice(&((b << 16) | a).to_be_bytes());
        let trailer = sha1_digest(&pack);
        pack.extend_from_slice(&trailer);
        input.extend_from_slice(&pack);
        input
    }

    #[test]
    fn cancellation_between_retention_steps_does_not_consume_the_rest() {
        let mut receive = machine();
        let bytes = input();
        assert!(bytes.len() > 3 * CHUNK_BYTES);
        let mut calls = 0;
        let result = push(&mut receive, &bytes, &WireLimits::default(), &mut || {
            calls += 1;
            calls < 2
        });
        assert!(matches!(
            result,
            Err(ReceiveError::AuthoritativeRefusal(
                RefusalCode::CancellationInProgress
            ))
        ));
        assert_eq!(
            calls, 2,
            "cancellation must stop before a second chunk is retained"
        );
    }

    #[test]
    fn live_input_reaches_every_bounded_step_without_a_second_request_copy() {
        let mut receive = machine();
        let bytes = input();
        let mut calls = 0;
        push(&mut receive, &bytes, &WireLimits::default(), &mut || {
            calls += 1;
            true
        })
        .unwrap();
        assert_eq!(calls, bytes.len().div_ceil(CHUNK_BYTES));
        // This test covers native framing/retention only. It does not claim
        // quarantine validation or authority publication from parser success.
    }

    #[test]
    fn malformed_native_prefix_stops_before_later_body_chunks() {
        let mut receive = machine();
        let mut calls = 0;
        let bytes = vec![b'z'; 3 * CHUNK_BYTES];
        assert!(
            push(&mut receive, &bytes, &WireLimits::default(), &mut || {
                calls += 1;
                true
            })
            .is_err()
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn derived_chunks_honor_one_packet_calls_even_with_a_pending_header() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let wire = WireLimits {
                max_packets_per_push: 1,
                ..WireLimits::default()
            };
            let limits = ReceiveLimits {
                wire: wire.clone(),
                ..ReceiveLimits::default()
            };
            let caps = format!(
                "report-status delete-refs object-format={}",
                format.as_str()
            );
            let capabilities = Capabilities::parse_v1(caps.as_bytes(), &wire).unwrap();
            let mut receive = ReceivePack::new(
                ReceiveContext::new(format, capabilities, limits, SignedPushProfile::Refuse)
                    .unwrap(),
            )
            .unwrap();
            let zero = "0".repeat(format.digest_len() * 2);
            let mut packets = (0..3)
                .map(|index| {
                    let suffix = if index == 0 {
                        format!("\0{caps}")
                    } else {
                        String::new()
                    };
                    Packet::Data(
                        format!("{zero} {zero} refs/tags/absent-{index}{suffix}").into_bytes(),
                    )
                })
                .collect::<Vec<_>>();
            packets.push(Packet::Flush);
            let bytes = encode_packets(&packets, &wire).unwrap();
            receive.push_bytes(&bytes[..3]).unwrap();
            let mut checkpoints = 0;
            push(&mut receive, &bytes[3..], &wire, &mut || {
                checkpoints += 1;
                true
            })
            .unwrap();
            assert_eq!(receive.phase(), fgit_wire::receive::ReceivePhase::Ready);
            assert_eq!(checkpoints, (bytes.len() - 3).div_ceil(4));
            assert_eq!(wire.max_packets_per_push, 1);
        }
    }
}
