use super::*;
use super::tests::{Repository, chunks, crc, decode, http_head, stored, FIXED};
use crate::smart_http::{ProtocolVersion, parse_head};
use crate::smart_http::rpc::UploadRpc;
use crate::{Capabilities, GitObjectFormat, Packet, WireLimits, encode_packets};

fn decorated(member: &[u8], flags: u8) -> Vec<u8> {
    let mut header = member[..10].to_vec();
    header[3] = flags;
    if flags & 4 != 0 {
        // Extra fields are opaque, including zeros and non-UTF-8 bytes.
        header.extend_from_slice(&[4, 0, 0, 255, 1, 0]);
    }
    if flags & 8 != 0 { header.extend_from_slice(b"untrusted-name\0"); }
    if flags & 16 != 0 { header.extend_from_slice(b"opaque\xff-comment\0"); }
    if flags & 2 != 0 {
        let checksum = crc(&header).to_le_bytes();
        header.extend_from_slice(&checksum[..2]);
    }
    header.extend_from_slice(&member[10..]);
    header
}

#[test]
fn every_optional_header_combination_survives_every_fragment_boundary() {
    for flags in 0..32 {
        let member = decorated(FIXED, flags);
        for width in 1..=member.len() {
            assert_eq!(decode(&member, width, HttpLimits::default()).unwrap(), b"hello gzip\n".repeat(8));
        }
    }
    // A zero-length extra field must advance without consuming DEFLATE bytes.
    let mut member = FIXED[..10].to_vec();
    member[3] = 4;
    member.extend_from_slice(&[0, 0]);
    member.extend_from_slice(&FIXED[10..]);
    assert_eq!(decode(&member, 1, HttpLimits::default()).unwrap(), b"hello gzip\n".repeat(8));
}

#[test]
fn invalid_magic_method_reserved_flags_and_header_checksums_are_terminal() {
    for (index, value) in [(0, 0), (1, 0), (2, 0), (3, 32), (3, 64), (3, 128)] {
        let mut member = FIXED.to_vec();
        member[index] = value;
        assert!(matches!(decode(&member, 1, HttpLimits::default()),
            Err(RpcError::Http(HttpError::InvalidCompressedBody))));
    }
    let member = decorated(FIXED, 31);
    let header_end = member.len() - (FIXED.len() - 10);
    for index in 0..header_end {
        let mut bad = member.clone();
        bad[index] ^= 1;
        assert!(decode(&bad, 1, HttpLimits::default()).is_err(), "header byte {index}");
    }
    for cut in 0..member.len() {
        assert!(decode(&member[..cut], 1, HttpLimits::default()).is_err(), "cut {cut}");
    }
}

#[test]
fn metadata_budget_is_exact_and_never_counts_deflate_or_the_trailer() {
    let member = decorated(FIXED, 31);
    let header_bytes = member.len() - (FIXED.len() - 10);
    let limits = HttpLimits {
        max_head_bytes: header_bytes, max_target_bytes: header_bytes,
        ..HttpLimits::default()
    };
    assert_eq!(decode(&member, 1, limits).unwrap(), b"hello gzip\n".repeat(8));
    let tight = HttpLimits {
        max_head_bytes: header_bytes - 1, max_target_bytes: header_bytes - 1,
        ..limits
    };
    assert!(matches!(decode(&member, 1, tight), Err(RpcError::Http(HttpError::BodyTooLarge))));
    for flag in [4, 8, 16] {
        let mut oversized = FIXED[..10].to_vec();
        oversized[3] = flag;
        if flag == 4 { oversized.extend_from_slice(&u16::MAX.to_le_bytes()); }
        oversized.extend_from_slice(&[b'a'; 128]);
        assert!(matches!(decode(&oversized, 1, limits), Err(RpcError::Http(HttpError::BodyTooLarge))));
    }
}

fn v2_caps() -> Capabilities {
    Capabilities::parse_v2_advertisement(&[
        Packet::Data(b"version 2\n".to_vec()),
        Packet::Data(b"ls-refs\n".to_vec()),
        Packet::Data(b"fetch\n".to_vec()), Packet::Flush,
    ], &WireLimits::default()).unwrap()
}

#[test]
fn gzip_v2_ls_refs_and_fetch_use_the_real_machines_for_both_hashes() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format);
        let oid = "11".repeat(format.digest_len());
        for fetch in [false, true] {
            let packets = if fetch {
                vec![Packet::Data(b"command=fetch\n".to_vec()), Packet::Delimiter,
                    Packet::Data(format!("want {oid}\n").into_bytes()),
                    Packet::Data(b"done\n".to_vec()), Packet::Flush]
            } else {
                vec![Packet::Data(b"command=ls-refs\n".to_vec()), Packet::Delimiter, Packet::Flush]
            };
            let payload = encode_packets(&packets, &WireLimits::default()).unwrap();
            let member = decorated(&stored(&payload), 31);
            for chunked in [false, true] {
                let head = http_head("/repo.git/git-upload-pack", "gzip", member.len(), chunked);
                let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
                let body = if chunked { chunks(&member) } else { member.clone() };
                for width in [1, 3, 19, body.len()] {
                    let mut rpc = UploadRpc::new(&request, ProtocolVersion::V2, v2_caps(),
                        &repository, WireLimits::default(), HttpLimits::default()).unwrap();
                    for fragment in body.chunks(width) {
                        assert_eq!(rpc.push(fragment, &mut || true).unwrap().consumed, fragment.len());
                    }
                    let reply = rpc.finish(&mut || true).unwrap();
                    assert_eq!(reply.version(), ProtocolVersion::V2);
                    if fetch {
                        assert_eq!(reply.pack_request().unwrap().wants, vec![repository.refs[0].oid]);
                    } else {
                        assert!(reply.pack_request().is_none());
                        let expected = encode_packets(&[
                            Packet::Data(format!("{oid} refs/heads/main\n").into_bytes()), Packet::Flush,
                        ], &WireLimits::default()).unwrap();
                        assert_eq!(reply.prefix(), expected);
                    }
                }
            }
        }
    }
}

#[test]
fn verified_gzip_does_not_replace_http_termination_or_hide_a_second_command() {
    let repository = Repository::new(GitObjectFormat::Sha1);
    let command = encode_packets(&[
        Packet::Data(b"command=ls-refs\n".to_vec()), Packet::Delimiter, Packet::Flush,
    ], &WireLimits::default()).unwrap();
    for suffix in [b"".as_slice(), b"0", command.as_slice()] {
        let mut payload = command.clone();
        payload.extend_from_slice(suffix);
        let member = stored(&payload);
        let head = http_head("/repo.git/git-upload-pack", "gzip", member.len(), true);
        let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
        let mut rpc = UploadRpc::new(&request, ProtocolVersion::V2, v2_caps(),
            &repository, WireLimits::default(), HttpLimits::default()).unwrap();
        let body = chunks(&member);
        let result = rpc.push(&body[..body.len() - 5], &mut || true);
        if suffix.is_empty() {
            assert!(!result.unwrap().body_complete);
            assert!(matches!(rpc.finish(&mut || true), Err(RpcError::Http(HttpError::TruncatedBody))));
        } else {
            assert!(result.is_err());
            assert!(matches!(rpc.finish(&mut || true), Err(RpcError::FailedRequest)));
        }
    }
}

#[test]
fn independently_compressed_large_fetch_negotiation_exceeds_gits_gzip_threshold() {
    let repository = Repository::new(GitObjectFormat::Sha1);
    let mut packets = vec![
        Packet::Data(format!("want {} multi_ack\n", "11".repeat(20)).into_bytes()), Packet::Flush,
    ];
    for index in 0..128 {
        packets.push(Packet::Data(format!("have {:040x}\n", index + 2).into_bytes()));
    }
    packets.push(Packet::Flush);
    let expected = encode_packets(&packets, &WireLimits::default()).unwrap();
    assert!(expected.len() > 1024);
    assert_eq!(decode(LARGE_NEGOTIATION, 1, HttpLimits::default()).unwrap(), expected);
    for chunked in [false, true] {
        let head = http_head("/repo.git/git-upload-pack", "gzip", LARGE_NEGOTIATION.len(), chunked);
        let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
        let body = if chunked { chunks(LARGE_NEGOTIATION) } else { LARGE_NEGOTIATION.to_vec() };
        for width in [1, 17, body.len()] {
            let capabilities = Capabilities::parse_v1(b"multi_ack", &WireLimits::default()).unwrap();
            let mut rpc = UploadRpc::new(&request, ProtocolVersion::V0, capabilities,
                &repository, WireLimits::default(), HttpLimits::default()).unwrap();
            for fragment in body.chunks(width) {
                assert_eq!(rpc.push(fragment, &mut || true).unwrap().consumed, fragment.len());
            }
            let reply = rpc.finish(&mut || true).unwrap();
            assert_eq!(reply.prefix(), b"0008NAK\n");
            assert!(reply.pack_request().is_none());
        }
    }
}

// Independent Python zlib gzip fixture, level 9: one want, 128 distinct haves,
// final negotiation flush. This is a real pkt-line body, not an inflater-only
// repetition fixture. It needs no external executable in the Rust test.
const LARGE_NEGOTIATION: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x95, 0xd9,
    0xb9, 0x4d, 0x44, 0x51, 0x14, 0x44, 0x41, 0x9f, 0x28, 0x26, 0x84, 0x7f,
    0xb7, 0xf7, 0x86, 0x68, 0xd0, 0x30, 0x80, 0x40, 0x2c, 0x16, 0x4b, 0xfa,
    0x48, 0x44, 0x40, 0xb5, 0x7f, 0xcc, 0xb2, 0xfa, 0x38, 0xea, 0xfa, 0x73,
    0xf9, 0xf8, 0x3c, 0xc5, 0x3f, 0x77, 0x7a, 0xff, 0x7a, 0xfb, 0x7c, 0xb9,
    0xbb, 0x5c, 0x5f, 0x6f, 0x8e, 0xbf, 0x55, 0x3e, 0x5f, 0xbe, 0x1f, 0x4f,
    0xc7, 0xff, 0x96, 0x37, 0x5a, 0x14, 0x17, 0xcd, 0xc5, 0x70, 0xb1, 0xb8,
    0xd8, 0x5c, 0x9c, 0xb9, 0xb8, 0xe5, 0xe2, 0xc2, 0xc5, 0x3d, 0x17, 0x57,
    0x2e, 0x1e, 0xb8, 0x78, 0xe4, 0xe2, 0x49, 0x8b, 0x38, 0xb8, 0x08, 0x2e,
    0xd8, 0x47, 0xb0, 0x8f, 0x60, 0x1f, 0xc1, 0x3e, 0x82, 0x7d, 0x04, 0xfb,
    0x08, 0xf6, 0x11, 0xec, 0x23, 0xd8, 0x47, 0xb0, 0x8f, 0x60, 0x1f, 0xc1,
    0x3e, 0x82, 0x7d, 0x04, 0xfb, 0x48, 0xf6, 0x91, 0xec, 0x23, 0xd9, 0x47,
    0xb2, 0x8f, 0x64, 0x1f, 0xc9, 0x3e, 0x92, 0x7d, 0x24, 0xfb, 0x48, 0xf6,
    0x91, 0xec, 0x23, 0xd9, 0x47, 0xb2, 0x8f, 0x64, 0x1f, 0xc9, 0x3e, 0x92,
    0x7d, 0x24, 0xfb, 0x28, 0xf6, 0x51, 0xec, 0xa3, 0xd8, 0x47, 0xb1, 0x8f,
    0x62, 0x1f, 0xc5, 0x3e, 0x8a, 0x7d, 0x14, 0xfb, 0x28, 0xf6, 0x51, 0xec,
    0xa3, 0xd8, 0x47, 0xb1, 0x8f, 0x62, 0x1f, 0xc5, 0x3e, 0x8a, 0x7d, 0x14,
    0xfb, 0x68, 0xf6, 0xd1, 0xec, 0xa3, 0xd9, 0x47, 0xb3, 0x8f, 0x66, 0x1f,
    0xcd, 0x3e, 0x9a, 0x7d, 0x34, 0xfb, 0x68, 0xf6, 0xd1, 0xec, 0xa3, 0xd9,
    0x47, 0xb3, 0x8f, 0x66, 0x1f, 0xcd, 0x3e, 0x9a, 0x7d, 0x34, 0xfb, 0x18,
    0xf6, 0x31, 0xec, 0x63, 0xd8, 0xc7, 0xb0, 0x8f, 0x61, 0x1f, 0xc3, 0x3e,
    0x86, 0x7d, 0x0c, 0xfb, 0x18, 0xf6, 0x31, 0xec, 0x63, 0xd8, 0xc7, 0xb0,
    0x8f, 0x61, 0x1f, 0xc3, 0x3e, 0x86, 0x7d, 0x0c, 0xfb, 0x58, 0xec, 0x63,
    0xb1, 0x8f, 0xc5, 0x3e, 0x16, 0xfb, 0x58, 0xec, 0x63, 0xb1, 0x8f, 0xc5,
    0x3e, 0x16, 0xfb, 0x58, 0xec, 0x63, 0xb1, 0x8f, 0xc5, 0x3e, 0x16, 0xfb,
    0x58, 0xec, 0x63, 0xb1, 0x8f, 0xc5, 0x3e, 0x16, 0xfb, 0xd8, 0xec, 0x63,
    0xb3, 0x8f, 0xcd, 0x3e, 0x36, 0xfb, 0xd8, 0xec, 0x63, 0xb3, 0x8f, 0xcd,
    0x3e, 0x36, 0xfb, 0xd8, 0xec, 0x63, 0xb3, 0x8f, 0xcd, 0x3e, 0x36, 0xfb,
    0xd8, 0xec, 0x63, 0xb3, 0x8f, 0xcd, 0x3e, 0x36, 0xfb, 0x38, 0xb3, 0x8f,
    0x73, 0xfc, 0x7d, 0x20, 0xbf, 0x1c, 0xe3, 0xfc, 0x0f, 0x44, 0x19, 0x00,
    0x00,
];
