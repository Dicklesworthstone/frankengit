use super::*;
use crate::smart_http::{ContentEncoding, ProtocolVersion, head, parse_head};
use crate::smart_http::rpc::UploadRpc;
use crate::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, Packet, UploadPackRepository,
    WireLimits, encode_packets,
};

pub(super) fn decode(bytes: &[u8], width: usize, limits: HttpLimits) -> Result<Vec<u8>, RpcError> {
    let mut decoder = GzipDecoder::new(limits)?;
    let mut output = Vec::new();
    for fragment in bytes.chunks(width.min(INPUT_CHUNK_BYTES)) {
        output.extend(decoder.push(fragment, &mut || true)?);
    }
    decoder.finish(&mut || true)?;
    assert_eq!(decoder.decoded_bytes(), output.len() as u64);
    decoder.finish(&mut || true)?;
    Ok(output)
}

pub(super) fn crc(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(u32::MAX, |crc, &byte| crc_byte(crc, byte))
}

// Test-only stored-block encoder; production uses no encoder or reference Git.
pub(super) fn stored(bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    if bytes.is_empty() {
        result.extend_from_slice(&[1, 0, 0, 255, 255]);
    } else {
        let mut remaining = bytes.len();
        for part in bytes.chunks(65_535) {
            remaining -= part.len();
            let count = u16::try_from(part.len()).unwrap();
            result.push(u8::from(remaining == 0));
            result.extend_from_slice(&count.to_le_bytes());
            result.extend_from_slice(&(!count).to_le_bytes());
            result.extend_from_slice(part);
        }
    }
    result.extend_from_slice(&crc(bytes).to_le_bytes());
    result.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
    result
}

#[test]
fn crc_matches_standard_check_value() {
    assert_eq!(crc(b"123456789"), 0xcbf4_3926);
    assert_eq!(crc(b""), 0);
}

#[test]
fn stored_fixed_and_dynamic_members_survive_every_fragment_width() {
    for (member, expected) in [
        (stored(b""), Vec::new()),
        (stored(b"binary\0\xff\n"), b"binary\0\xff\n".to_vec()),
        (FIXED.to_vec(), b"hello gzip\n".repeat(8)),
        (DYNAMIC.to_vec(), b"want 1111111111111111111111111111111111111111\n".repeat(128)),
    ] {
        for width in 1..=member.len().min(INPUT_CHUNK_BYTES) {
            assert_eq!(decode(&member, width, HttpLimits::default()).unwrap(), expected);
        }
    }
    let mut text = FIXED.to_vec();
    text[3] = 1; // FTEXT is advisory, not a different compression method.
    assert_eq!(decode(&text, 1, HttpLimits::default()).unwrap(), b"hello gzip\n".repeat(8));
}

#[test]
fn corruption_truncation_and_suffixes_never_finish_and_poison_decoder() {
    for cut in 0..FIXED.len() {
        assert!(decode(&FIXED[..cut], 1, HttpLimits::default()).is_err(), "cut {cut}");
    }
    for index in FIXED.len() - 8..FIXED.len() {
        let mut corrupt = FIXED.to_vec();
        corrupt[index] ^= 1;
        let mut decoder = GzipDecoder::new(HttpLimits::default()).unwrap();
        let first = decoder.push(&corrupt, &mut || true)
            .and_then(|_| decoder.finish(&mut || true));
        assert!(first.is_err(), "trailer byte {index}");
        assert!(matches!(decoder.push(&[], &mut || true), Err(RpcError::FailedRequest)));
        assert!(matches!(decoder.finish(&mut || true), Err(RpcError::FailedRequest)));
    }
    for suffix in [b"junk".as_slice(), FIXED, b"\0\0\0\0"] {
        let mut member = FIXED.to_vec();
        member.extend_from_slice(suffix);
        for width in [1, 7, INPUT_CHUNK_BYTES] {
            assert!(decode(&member, width, HttpLimits::default()).is_err());
        }
    }
    // An attacker cannot turn the synthetic zlib framing into a second format:
    // an embedded valid Adler trailer still leaves extra bytes and must fail.
    let mut hidden = FIXED[..FIXED.len() - 8].to_vec();
    hidden.extend_from_slice(&[0, 0, 0, 1]);
    hidden.extend_from_slice(&FIXED[FIXED.len() - 8..]);
    assert!(decode(&hidden, 1, HttpLimits::default()).is_err());
}

#[test]
fn compressed_and_expanded_byte_limits_are_independent() {
    let limits = HttpLimits { max_body_bytes: 1024, ..HttpLimits::default() };
    assert!(DYNAMIC.len() < 1024);
    assert!(matches!(decode(DYNAMIC, 1, limits), Err(RpcError::Http(HttpError::BodyTooLarge))));
    let bytes = stored(&[0; 64]);
    let limits = HttpLimits { max_body_bytes: 64, ..HttpLimits::default() };
    assert!(matches!(decode(&bytes, 1, limits), Err(RpcError::Http(HttpError::BodyTooLarge))));
}

#[test]
fn cancellation_during_inflate_and_at_finalization_is_terminal() {
    let mut decoder = GzipDecoder::new(HttpLimits::default()).unwrap();
    let mut calls = 0;
    assert!(matches!(decoder.push(DYNAMIC, &mut || {
        calls += 1;
        calls == 1
    }), Err(RpcError::Cancelled)));
    assert!(matches!(decoder.finish(&mut || true), Err(RpcError::FailedRequest)));

    let mut decoder = GzipDecoder::new(HttpLimits::default()).unwrap();
    decoder.push(FIXED, &mut || true).unwrap();
    assert!(matches!(decoder.finish(&mut || false), Err(RpcError::Cancelled)));
    assert!(matches!(decoder.finish(&mut || true), Err(RpcError::FailedRequest)));
}

pub(super) fn http_head(path: &str, coding: &str, size: usize, chunked: bool) -> Vec<u8> {
    let framing = if chunked {
        "Transfer-Encoding: chunked".to_owned()
    } else {
        format!("Content-Length: {size}")
    };
    format!("POST {path} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Encoding: {coding}\r\n{framing}\r\n\r\n").into_bytes()
}

#[test]
fn gateway_envelope_and_git_parser_agree_without_enabling_native_gzip() {
    for coding in ["gzip", "GzIp", "identity"] {
        let bytes = http_head("/repo.git/git-upload-pack", coding, 40, false);
        let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        let request = parse_head(&bytes, HttpLimits::default()).unwrap().unwrap();
        assert_eq!(envelope.content_encoding, request.content_encoding);
        assert_eq!(request.content_encoding, if coding == "identity" {
            ContentEncoding::Identity
        } else {
            ContentEncoding::Gzip
        });
    }
    for path in [
        "/repo.git/git-receive-pack",
        "/repo.git/api/v1/issues/1/open",
        "/repo.git/info/refs?service=git-upload-pack",
    ] {
        let bytes = http_head(path, "gzip", 40, false);
        assert!(matches!(head::parse(&bytes, HttpLimits::default()),
            Err(HttpError::UnsupportedContentEncoding)));
    }
    for coding in ["br", "gzip, identity", "gzip; q=1", "gzip\r\nContent-Encoding: gzip"] {
        let bytes = http_head("/repo.git/git-upload-pack", coding, 40, false);
        assert!(head::parse(&bytes, HttpLimits::default()).is_err());
        assert!(parse_head(&bytes, HttpLimits::default()).is_err());
    }
}

pub(super) struct Repository {
    pub(super) refs: Vec<AdvertisedRef>,
    format: GitObjectFormat,
}
impl Repository {
    pub(super) fn new(format: GitObjectFormat) -> Self {
        let oid = AnyGitOid::from_hex(format, &"11".repeat(format.digest_len())).unwrap();
        Self {
            refs: vec![AdvertisedRef::new(oid, b"refs/heads/main", &WireLimits::default()).unwrap()],
            format,
        }
    }
}
impl UploadPackRepository for Repository {
    fn object_format(&self) -> GitObjectFormat { self.format }
    fn advertised_refs(&self) -> &[AdvertisedRef] { &self.refs }
    fn contains_want(&self, oid: AnyGitOid) -> bool { oid == self.refs[0].oid }
    fn is_common(&self, oid: AnyGitOid) -> bool { self.contains_want(oid) }
}
pub(super) fn chunks(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    for part in bytes.chunks(7) {
        output.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
        output.extend_from_slice(part);
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"0\r\n\r\n");
    output
}

#[test]
fn real_legacy_upload_machines_decode_both_hashes_and_both_http_framings() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format);
        let payload = encode_packets(&[
            Packet::Data(format!("want {}\n", "11".repeat(format.digest_len())).into_bytes()),
            Packet::Flush,
            Packet::Data(b"done\n".to_vec()),
        ], &WireLimits::default()).unwrap();
        let member = stored(&payload);
        for version in [ProtocolVersion::V0, ProtocolVersion::V1] {
            for chunked in [false, true] {
                let bytes = http_head("/repo.git/git-upload-pack", "gzip", member.len(), chunked);
                let request = parse_head(&bytes, HttpLimits::default()).unwrap().unwrap();
                let body = if chunked { chunks(&member) } else { member.clone() };
                for width in [1, 2, 7, 19, body.len()] {
                    let mut rpc = UploadRpc::new(&request, version, Capabilities::default(),
                        &repository, WireLimits::default(), HttpLimits::default()).unwrap();
                    let mut decoded = 0;
                    for fragment in body.chunks(width) {
                        let progress = rpc.push(fragment, &mut || true).unwrap();
                        assert_eq!(progress.consumed, fragment.len());
                        decoded = progress.decoded_body_bytes;
                    }
                    assert_eq!(decoded, payload.len() as u64);
                    let reply = rpc.finish(&mut || true).unwrap();
                    assert_eq!(reply.prefix(), b"0008NAK\n");
                    assert_eq!(reply.pack_request().unwrap().wants, vec![repository.refs[0].oid]);
                }
            }
        }
    }
}

#[test]
fn corrupt_gzip_cannot_release_a_completed_git_command() {
    let repository = Repository::new(GitObjectFormat::Sha1);
    let payload = encode_packets(&[
        Packet::Data(format!("want {}\n", "11".repeat(20)).into_bytes()),
        Packet::Flush,
        Packet::Data(b"done\n".to_vec()),
    ], &WireLimits::default()).unwrap();
    let mut member = stored(&payload);
    let checksum = member.len() - 8;
    member[checksum] ^= 1;
    let bytes = http_head("/repo.git/git-upload-pack", "gzip", member.len(), false);
    let request = parse_head(&bytes, HttpLimits::default()).unwrap().unwrap();
    let mut rpc = UploadRpc::new(&request, ProtocolVersion::V0, Capabilities::default(),
        &repository, WireLimits::default(), HttpLimits::default()).unwrap();
    assert!(matches!(rpc.push(&member, &mut || true),
        Err(RpcError::Http(HttpError::InvalidCompressedBody))));
    assert!(matches!(rpc.finish(&mut || true), Err(RpcError::FailedRequest)));
}

// Independent fixtures: Python 3 zlib gzip (wbits=31), fixed and dynamic
// Huffman blocks respectively. The checked plaintext is specified above.
pub(super) const FIXED: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xcb, 0x48,
    0xcd, 0xc9, 0xc9, 0x57, 0x48, 0xaf, 0xca, 0x2c, 0xe0, 0xca, 0xa0, 0x26,
    0x13, 0x00, 0x33, 0x77, 0x18, 0x09, 0x58, 0x00, 0x00, 0x00,
];
const DYNAMIC: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xed, 0xca,
    0x31, 0x0d, 0x00, 0x30, 0x08, 0x00, 0xb0, 0x1f, 0x15, 0xb3, 0x80, 0x24,
    0x0c, 0x70, 0x2d, 0xc1, 0x3e, 0x16, 0xf6, 0x2e, 0x69, 0xef, 0x4e, 0xf5,
    0x3d, 0xf9, 0x28, 0xc6, 0xb6, 0x6d, 0xdb, 0xb6, 0x6d, 0xdb, 0xb6, 0x6d,
    0xdb, 0xb6, 0x6d, 0xdb, 0xb6, 0x6d, 0xdb, 0xb6, 0xbf, 0xd8, 0x0b, 0xe9,
    0x1f, 0xb4, 0x37, 0x00, 0x17, 0x00, 0x00,
];
