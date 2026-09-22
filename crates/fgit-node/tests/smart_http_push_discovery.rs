#![forbid(unsafe_code)]
//! The write-side discovery path must not depend on a fetch-only HEAD view.

use std::path::PathBuf;

use fgit_admission::AdmissionLimits;
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId,
};
use fgit_wire::smart_http::{HttpLimits, ProtocolVersion, parse_head};
use fgit_wire::{Packet, PktLineDecoder, WireLimits, encode_packets};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_tag_only_repository_has_one_direct_push_ref_in_v0_and_v1() {
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "frankengit-http-push-discovery-{}",
        std::process::id()
    )));
    let (mut node, _) = OneNode::init(NodeConfig::new(
        scratch.0.clone(),
        TenantId::from_bytes([0xa1; 16]),
        RepositoryId::from_bytes([0xa2; 16]),
    ))
    .unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xa3; 16]),
        IdempotencyKey::new(b"tag-only-http-discovery".to_vec()).unwrap(),
    );
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let oid = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"hi");
    // One blob, stored DEFLATE block, Adler-32 for "hi", native pack trailer.
    let mut pack =
        b"PACK\0\0\0\x02\0\0\0\x01\x32\x78\x01\x01\x02\x00\xfd\xffhi\x01\x3b\x00\xd2".to_vec();
    let checksum = sha1_digest(&pack);
    pack.extend_from_slice(&checksum);
    let mut body = encode_packets(
        &[
            Packet::Data(
                format!("{} {oid} refs/tags/only\0report-status", "0".repeat(40)).into_bytes(),
            ),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap();
    body.extend_from_slice(&pack);
    let header = format!(
        "POST {route}/git-receive-pack HTTP/1.1\r\nHost: loopback\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let request = parse_head(header.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let outcome = node
        .smart_http_receive_rpc_in(
            &request,
            &session,
            &body,
            HttpLimits::default(),
            AdmissionLimits::default(),
            &mut || true,
            &mut Vec::new(),
        )
        .unwrap();
    assert!(matches!(
        outcome.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));

    for (protocol, version) in [
        ("", ProtocolVersion::V0),
        ("Git-Protocol: version=1\r\n", ProtocolVersion::V1),
    ] {
        let header = format!(
            "GET {route}/info/refs?service=git-receive-pack HTTP/1.1\r\nHost: loopback\r\n{protocol}\r\n"
        );
        let request = parse_head(header.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        // One visible direct ref fits. Adding a synthetic HEAD must not spend
        // another slot, and an unresolved default branch must not block push.
        let limits = WireLimits {
            max_advertised_refs: 1,
            ..WireLimits::default()
        };
        let response = node
            .smart_http_receive_discovery_in(&request, &session, limits.clone())
            .expect("push discovery does not require a resolvable fetch HEAD");
        assert_eq!(response.version(), version);
        assert!(
            response
                .head()
                .contains("application/x-git-receive-pack-advertisement")
        );
        let mut decoder = PktLineDecoder::new(limits).unwrap();
        let packets = decoder.push(response.body()).unwrap();
        decoder.finish().unwrap();
        let oid_prefix = format!("{oid} ");
        let advertised: Vec<&[u8]> = packets
            .iter()
            .filter_map(|packet| match packet {
                Packet::Data(data) if data.starts_with(oid_prefix.as_bytes()) => {
                    Some(data.as_slice())
                }
                _ => None,
            })
            .collect();
        assert_eq!(advertised.len(), 1);
        assert!(advertised[0].starts_with(format!("{oid} refs/tags/only\0").as_bytes()));
        assert!(
            !response
                .body()
                .windows(b" HEAD".len())
                .any(|w| w == b" HEAD")
        );
    }
    node.shutdown().unwrap();
}
