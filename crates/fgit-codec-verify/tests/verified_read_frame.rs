#![forbid(unsafe_code)]
//! A separate executable parses a server's frame before the client verifies it.

use std::io::Write;
use std::process::{Command, Stdio};

use fgit_codec::{CryptoBodyIdentity, RepositoryConfigurationBody, body_id};
use fgit_crypto::{ref_state_membership_proof, ref_state_merkle_root};
use fgit_types::hash::Digest;
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::refs::RefName;
use fgit_verified_read::{
    PinnedAuthorityHead, VerifiedMembership, VerifiedReadAnswer, VerifiedReadEnvelope,
    encode_verified_read_envelope, verify_envelope,
};

fn name(value: &[u8]) -> RefName {
    RefName::try_new(value).expect("fixture ref name is valid")
}

const fn oid(byte: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([byte; GitOidSha1::LEN]))
}

fn server_envelope() -> (PinnedAuthorityHead, Vec<u8>) {
    let requested = name(b"refs/heads/main");
    let entries = vec![
        (requested.clone(), oid(0x11)),
        (name(b"refs/tags/v1"), oid(0x22)),
    ];
    let (bound_oid, proof) =
        ref_state_membership_proof(&entries, &requested).expect("fixture ref is present");
    let configuration = RepositoryConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha1,
        hidden_ref_rules: Vec::new(),
    };
    let configuration_id =
        body_id(&CryptoBodyIdentity, &configuration).expect("configuration identifies");
    let mut head = fgit_codec::harness::genesis_head();
    head.ref_root = ref_state_merkle_root(&entries).expect("fixture ref root is canonical");
    head.configuration_root = Digest::new(configuration_id.algorithm(), *configuration_id.digest());
    let pinned = PinnedAuthorityHead::new(head.clone());
    let envelope = VerifiedReadEnvelope::new(
        head,
        Some(configuration),
        VerifiedReadAnswer::RefMembership {
            name: requested,
            oid: bound_oid,
            proof: Box::new(proof),
        },
    );
    (
        pinned,
        encode_verified_read_envelope(&envelope).expect("server envelope encodes"),
    )
}

#[test]
fn child_process_parses_server_frame_then_client_verifies_the_pinned_proof() {
    let (pinned, relay_bytes) = server_envelope();
    let mut child = Command::new(env!("CARGO_BIN_EXE_verified_read_frame"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("std-only frame consumer starts");
    child
        .stdin
        .take()
        .expect("child stdin is piped")
        .write_all(&relay_bytes)
        .expect("server sends only frame bytes to child");
    let output = child.wait_with_output().expect("child process reaps");
    assert!(
        output.status.success(),
        "independent frame consumer refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = String::from_utf8(output.stdout).expect("child summary is UTF-8");
    let (_, payload) = fgit_codec::split_frame(&relay_bytes, fgit_codec::DecodeLimits::DEFAULT)
        .expect("the server emitted one canonical frame");
    assert_eq!(
        summary,
        format!(
            "frankengit/verified-read-envelope/v1|verified-read-envelope|1|0|{}\n",
            payload.len()
        ),
        "child parses the framed envelope without importing fgit-codec"
    );

    let decoded = fgit_verified_read::decode_verified_read_envelope(
        &relay_bytes,
        fgit_codec::DecodeLimits::DEFAULT,
    )
    .expect("client decodes the server frame after the child boundary");
    assert_eq!(
        verify_envelope(&pinned, &decoded),
        Ok(VerifiedMembership::Ref),
        "the client verifier accepts only the proof bound to its own head pin"
    );
}
