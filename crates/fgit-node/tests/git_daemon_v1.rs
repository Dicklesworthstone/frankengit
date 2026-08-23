#![forbid(unsafe_code)]
//! Git-daemon protocol-V1 greeting selection (`frankengit-daemon-v1-greeting-refused-uhp0`).
//!
//! Modern Git sends `version=1` in the NUL-parameter suffix of its git-daemon
//! greeting. The daemon admits that exact parameter and selects the existing
//! legacy V1 wire grammar. V2 remains a typed refusal because its separate
//! ls-refs service is not wired here.
//!
//! V1's mandatory `version 1\n` pkt-line means a complete V1 advertisement
//! cannot be byte-identical to V0. The permitted twin below instead pins the
//! precise compatibility invariant: that required prelude is the *only*
//! difference, including for a non-empty capability advertisement.

use std::convert::Infallible;
use std::io::Cursor;

use fgit_node::{
    GitDaemonTransportRefusal, parse_git_daemon_request, serve_git_daemon_upload_pack,
};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, PackPayloadSource,
    UploadPackRepository, UploadPackVersion, WireError, WireLimits,
};

struct EmptyRepository;

impl UploadPackRepository for EmptyRepository {
    fn object_format(&self) -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &[]
    }

    fn contains_want(&self, _oid: AnyGitOid) -> bool {
        false
    }

    fn is_common(&self, _oid: AnyGitOid) -> bool {
        false
    }
}

struct EmptyPayload;

impl PackPayloadSource for EmptyPayload {
    fn next_chunk(&mut self, _maximum_chunk_bytes: usize) -> Result<Option<Vec<u8>>, WireError> {
        Ok(None)
    }
}

fn greeting(parameters: &[&[u8]]) -> Vec<u8> {
    let mut payload = b"git-upload-pack /demo.git\0".to_vec();
    for parameter in parameters {
        payload.extend_from_slice(parameter);
        payload.push(0);
    }
    let mut frame = format!("{:04x}", payload.len() + 4).into_bytes();
    frame.extend_from_slice(&payload);
    frame
}

fn capabilities() -> Capabilities {
    Capabilities::parse_v1(b"agent=fgit-node-v1-test", &WireLimits::default())
        .expect("the deterministic test capability is valid v0/v1 wire text")
}

fn serve_empty(greeting: Vec<u8>, capabilities: Capabilities) -> (UploadPackVersion, Vec<u8>) {
    let mut reader = Cursor::new(greeting);
    let mut output = Vec::new();
    let outcome = serve_git_daemon_upload_pack(
        &mut reader,
        &mut output,
        &EmptyRepository,
        capabilities,
        WireLimits::default(),
        |_request, _pack_request| -> Result<EmptyPayload, Infallible> { Ok(EmptyPayload) },
    )
    .expect("an empty repository finishes after its complete advertisement");
    (outcome.request().upload_pack_version(), output)
}

#[test]
fn version_one_greeting_emits_only_its_required_prelude_before_the_v0_advertisement() {
    let (v0_version, v0_advertisement) = serve_empty(greeting(&[]), capabilities());
    let (v1_version, v1_advertisement) = serve_empty(greeting(&[b"version=1"]), capabilities());

    assert_eq!(v0_version, UploadPackVersion::V0);
    assert_eq!(v1_version, UploadPackVersion::V1);

    const V1_PRELUDE: &[u8] = b"000eversion 1\n";
    assert!(
        v1_advertisement.starts_with(V1_PRELUDE),
        "V1 must start with its required declaration, got {v1_advertisement:?}"
    );
    assert_eq!(
        &v1_advertisement[V1_PRELUDE.len()..],
        v0_advertisement.as_slice(),
        "the V1 declaration must not change the ref or capability advertisement"
    );
}

#[test]
fn unknown_greeting_generations_remain_typed_refusals() {
    // version=2 left this refusal set when 6mmn wired the v2 lane; every
    // other generation stays refused with its exact parameter length.
    for (parameter, expected_bytes) in [
        (b"version=3".as_slice(), 1),
        (b"version=future".as_slice(), 6),
    ] {
        let refusal = parse_git_daemon_request(&greeting(&[parameter]), WireLimits::default())
            .expect_err("only the exact V1 extension is admitted on this lane");

        assert!(
            matches!(
                refusal,
                GitDaemonTransportRefusal::UnsupportedProtocolVersion { version_bytes }
                    if version_bytes == expected_bytes
            ),
            "parameter {:?} must retain its typed refusal, got {refusal:?}",
            String::from_utf8_lossy(parameter)
        );
    }
}
