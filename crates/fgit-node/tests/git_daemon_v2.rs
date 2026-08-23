#![forbid(unsafe_code)]
//! Git-daemon protocol-V2 greeting selection and session serving
//! (`frankengit-daemon-v2-lsrefs-serving-6mmn`).
//!
//! Modern Git defaults to protocol v2 and sends `version=2` in the
//! NUL-parameter suffix of its git-daemon greeting. The daemon admits that
//! parameter and serves the SANS-I/O v2 command machine from `fgit-wire`:
//! `ls-refs` answers from the authenticated advertised-ref view, and a
//! completed `fetch` request flows into the canonical pack planner exactly as
//! the legacy lanes do. Each v2 command is one complete machine run: the
//! request is `command=` packet, then client capabilities, then a
//! delimiter packet, then arguments, then a flush.

use std::convert::Infallible;
use std::io::Cursor;

use fgit_node::{
    GitDaemonSessionOutcome, GitDaemonTransportRefusal, parse_git_daemon_request,
    serve_git_daemon_upload_pack,
};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, PackPayloadSource,
    UploadPackRepository, UploadPackVersion, WireError, WireLimits,
};

const TIP: &str = "1111111111111111111111111111111111111111";

fn tip() -> AnyGitOid {
    AnyGitOid::from_hex(GitObjectFormat::Sha1, TIP).expect("fixture oid")
}

struct OneRefRepository;

impl OneRefRepository {
    fn refs() -> &'static [AdvertisedRef] {
        static REFS: std::sync::LazyLock<Vec<AdvertisedRef>> = std::sync::LazyLock::new(|| {
            vec![
                AdvertisedRef::new(tip(), b"refs/heads/main", &WireLimits::default())
                    .expect("fixture ref"),
            ]
        });
        &REFS
    }
}

impl UploadPackRepository for OneRefRepository {
    fn object_format(&self) -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        Self::refs()
    }

    fn contains_want(&self, oid: AnyGitOid) -> bool {
        oid == tip()
    }

    fn is_common(&self, _oid: AnyGitOid) -> bool {
        false
    }
}

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

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut framed = format!("{:04x}", payload.len() + 4).into_bytes();
    framed.extend_from_slice(payload);
    framed
}

fn pkt_line(line: &[u8]) -> Vec<u8> {
    frame(line)
}

const DELIMITER: &[u8] = b"0001";
const FLUSH: &[u8] = b"0000";

fn greeting(version: Option<&[u8]>) -> Vec<u8> {
    let mut payload = b"git-upload-pack /22222222222222222222222222222222.git\0".to_vec();
    if let Some(version) = version {
        payload.extend_from_slice(b"version=");
        payload.extend_from_slice(version);
        payload.push(0);
    }
    frame(&payload)
}

fn serve(
    wire: Vec<u8>,
    repository: &impl UploadPackRepository,
) -> (
    Result<GitDaemonSessionOutcome, fgit_node::GitDaemonServeError<Infallible>>,
    Vec<u8>,
) {
    let mut output = Vec::new();
    let outcome = serve_git_daemon_upload_pack(
        &mut Cursor::new(wire),
        &mut output,
        repository,
        Capabilities::parse_v1(b"agent=v2-test", &WireLimits::default())
            .expect("deterministic test capabilities"),
        WireLimits::default(),
        |_request, _pack_request| -> Result<EmptyPayload, Infallible> { Ok(EmptyPayload) },
    );
    (outcome, output)
}

#[test]
fn version_two_greeting_selects_the_v2_lane() {
    let request = parse_git_daemon_request(&greeting(Some(b"2")), WireLimits::default())
        .expect("a version=2 greeting is admitted");
    assert_eq!(request.upload_pack_version(), UploadPackVersion::V2);
}

#[test]
fn version_three_greeting_remains_a_typed_refusal() {
    let error = parse_git_daemon_request(&greeting(Some(b"3")), WireLimits::default())
        .expect_err("an unknown protocol generation stays refused");
    assert!(matches!(
        error,
        GitDaemonTransportRefusal::UnsupportedProtocolVersion { .. }
    ));
}

#[test]
fn an_empty_repository_v2_session_serves_ls_refs_then_ends_cleanly() {
    let mut wire = greeting(Some(b"2"));
    wire.extend_from_slice(&pkt_line(b"command=ls-refs"));
    wire.extend_from_slice(DELIMITER);
    wire.extend_from_slice(FLUSH);

    let (outcome, output) = serve(wire, &EmptyRepository);
    assert!(matches!(
        outcome,
        Ok(GitDaemonSessionOutcome::EmptyRepository(_))
    ));
    let text = String::from_utf8(output).expect("advertisement is utf-8 pkt-line text");
    assert!(text.contains("version 2"), "the v2 prelude must be present");
}

#[test]
fn a_v2_fetch_request_flows_into_the_canonical_pack_planner() {
    let mut wire = greeting(Some(b"2"));
    // A stock clone first asks what refs exist.
    wire.extend_from_slice(&pkt_line(b"command=ls-refs"));
    wire.extend_from_slice(DELIMITER);
    wire.extend_from_slice(FLUSH);
    // Then it requests the tips it wants, terminating arguments with done.
    wire.extend_from_slice(&pkt_line(b"command=fetch"));
    wire.extend_from_slice(DELIMITER);
    wire.extend_from_slice(&pkt_line(format!("want {TIP}").as_bytes()));
    wire.extend_from_slice(&pkt_line(b"done"));
    wire.extend_from_slice(FLUSH);

    let (outcome, output) = serve(wire, &OneRefRepository);
    assert!(matches!(outcome, Ok(GitDaemonSessionOutcome::Pack(_))));

    let text = String::from_utf8(output).expect("pkt-line frames are utf-8 safe here");
    assert!(text.contains("version 2"), "the v2 prelude must be present");
    assert!(
        text.contains("packfile\n"),
        "fetch must answer with the packfile section marker"
    );
}

#[test]
fn ls_refs_lists_the_advertised_tip_for_each_command() {
    let mut wire = greeting(Some(b"2"));
    for _ in 0..2 {
        wire.extend_from_slice(&pkt_line(b"command=ls-refs"));
        wire.extend_from_slice(DELIMITER);
        wire.extend_from_slice(FLUSH);
    }
    // Without a fetch the session still ends cleanly: ls-refs answered both
    // commands and the client closed having learned everything it needed.
    let (outcome, output) = serve(wire, &OneRefRepository);
    assert!(matches!(
        outcome,
        Ok(GitDaemonSessionOutcome::EmptyRepository(_))
    ));
    let occurrences = output
        .windows(TIP.len())
        .filter(|window| *window == TIP.as_bytes())
        .count();
    assert_eq!(
        occurrences, 2,
        "each of the two ls-refs commands answers once with the advertised tip"
    );
}
