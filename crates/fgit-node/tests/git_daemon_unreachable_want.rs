#![forbid(unsafe_code)]
//! Transport regression for frankengit-aitq: an unreachable want gets one
//! upstream-worded ERR packet, without entering pack construction. This is a
//! protocol adapter test; persisted-node disclosure coverage lives beside
//! `upload_visibility`'s authority-backed fixtures.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io::{self, Write};

use fgit_admission::AdmissionSnapshot;
use fgit_node::{
    AdmissionUploadPackRepository, GitDaemonServeError, GitDaemonSessionOutcome,
    GitDaemonTransportRefusal, serve_git_daemon_upload_pack,
};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use fgit_wire::visibility::RefVisibility;
use fgit_wire::{Capabilities, PackPayloadSource, UploadPackRepository, WireError, WireLimits};

struct Payload;
impl PackPayloadSource for Payload {
    fn next_chunk(&mut self, _: usize) -> Result<Option<Vec<u8>>, WireError> {
        Ok(None)
    }
}

fn oid(format: GitHashAlgorithm, digit: char) -> GitOid {
    GitOid::from_hex(format, &digit.to_string().repeat(format.digest_len() * 2)).unwrap()
}

fn repository(
    format: GitHashAlgorithm,
    hidden_object_exists: bool,
) -> AdmissionUploadPackRepository {
    repository_view(format, true, hidden_object_exists)
}

fn repository_view(
    format: GitHashAlgorithm,
    visible_object_exists: bool,
    hidden_object_exists: bool,
) -> AdmissionUploadPackRepository {
    let mut refs = BTreeMap::new();
    if visible_object_exists {
        refs.insert(
            RefName::try_new(b"refs/heads/main").unwrap(),
            oid(format, '1'),
        );
    }
    if hidden_object_exists {
        refs.insert(
            RefName::try_new(b"refs/private/secret").unwrap(),
            oid(format, '2'),
        );
    }
    let mut hidden_refs = RefVisibility::new();
    hidden_refs
        .push_rule(b"refs/private", &WireLimits::default())
        .unwrap();
    AdmissionUploadPackRepository::from_snapshot(
        &AdmissionSnapshot {
            refs,
            hidden_refs,
            ..AdmissionSnapshot::default()
        },
        format,
        &WireLimits::default(),
    )
    .unwrap()
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{:04x}", payload.len() + 4).into_bytes();
    bytes.extend_from_slice(payload);
    bytes
}

fn greeting(version: u8) -> Vec<u8> {
    let version_suffix = if version == 0 {
        String::new()
    } else {
        format!("\0version={version}\0")
    };
    frame(
        format!("git-upload-pack /22222222222222222222222222222222.git\0{version_suffix}")
            .as_bytes(),
    )
}

fn request(version: u8, format: GitHashAlgorithm, want: &str) -> Vec<u8> {
    let mut bytes = greeting(version);
    if version == 2 {
        bytes.extend(frame(b"command=fetch\n"));
        bytes.extend(frame(
            format!("object-format={}\n", format.as_str()).as_bytes(),
        ));
        bytes.extend_from_slice(b"0001");
    }
    bytes.extend(frame(format!("want {want}\n").as_bytes()));
    if version != 2 {
        bytes.extend_from_slice(b"0000");
    }
    bytes.extend(frame(b"done\n"));
    if version == 2 {
        bytes.extend_from_slice(b"0000");
    }
    bytes
}

fn serve(
    bytes: &[u8],
    repository: &impl UploadPackRepository,
    writer: &mut impl Write,
) -> (
    Result<GitDaemonSessionOutcome, GitDaemonServeError<Infallible>>,
    usize,
) {
    let mut builds = 0;
    let outcome = serve_git_daemon_upload_pack(
        &mut &bytes[..],
        writer,
        repository,
        Capabilities::parse_v1(b"agent=unreachable-want-test", &WireLimits::default()).unwrap(),
        WireLimits::default(),
        |_, _| {
            builds += 1;
            Ok::<_, Infallible>(Payload)
        },
    );
    (outcome, builds)
}

fn assert_want_refusal(
    result: Result<GitDaemonSessionOutcome, GitDaemonServeError<Infallible>>,
    expected: GitOid,
) {
    assert!(matches!(
        result,
        Err(GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(
            WireError::WantNotAdvertised { oid } | WireError::WantNotReachable { oid }
        ))) if oid == expected
    ));
}

#[test]
fn refused_wants_get_exact_upstream_err_before_pack_in_both_formats_and_all_versions() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let repository = repository(format, true);
        for version in [0, 1, 2] {
            // Permitted twin: the exact same transport and format still serve
            // the visible object, so refusing all wants cannot satisfy this test.
            let mut output = Vec::new();
            let (result, builds) = serve(
                &request(version, format, &oid(format, '1').to_string()),
                &repository,
                &mut output,
            );
            assert!(
                matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),
                "{result:?}"
            );
            assert_eq!(builds, 1);
            assert!(!output.windows(4).any(|bytes| bytes == b"ERR "));

            for want in [oid(format, '2'), oid(format, '3')] {
                output.clear();
                let (result, builds) = serve(
                    &request(version, format, &want.to_string()),
                    &repository,
                    &mut output,
                );
                assert_want_refusal(result, want);
                assert_eq!(builds, 0, "a rejected want never enters pack construction");
                assert!(output.ends_with(&frame(
                    format!("ERR upload-pack: not our ref {want}\n").as_bytes()
                )));
                for forbidden in [
                    b"NAK".as_slice(),
                    b"acknowledgments",
                    b"packfile\n",
                    b"PACK",
                ] {
                    assert!(
                        !output
                            .windows(forbidden.len())
                            .any(|bytes| bytes == forbidden)
                    );
                }
            }
        }
    }
}

#[test]
fn the_same_want_is_indistinguishable_when_hidden_or_absent() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let hidden = repository(format, true);
        let absent = repository(format, false);
        for version in [0, 1, 2] {
            let want = oid(format, '2');
            let bytes = request(version, format, &want.to_string());
            let mut responses = Vec::new();
            for repository in [&hidden, &absent] {
                let mut output = Vec::new();
                let (result, builds) = serve(&bytes, repository, &mut output);
                assert_want_refusal(result, want);
                assert_eq!(builds, 0);
                responses.push(output);
            }
            assert_eq!(
                responses[0], responses[1],
                "the response cannot be an existence oracle"
            );
        }
    }
}

#[test]
fn empty_legacy_views_refuse_wants_and_do_not_disclose_hidden_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let hidden = repository_view(format, false, true);
        let absent = repository_view(format, false, false);
        for version in [0, 1] {
            for want in [oid(format, '2'), oid(format, '3')] {
                let bytes = request(version, format, &want.to_string());
                let mut responses = Vec::new();
                for repository in [&hidden, &absent] {
                    assert!(repository.advertised_refs().is_empty());
                    let mut output = Vec::new();
                    let (result, builds) = serve(&bytes, repository, &mut output);
                    assert_want_refusal(result, want);
                    assert_eq!(builds, 0);
                    assert!(output.ends_with(&frame(
                        format!("ERR upload-pack: not our ref {want}\n").as_bytes()
                    )));
                    assert!(!output.windows(3).any(|bytes| bytes == b"NAK"));
                    assert!(!output.windows(4).any(|bytes| bytes == b"PACK"));
                    responses.push(output);
                }
                assert_eq!(
                    responses[0], responses[1],
                    "a hidden-only view and an empty view disclose the same information"
                );
            }
        }
    }
}

#[test]
fn empty_legacy_views_complete_on_clean_eof_or_want_less_flush() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for version in [0, 1] {
            let mut responses = Vec::new();
            for hidden_object_exists in [false, true] {
                let repository = repository_view(format, false, hidden_object_exists);
                for ending in [b"".as_slice(), b"0000".as_slice()] {
                    let mut bytes = greeting(version);
                    bytes.extend_from_slice(ending);
                    let mut output = Vec::new();
                    let (result, builds) = serve(&bytes, &repository, &mut output);
                    assert!(
                        matches!(result, Ok(GitDaemonSessionOutcome::EmptyRepository(_))),
                        "{result:?}"
                    );
                    assert_eq!(builds, 0);
                    assert!(!output.windows(4).any(|bytes| bytes == b"ERR "));
                    assert!(!output.windows(4).any(|bytes| bytes == b"PACK"));
                    responses.push(output);
                }
            }
            assert!(responses.windows(2).all(|pair| pair[0] == pair[1]));

            // The zero-input exception belongs only to empty advertisements.
            let visible = repository(format, false);
            let (result, builds) = serve(&greeting(version), &visible, &mut Vec::new());
            assert!(matches!(
                result,
                Err(GitDaemonServeError::Transport(
                    GitDaemonTransportRefusal::IncompleteNegotiation
                ))
            ));
            assert_eq!(builds, 0);
        }
    }
}

#[test]
fn empty_legacy_views_refuse_truncated_or_malformed_requests() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let repository = repository_view(format, false, false);
        for version in [0, 1] {
            for truncated in [b"0".as_slice(), b"000".as_slice(), b"0009wa".as_slice()] {
                let mut bytes = greeting(version);
                bytes.extend_from_slice(truncated);
                let mut output = Vec::new();
                let (result, builds) = serve(&bytes, &repository, &mut output);
                assert!(matches!(
                    result,
                    Err(GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(
                        WireError::TruncatedPacket { pending }
                    ))) if pending == truncated.len()
                ));
                assert_eq!(builds, 0);
                assert!(!output.windows(4).any(|bytes| bytes == b"ERR "));
            }

            let mut bytes = greeting(version);
            bytes.extend_from_slice(b"zzzznot-a-packet-length");
            let mut output = Vec::new();
            let (result, builds) = serve(&bytes, &repository, &mut output);
            assert!(matches!(
                result,
                Err(GitDaemonServeError::Transport(
                    GitDaemonTransportRefusal::Wire(_)
                ))
            ));
            assert_eq!(builds, 0);
            assert!(!output.windows(4).any(|bytes| bytes == b"ERR "));
        }
    }
}

#[test]
fn malformed_wants_do_not_gain_a_reflected_protocol_diagnostic() {
    let repository = repository(GitHashAlgorithm::Sha1, false);
    for version in [0, 1, 2] {
        let mut output = Vec::new();
        let (result, builds) = serve(
            &request(version, GitHashAlgorithm::Sha1, "not-an-object-id"),
            &repository,
            &mut output,
        );
        assert!(result.is_err());
        assert_eq!(builds, 0);
        assert!(!output.windows(4).any(|bytes| bytes == b"ERR "));
    }
}

struct RefusalWriteFails {
    attempted: bool,
}
impl Write for RefusalWriteFails {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.windows(4).any(|part| part == b"ERR ") {
            self.attempted = true;
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_disconnected_client_does_not_change_the_typed_want_refusal() {
    for version in [0, 1, 2] {
        let format = GitHashAlgorithm::Sha1;
        let repository = repository(format, false);
        let want = oid(format, '2');
        let mut writer = RefusalWriteFails { attempted: false };
        let (result, builds) = serve(
            &request(version, format, &want.to_string()),
            &repository,
            &mut writer,
        );
        assert_want_refusal(result, want);
        assert!(writer.attempted);
        assert_eq!(builds, 0);
    }
}
