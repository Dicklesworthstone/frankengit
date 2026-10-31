//! Negotiation remains interactive while only its pack transition is deferred.

use super::*;
use crate::{
    GitDaemonRepositoryPath, GitDaemonRequest, GitDaemonServeError, GitDaemonService,
    GitDaemonSessionOutcome, serve_git_daemon_upload_pack_after_greeting,
};
use fgit_types::GitHashAlgorithm;
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, PackPayloadSource, Packet,
    UploadPackRepository, UploadPackVersion, WireError, WireLimits, encode_packets,
};
use std::cell::RefCell;
use std::io::{self, Cursor, Read, Write};
use std::rc::Rc;

struct Repository(Vec<AdvertisedRef>);
impl UploadPackRepository for Repository {
    fn object_format(&self) -> GitObjectFormat {
        self.0[0].oid.algorithm()
    }
    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.0
    }
    fn contains_want(&self, oid: AnyGitOid) -> bool {
        oid == self.0[0].oid
    }
    fn is_common(&self, _: AnyGitOid) -> bool {
        false
    }
}

struct Payload;
impl PackPayloadSource for Payload {
    fn next_chunk(&mut self, _: usize) -> Result<Option<Vec<u8>>, WireError> {
        Ok(None)
    }
}

struct RecordingWriter(Rc<RefCell<Vec<u8>>>);
impl Write for RecordingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct InteractiveReader {
    first: Cursor<Vec<u8>>,
    second: Cursor<Vec<u8>>,
    output: Rc<RefCell<Vec<u8>>>,
    intermediate: Vec<u8>,
    observed: bool,
}
impl Read for InteractiveReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.first.read(bytes)?;
        if count > 0 {
            return Ok(count);
        }
        assert!(
            self.output.borrow().ends_with(&self.intermediate),
            "the client must receive the intermediate response before sending its next round"
        );
        self.observed = true;
        self.second.read(bytes)
    }
}

fn packets(values: &[Packet]) -> Vec<u8> {
    encode_packets(values, &WireLimits::default()).unwrap()
}

#[test]
fn intermediate_negotiation_is_not_held_for_pack_preparation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let oid = AnyGitOid::from_hex(format, &"1".repeat(format.digest_len() * 2)).unwrap();
        let repository = Repository(vec![
            AdvertisedRef::new(oid, b"refs/heads/main", &WireLimits::default()).unwrap(),
        ]);
        for version in [
            UploadPackVersion::V0,
            UploadPackVersion::V1,
            UploadPackVersion::V2,
        ] {
            let (first, second, intermediate, caps) = if version == UploadPackVersion::V2 {
                (
                    packets(&[
                        Packet::Data(b"command=ls-refs\n".to_vec()),
                        Packet::Data(format!("object-format={}\n", format.as_str()).into_bytes()),
                        Packet::Delimiter,
                        Packet::Flush,
                    ]),
                    packets(&[
                        Packet::Data(b"command=fetch\n".to_vec()),
                        Packet::Data(format!("object-format={}\n", format.as_str()).into_bytes()),
                        Packet::Delimiter,
                        Packet::Data(format!("want {oid}\n").into_bytes()),
                        Packet::Data(b"done\n".to_vec()),
                        Packet::Flush,
                    ]),
                    packets(&[
                        Packet::Data(format!("{oid} refs/heads/main\n").into_bytes()),
                        Packet::Flush,
                    ]),
                    Capabilities::default(),
                )
            } else {
                (
                    packets(&[
                        Packet::Data(format!("want {oid} multi_ack\n").into_bytes()),
                        Packet::Flush,
                    ]),
                    packets(&[Packet::Data(b"done\n".to_vec())]),
                    packets(&[Packet::Data(b"NAK\n".to_vec())]),
                    Capabilities::parse_v1(b"multi_ack", &WireLimits::default()).unwrap(),
                )
            };
            let output = Rc::new(RefCell::new(Vec::new()));
            let mut reader = InteractiveReader {
                first: Cursor::new(first),
                second: Cursor::new(second),
                output: Rc::clone(&output),
                intermediate,
                observed: false,
            };
            let mut builds = 0;
            let outcome = serve_git_daemon_upload_pack_after_greeting(
                &mut reader,
                &mut RecordingWriter(Rc::clone(&output)),
                GitDaemonRequest {
                    repository_path: GitDaemonRepositoryPath::parse(b"/repo.git").unwrap(),
                    service: GitDaemonService::UploadPack(version),
                },
                &repository,
                caps,
                WireLimits::default(),
                None,
                pack_line,
                |_, _| -> Result<Payload, GitDaemonServeError<NodePackMaterializationRefusal>> {
                    builds += 1;
                    assert!(
                        !output
                            .borrow()
                            .windows(9)
                            .any(|bytes| bytes == b"packfile\n")
                    );
                    Err(GitDaemonServeError::Pack(
                        PackWriteError::Pack(PackError::TotalExpandedLimit {
                            actual: 8192,
                            limit: 4096,
                        })
                        .into(),
                    ))
                },
            );
            assert!(reader.observed);
            assert_eq!(builds, 1);
            assert!(matches!(outcome, Err(GitDaemonServeError::Pack(_))));
            let expected = pack_line(
                &PackWriteError::Pack(PackError::TotalExpandedLimit {
                    actual: 8192,
                    limit: 4096,
                })
                .into(),
            )
            .unwrap();
            assert!(
                output
                    .borrow()
                    .ends_with(&packets(&[Packet::Data(expected)]))
            );
        }
    }
}

struct RejectErrorWrite {
    attempted: bool,
}
impl Write for RejectErrorWrite {
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
fn a_failed_diagnostic_write_retains_the_original_resource_refusal() {
    let format = GitHashAlgorithm::Sha1;
    let oid = AnyGitOid::from_hex(format, &"1".repeat(40)).unwrap();
    let repository = Repository(vec![
        AdvertisedRef::new(oid, b"refs/heads/main", &WireLimits::default()).unwrap(),
    ]);
    let input = packets(&[
        Packet::Data(format!("want {oid}\n").into_bytes()),
        Packet::Flush,
        Packet::Data(b"done\n".to_vec()),
    ]);
    let mut writer = RejectErrorWrite { attempted: false };
    let outcome: Result<
        GitDaemonSessionOutcome,
        GitDaemonServeError<NodePackMaterializationRefusal>,
    > = serve_git_daemon_upload_pack_after_greeting(
        &mut input.as_slice(),
        &mut writer,
        GitDaemonRequest {
            repository_path: GitDaemonRepositoryPath::parse(b"/repo.git").unwrap(),
            service: GitDaemonService::UploadPack(UploadPackVersion::V0),
        },
        &repository,
        Capabilities::default(),
        WireLimits::default(),
        None,
        pack_line,
        |_, _| -> Result<Payload, _> {
            Err(GitDaemonServeError::Pack(
                PackWriteError::Pack(PackError::TotalExpandedLimit {
                    actual: 8192,
                    limit: 4096,
                })
                .into(),
            ))
        },
    );
    assert!(writer.attempted);
    assert!(matches!(outcome, Err(GitDaemonServeError::Pack(ref error))
        if matches!(error, NodePackMaterializationRefusal::Pack(inner)
            if matches!(inner.as_ref(), PackWriteError::Pack(PackError::TotalExpandedLimit { actual: 8192, limit: 4096 })))));
}

#[test]
fn an_unknown_builder_failure_keeps_its_prefix_and_fatal_after_work_expires() {
    use crate::{
        DeadlineTcpStream, GitDaemonSessionDeadline, GitDaemonSessionTimeout,
        GitDaemonSessionWorkScaling,
    };
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    let format = GitHashAlgorithm::Sha1;
    let oid = AnyGitOid::from_hex(format, &"1".repeat(40)).unwrap();
    let repository = Repository(vec![
        AdvertisedRef::new(oid, b"refs/heads/main", &WireLimits::default()).unwrap(),
    ]);
    for (version, sideband) in [
        (UploadPackVersion::V0, false),
        (UploadPackVersion::V0, true),
        (UploadPackVersion::V1, false),
        (UploadPackVersion::V1, true),
        (UploadPackVersion::V2, true),
    ] {
        let input = if version == UploadPackVersion::V2 {
            packets(&[
                Packet::Data(b"command=fetch\n".to_vec()),
                Packet::Delimiter,
                Packet::Data(format!("want {oid}\n").into_bytes()),
                Packet::Data(b"done\n".to_vec()),
                Packet::Flush,
            ])
        } else {
            let caps = if sideband { " side-band-64k" } else { "" };
            packets(&[
                Packet::Data(format!("want {oid}{caps}\n").into_bytes()),
                Packet::Flush,
                Packet::Data(b"done\n".to_vec()),
            ])
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let mut deadline = GitDaemonSessionDeadline::new(
            GitDaemonSessionTimeout::try_new(Duration::from_secs(5)).unwrap(),
            GitDaemonSessionWorkScaling::DEFAULT,
        );
        deadline.started = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
        deadline.note_admitted(1 << 30);
        assert!(!deadline.expired());
        let outcome = serve_git_daemon_upload_pack_after_greeting(
            &mut input.as_slice(),
            &mut DeadlineTcpStream::new(&mut stream, deadline.clone()),
            GitDaemonRequest {
                repository_path: GitDaemonRepositoryPath::parse(b"/repo.git").unwrap(),
                service: GitDaemonService::UploadPack(version),
            },
            &repository,
            Capabilities::parse_v1(b"side-band-64k", &WireLimits::default()).unwrap(),
            WireLimits::default(),
            Some(&deadline),
            |_| None,
            |_, _| -> Result<Payload, GitDaemonServeError<&'static str>> {
                deadline.shared.admitted_bytes.store(0, Ordering::Relaxed);
                assert!(deadline.expired());
                Err(GitDaemonServeError::Pack("custom build refusal"))
            },
        );
        assert!(matches!(
            outcome,
            Err(GitDaemonServeError::Pack("custom build refusal"))
        ));
        stream.shutdown(Shutdown::Write).unwrap();
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).unwrap();
        let mut decoder = fgit_wire::PktLineDecoder::new(WireLimits::default()).unwrap();
        let output = decoder.push(&bytes).unwrap();
        decoder.finish().unwrap();
        let expected_prefix = if version == UploadPackVersion::V2 {
            Packet::Data(b"packfile\n".to_vec())
        } else {
            Packet::Data(b"NAK\n".to_vec())
        };
        if sideband {
            assert!(
                output.ends_with(&[
                    expected_prefix,
                    Packet::Data(b"\x03custom build refusal".to_vec()),
                    Packet::Flush,
                ]),
                "the generic fallback retains its original protocol shape: {output:?}"
            );
        } else {
            assert_eq!(output.last(), Some(&expected_prefix));
        }
        assert!(!bytes.windows(4).any(|part| part == b"ERR "));
        assert!(deadline.expired());
        assert!(deadline.remaining_write().is_ok());
        assert!(!deadline.note_selected_upload_work(usize::MAX));
    }
}
