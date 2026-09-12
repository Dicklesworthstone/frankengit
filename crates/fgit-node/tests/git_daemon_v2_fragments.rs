#![forbid(unsafe_code)]
//! Arbitrary TCP read boundaries must not reset a partially decoded command.
use fgit_node::{
    GitDaemonServeError, GitDaemonSessionOutcome, GitDaemonTransportRefusal,
    serve_git_daemon_upload_pack,
};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, PackPayloadSource,
    UploadPackRepository, WireError, WireLimits,
};
use std::convert::Infallible;
use std::io::{self, Read};
struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
}
impl UploadPackRepository for Repository {
    fn object_format(&self) -> GitObjectFormat {
        self.format
    }
    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }
    fn contains_want(&self, id: AnyGitOid) -> bool {
        self.refs[0].oid == id
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
struct Fragmented {
    bytes: Vec<u8>,
    at: usize,
    split: usize,
    maximum: usize,
}
impl Read for Fragmented {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let until = if self.at < self.split {
            self.split
        } else {
            self.bytes.len()
        };
        let count = output.len().min(until - self.at).min(self.maximum);
        output[..count].copy_from_slice(&self.bytes[self.at..self.at + count]);
        self.at += count;
        Ok(count)
    }
}
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", bytes.len() + 4).into_bytes();
    out.extend_from_slice(bytes);
    out
}
fn greeting() -> Vec<u8> {
    frame(b"git-upload-pack /22222222222222222222222222222222.git\0\0version=2\0")
}
fn command(name: &str, format: GitObjectFormat) -> Vec<u8> {
    let mut bytes = frame(format!("command={name}\n").as_bytes());
    bytes.extend(frame(
        format!("object-format={}\n", format.as_str()).as_bytes(),
    ));
    bytes.extend_from_slice(b"0001");
    bytes
}
fn repository(format: GitObjectFormat) -> Repository {
    let oid = AnyGitOid::from_hex(format, &"1".repeat(format.digest_len() * 2)).unwrap();
    Repository {
        format,
        refs: vec![AdvertisedRef::new(oid, b"refs/heads/main", &WireLimits::default()).unwrap()],
    }
}
fn serve(
    bytes: Vec<u8>,
    split: usize,
    maximum: usize,
    repository: &Repository,
) -> (
    Result<GitDaemonSessionOutcome, GitDaemonServeError<Infallible>>,
    Vec<u8>,
    usize,
) {
    let mut reader = Fragmented {
        bytes,
        at: 0,
        split,
        maximum,
    };
    let mut output = Vec::new();
    let mut builds = 0;
    let result = serve_git_daemon_upload_pack(
        &mut reader,
        &mut output,
        repository,
        Capabilities::parse_v1(b"agent=fragment-regression", &WireLimits::default()).unwrap(),
        WireLimits::default(),
        |_, _| {
            builds += 1;
            Ok::<_, Infallible>(Payload)
        },
    );
    (result, output, builds)
}
#[test]
fn ls_refs_and_fetch_preserve_every_coalesced_and_fragmented_command_boundary() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format);
        let mut bytes = greeting();
        let greeting_len = bytes.len();
        for _ in 0..2 {
            bytes.extend(command("ls-refs", format));
            bytes.extend(frame(b"ref-prefix refs/heads/main\n"));
            bytes.extend_from_slice(b"0000");
        }
        bytes.extend(command("fetch", format));
        bytes.extend(frame(
            format!("want {}\n", repository.refs[0].oid).as_bytes(),
        ));
        bytes.extend(frame(b"done\n"));
        bytes.extend_from_slice(b"0000");
        let (result, expected, count) = serve(bytes.clone(), bytes.len(), usize::MAX, &repository);
        assert!(
            matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),
            "{result:?}"
        );
        assert_eq!(count, 1);
        for split in greeting_len..=bytes.len() {
            let (result, actual, count) = serve(bytes.clone(), split, usize::MAX, &repository);
            assert!(
                matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),
                "{format:?}, split={split}: {result:?}"
            );
            assert_eq!(
                actual, expected,
                "transport boundaries must not change wire bytes"
            );
            assert_eq!(count, 1);
        }
        let (result, actual, count) = serve(bytes.clone(), bytes.len(), 1, &repository);
        assert!(matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))));
        assert_eq!(actual, expected);
        assert_eq!(count, 1);
    }
}
#[test]
fn eof_after_ls_refs_is_success_only_between_complete_commands() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format);
        let mut complete = greeting();
        complete.extend(command("ls-refs", format));
        complete.extend_from_slice(b"0000");
        let (result, _, builds) = serve(complete.clone(), complete.len(), usize::MAX, &repository);
        assert!(matches!(
            result,
            Ok(GitDaemonSessionOutcome::EmptyRepository(_))
        ));
        assert_eq!(builds, 0);
        for suffix in [b"0".to_vec(), b"001".to_vec(), b"0012command=".to_vec()] {
            let mut bytes = complete.clone();
            bytes.extend(suffix);
            let (result, output, builds) =
                serve(bytes.clone(), bytes.len(), usize::MAX, &repository);
            assert!(
                matches!(
                    result,
                    Err(GitDaemonServeError::Transport(
                        GitDaemonTransportRefusal::Wire(WireError::TruncatedPacket { .. })
                    ))
                ),
                "{result:?}"
            );
            assert_eq!(builds, 0);
            assert!(!output.windows(9).any(|s| s == b"packfile\n"));
        }
        for suffix in [frame(b"command=fetch\n"), command("fetch", format), {
            let mut s = command("fetch", format);
            s.extend(frame(
                format!("want {}\n", repository.refs[0].oid).as_bytes(),
            ));
            s
        }] {
            let mut bytes = complete.clone();
            bytes.extend(suffix);
            let (result, _, builds) = serve(bytes.clone(), bytes.len(), usize::MAX, &repository);
            assert!(
                matches!(
                    result,
                    Err(GitDaemonServeError::Transport(
                        GitDaemonTransportRefusal::IncompleteNegotiation
                    ))
                ),
                "{result:?}"
            );
            assert_eq!(builds, 0);
        }
    }
}
#[test]
fn fragmented_refused_want_never_reaches_the_pack_builder() {
    let format = GitObjectFormat::Sha1;
    let repository = repository(format);
    let mut bytes = greeting();
    bytes.extend(command("ls-refs", format));
    bytes.extend_from_slice(b"0000");
    let start = bytes.len();
    bytes.extend(command("fetch", format));
    bytes.extend(frame(format!("want {}\n", "2".repeat(40)).as_bytes()));
    bytes.extend_from_slice(b"0000");
    for split in start..bytes.len() {
        let (result, output, builds) = serve(bytes.clone(), split, usize::MAX, &repository);
        assert!(
            matches!(
                result,
                Err(GitDaemonServeError::Transport(
                    GitDaemonTransportRefusal::Wire(WireError::WantNotReachable { .. })
                ))
            ),
            "split={split}: {result:?}"
        );
        assert_eq!(builds, 0);
        assert!(!output.windows(9).any(|s| s == b"packfile\n"));
    }
}
