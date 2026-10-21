#![forbid(unsafe_code)]
//! A partial-clone filter this node does not serve is refused the way upstream
//! upload-pack refuses a disallowed filter: one `ERR filter '<name>' not
//! supported` packet in place of the negotiation output, before any pack is
//! built, so a stock client reports a remote error instead of a hang-up. The
//! served twin still builds exactly one pack (frankengit-root-doctrine-x2mv.4.33).
use fgit_node::{
    GitDaemonServeError, GitDaemonSessionOutcome, GitDaemonTransportRefusal,
    serve_git_daemon_upload_pack,
};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, PackPayloadSource,
    UploadPackRepository, WireError, WireLimits,
};
use std::convert::Infallible;

const REFUSAL: &[u8] = b"ERR filter 'sparse:oid' not supported\n";

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

fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", bytes.len() + 4).into_bytes();
    out.extend_from_slice(bytes);
    out
}
fn repository(format: GitObjectFormat) -> Repository {
    let oid = AnyGitOid::from_hex(format, &"1".repeat(format.digest_len() * 2)).unwrap();
    Repository {
        format,
        refs: vec![AdvertisedRef::new(oid, b"refs/heads/main", &WireLimits::default()).unwrap()],
    }
}
fn v2_fetch(repository: &Repository, filter: &str) -> Vec<u8> {
    let format = repository.format;
    let mut bytes = frame(b"git-upload-pack /22222222222222222222222222222222.git\0\0version=2\0");
    bytes.extend(frame(b"command=fetch\n"));
    bytes.extend(frame(
        format!("object-format={}\n", format.as_str()).as_bytes(),
    ));
    bytes.extend_from_slice(b"0001");
    bytes.extend(frame(
        format!("want {}\n", repository.refs[0].oid).as_bytes(),
    ));
    bytes.extend(frame(format!("filter {filter}\n").as_bytes()));
    bytes.extend(frame(b"done\n"));
    bytes.extend_from_slice(b"0000");
    bytes
}
fn v0_fetch(repository: &Repository, filter: &str) -> Vec<u8> {
    let mut bytes = frame(b"git-upload-pack /22222222222222222222222222222222.git\0");
    bytes.extend(frame(
        format!("want {} filter\n", repository.refs[0].oid).as_bytes(),
    ));
    bytes.extend(frame(format!("filter {filter}\n").as_bytes()));
    bytes.extend_from_slice(b"0000");
    bytes.extend(frame(b"done\n"));
    bytes
}
fn serve(
    bytes: &[u8],
    repository: &Repository,
) -> (
    Result<GitDaemonSessionOutcome, GitDaemonServeError<Infallible>>,
    Vec<u8>,
    usize,
) {
    let mut reader = bytes;
    let mut output = Vec::new();
    let mut builds = 0;
    let result = serve_git_daemon_upload_pack(
        &mut reader,
        &mut output,
        repository,
        Capabilities::parse_v1(b"agent=unserved-filter filter", &WireLimits::default()).unwrap(),
        WireLimits::default(),
        |_, _| {
            builds += 1;
            Ok::<_, Infallible>(Payload)
        },
    );
    (result, output, builds)
}
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn refused_specs(format: GitObjectFormat) -> Vec<String> {
    vec![
        // The spelling a client sends for `--filter=sparse:oid=main:.sparse`.
        "sparse:oid=main:.sparse".to_owned(),
        // A full object id of this repository's format.
        format!("sparse:oid={}", "2".repeat(format.digest_len() * 2)),
        // A refused term nested inside a compound filter.
        "combine:blob:none+sparse%3Aoid%3Dmain%3A.sparse".to_owned(),
    ]
}

#[test]
fn v2_unserved_filters_get_upstreams_err_before_any_pack_and_the_served_twin_builds_one() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format);
        for spec in refused_specs(format) {
            let (result, output, builds) = serve(&v2_fetch(&repository, &spec), &repository);
            assert!(
                matches!(
                    result,
                    Err(GitDaemonServeError::Transport(
                        GitDaemonTransportRefusal::UnservedFilter {
                            filter: "sparse:oid"
                        }
                    ))
                ),
                "{format:?} {spec}: {result:?}"
            );
            assert_eq!(builds, 0, "{spec}: refused before any pack is built");
            assert!(
                output.ends_with(&frame(REFUSAL)),
                "{spec}: ERR is the last packet"
            );
            assert!(!contains(&output, b"packfile\n"), "{spec}: no pack section");
            assert!(
                !contains(&output, b"acknowledgments"),
                "{spec}: no negotiation output"
            );
        }
        let (result, output, builds) = serve(&v2_fetch(&repository, "blob:none"), &repository);
        assert!(
            matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),
            "{format:?} served twin: {result:?}"
        );
        assert_eq!(builds, 1);
        assert!(contains(&output, b"packfile\n"));
        assert!(!contains(&output, b"ERR "));
    }
}

#[test]
fn v0_unserved_filters_get_upstreams_err_in_place_of_nak_and_the_served_twin_builds_one() {
    let repository = repository(GitObjectFormat::Sha1);
    for spec in refused_specs(GitObjectFormat::Sha1) {
        let (result, output, builds) = serve(&v0_fetch(&repository, &spec), &repository);
        assert!(
            matches!(
                result,
                Err(GitDaemonServeError::Transport(
                    GitDaemonTransportRefusal::UnservedFilter {
                        filter: "sparse:oid"
                    }
                ))
            ),
            "{spec}: {result:?}"
        );
        assert_eq!(builds, 0, "{spec}: refused before any pack is built");
        assert!(
            output.ends_with(&frame(REFUSAL)),
            "{spec}: ERR is the last packet"
        );
        assert!(!contains(&output, b"NAK"), "{spec}: no negotiation answer");
    }
    let (result, output, builds) = serve(&v0_fetch(&repository, "blob:none"), &repository);
    assert!(
        matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),
        "served twin: {result:?}"
    );
    assert_eq!(builds, 1);
    assert!(contains(&output, b"NAK"));
    assert!(!contains(&output, b"ERR "));
}
