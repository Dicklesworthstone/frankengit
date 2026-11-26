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

use std::cell::Cell;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io::{Cursor, Read};

use fgit_admission::AdmissionSnapshot;
use fgit_node::{
    AdmissionUploadPackRepository, GitDaemonServeError, GitDaemonService,
    GitDaemonTransportRefusal, parse_git_daemon_request, serve_git_daemon_upload_pack,
};
use fgit_types::RefName;
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, PackPayloadSource, PackRequest,
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

fn serve_empty(greeting: Vec<u8>, capabilities: Capabilities) -> (GitDaemonService, Vec<u8>) {
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
    (outcome.request().service(), output)
}

#[test]
fn version_one_greeting_emits_only_its_required_prelude_before_the_v0_advertisement() {
    let (v0_version, v0_advertisement) = serve_empty(greeting(&[]), capabilities());
    let (v1_version, v1_advertisement) = serve_empty(greeting(&[b"version=1"]), capabilities());

    assert_eq!(
        v0_version,
        GitDaemonService::UploadPack(UploadPackVersion::V0)
    );
    assert_eq!(
        v1_version,
        GitDaemonService::UploadPack(UploadPackVersion::V1)
    );

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

struct OneRefRepository(Vec<AdvertisedRef>);

impl OneRefRepository {
    fn new() -> Self {
        let tip = AnyGitOid::from_hex(GitObjectFormat::Sha1, &"ab".repeat(20)).unwrap();
        Self(vec![
            AdvertisedRef::new(tip, b"refs/heads/main", &WireLimits::default()).unwrap(),
        ])
    }
}

impl UploadPackRepository for OneRefRepository {
    fn object_format(&self) -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.0
    }

    fn contains_want(&self, oid: AnyGitOid) -> bool {
        self.0.iter().any(|reference| reference.oid == oid)
    }

    fn is_common(&self, _oid: AnyGitOid) -> bool {
        false
    }
}

#[test]
fn a_flush_before_any_want_ends_the_session_cleanly() {
    // `git ls-remote` over git:// sends a flush instead of wants once it has
    // the advertisement; upstream upload-pack ends the session there.
    for parameters in [&[][..], &[b"version=1".as_slice()][..]] {
        let mut wire = greeting(parameters);
        wire.extend_from_slice(b"0000");
        let mut output = Vec::new();
        let outcome = serve_git_daemon_upload_pack(
            &mut Cursor::new(wire.clone()),
            &mut output,
            &OneRefRepository::new(),
            capabilities(),
            WireLimits::default(),
            |_request, _pack_request| -> Result<EmptyPayload, Infallible> { Ok(EmptyPayload) },
        );
        assert!(outcome.is_ok(), "{parameters:?}");
        assert!(
            output
                .windows(b"refs/heads/main".len())
                .any(|window| window == b"refs/heads/main")
        );

        // Twin: a want after the terminating flush is refused, not served.
        wire.extend_from_slice(format!("0032want {}\n", "ab".repeat(20)).as_bytes());
        let outcome = serve_git_daemon_upload_pack(
            &mut Cursor::new(wire),
            &mut Vec::new(),
            &OneRefRepository::new(),
            capabilities(),
            WireLimits::default(),
            |_request, _pack_request| -> Result<EmptyPayload, Infallible> { Ok(EmptyPayload) },
        );
        assert!(outcome.is_err(), "{parameters:?}");
    }
}

struct CheckpointRepository<'a> {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
    expired: &'a Cell<bool>,
    checkpoints: Cell<usize>,
}

impl UploadPackRepository for CheckpointRepository<'_> {
    fn object_format(&self) -> GitObjectFormat {
        self.format
    }
    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }
    fn contains_want(&self, oid: AnyGitOid) -> bool {
        self.refs.iter().any(|reference| reference.oid == oid)
    }
    fn is_common(&self, _: AnyGitOid) -> bool {
        false
    }
    fn negotiation_checkpoint(&self) -> Result<(), WireError> {
        self.checkpoints.set(self.checkpoints.get() + 1);
        if self.expired.get() {
            Err(WireError::PackSourceRefused)
        } else {
            Ok(())
        }
    }
    fn supports_shallow(&self) -> bool {
        true
    }
    fn shallow_update(
        &self,
        _: &PackRequest,
    ) -> Result<fgit_wire::closure::ShallowUpdate, WireError> {
        Ok(fgit_wire::closure::ShallowUpdate {
            shallow: Vec::new(),
            unshallow: Vec::new(),
        })
    }
}

// Expire only after advertisement construction, at the first negotiation read.
// This test therefore needs the live checkpoint to survive the legacy wrapper;
// an early constructor check alone cannot make the expired twin pass.
struct ExpiryOnNegotiation<'a> {
    input: Cursor<Vec<u8>>,
    greeting_bytes: u64,
    expire_on_read: bool,
    expired: &'a Cell<bool>,
}

impl Read for ExpiryOnNegotiation<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.expire_on_read && self.input.position() >= self.greeting_bytes {
            self.expired.set(true);
        }
        self.input.read(buffer)
    }
}

struct SelectedPayload(Option<Vec<u8>>);

impl PackPayloadSource for SelectedPayload {
    fn next_chunk(&mut self, _: usize) -> Result<Option<Vec<u8>>, WireError> {
        Ok(self.0.take())
    }
}

#[test]
fn shallow_exclusion_retains_the_live_checkpoint_through_the_legacy_advertisement() {
    const SELECTED: &[u8] = b"PACK-fixture-selected-after-negotiation";
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for parameters in [&[][..], &[b"version=1".as_slice()][..]] {
            for expire_on_read in [false, true] {
                let expired = Cell::new(false);
                let tip = AnyGitOid::from_hex(format, &"ab".repeat(format.digest_len())).unwrap();
                let repository = CheckpointRepository {
                    format,
                    refs: vec![
                        AdvertisedRef::new(tip, b"refs/heads/main", &WireLimits::default())
                            .unwrap(),
                    ],
                    expired: &expired,
                    checkpoints: Cell::new(0),
                };
                let capabilities_text =
                    format!("shallow deepen-not object-format={}", format.as_str());
                let capabilities =
                    Capabilities::parse_v1(capabilities_text.as_bytes(), &WireLimits::default())
                        .unwrap();
                let mut input = greeting(parameters);
                let greeting_bytes = input.len() as u64;
                for line in [
                    format!("want {tip} {capabilities_text}\n"),
                    "deepen-not main\n".to_owned(),
                ] {
                    input.extend_from_slice(format!("{:04x}", line.len() + 4).as_bytes());
                    input.extend_from_slice(line.as_bytes());
                }
                input.extend_from_slice(b"00000009done\n");
                let mut reader = ExpiryOnNegotiation {
                    input: Cursor::new(input),
                    greeting_bytes,
                    expire_on_read,
                    expired: &expired,
                };
                let mut output = Vec::new();
                let mut built = 0;
                let outcome = serve_git_daemon_upload_pack(
                    &mut reader,
                    &mut output,
                    &repository,
                    capabilities,
                    WireLimits::default(),
                    |_, request| -> Result<SelectedPayload, Infallible> {
                        built += 1;
                        assert_eq!(request.deepen_not, vec![tip]);
                        Ok(SelectedPayload(Some(SELECTED.to_vec())))
                    },
                );
                assert!(
                    repository.checkpoints.get() > 0,
                    "the source checkpoint must be forwarded"
                );
                if expire_on_read {
                    assert!(
                        matches!(
                            &outcome,
                            Err(GitDaemonServeError::Transport(
                                GitDaemonTransportRefusal::Wire(WireError::PackSourceRefused)
                            ))
                        ),
                        "{outcome:?}"
                    );
                    assert_eq!(built, 0);
                    assert!(
                        !output
                            .windows(SELECTED.len())
                            .any(|bytes| bytes == SELECTED)
                    );
                } else {
                    assert!(outcome.is_ok(), "{outcome:?}");
                    assert_eq!(built, 1);
                    assert!(output.ends_with(SELECTED));
                }
            }
        }
    }
}

#[test]
fn native_ref_order_hint_describes_the_exact_immutable_advertisement() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let tip = AnyGitOid::from_hex(format, &"ab".repeat(format.digest_len())).unwrap();
        let branch = RefName::try_new(b"refs/heads/main").unwrap();
        for unusual in [false, true] {
            for head in [false, true] {
                let mut refs = BTreeMap::from([(branch.clone(), tip)]);
                if unusual {
                    refs.insert(RefName::try_new(b"AA/name").unwrap(), tip);
                }
                let snapshot = AdmissionSnapshot {
                    refs,
                    head_target: head.then_some(branch.clone()),
                    ..AdmissionSnapshot::default()
                };
                let repository = AdmissionUploadPackRepository::from_snapshot(
                    &snapshot,
                    format,
                    &WireLimits::default(),
                )
                .unwrap();
                let sorted = repository.sorted_advertised_refs();
                if unusual && head {
                    assert!(
                        sorted.is_none(),
                        "a synthesized HEAD must not grant a false ordering hint"
                    );
                    assert_eq!(repository.advertised_refs()[0].name, b"HEAD");
                    assert_eq!(repository.advertised_refs()[1].name, b"AA/name");
                } else {
                    assert_eq!(sorted.unwrap(), repository.advertised_refs());
                }
            }
        }
    }
}
