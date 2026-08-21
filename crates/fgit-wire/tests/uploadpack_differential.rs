#![forbid(unsafe_code)]
//! FG-018c: pinned Git upload-pack transcript bridge.
//!
//! The surrounding E2E suite creates the repository and captures every oracle
//! byte stream.  This ignored test consumes that corpus through the public
//! SANS-I/O surface, writes FrankenGit-owned counterpart transcripts, and
//! refuses to collapse the pack writer or epoch-0 import policy into a wire
//! byte-match claim.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use fgit_git_object::{AcceptanceProfile, ObjectError, ParseLimits, parse_commit};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, LegacyUploadPack, Packet,
    PktLineDecoder, UploadPackRepository, UploadPackVersion, V1Advertisement, V2UploadPack,
    WireEvent, WireLimits, encode_packets,
};

const CORPUS_ENV: &str = "FGIT_UPLOADPACK_DIFFERENTIAL_CORPUS";
const OUTPUT_ENV: &str = "FGIT_UPLOADPACK_DIFFERENTIAL_OUTPUT";

#[derive(Clone, Debug)]
struct CorpusRepository {
    refs: Vec<AdvertisedRef>,
}

impl CorpusRepository {
    fn from_advertisement(advertisement: &V1Advertisement) -> Self {
        Self {
            refs: advertisement.refs.clone(),
        }
    }
}

impl UploadPackRepository for CorpusRepository {
    fn object_format(&self) -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }

    fn contains_want(&self, oid: AnyGitOid) -> bool {
        self.refs.iter().any(|reference| reference.oid == oid)
    }

    fn is_common(&self, _oid: AnyGitOid) -> bool {
        false
    }

    fn symref_target(&self, name: &[u8]) -> Option<&[u8]> {
        (name == b"HEAD").then_some(b"refs/heads/master")
    }
}

fn required_directory(name: &str) -> PathBuf {
    PathBuf::from(env::var(name).unwrap_or_else(|_| panic!("{name} must be set by FG-018c")))
}

fn read(corpus: &Path, name: &str) -> Vec<u8> {
    fs::read(corpus.join(name)).unwrap_or_else(|error| panic!("read {name}: {error}"))
}

fn decode_packets(bytes: &[u8], label: &str) -> Vec<Packet> {
    let limits = WireLimits::default();
    let mut decoder = PktLineDecoder::new(limits).expect("default wire limits are valid");
    let packets = decoder
        .push(bytes)
        .unwrap_or_else(|error| panic!("decode {label}: {error}"));
    decoder
        .finish()
        .unwrap_or_else(|error| panic!("finish {label}: {error}"));
    packets
}

fn encode(packets: &[Packet], label: &str) -> Vec<u8> {
    encode_packets(packets, &WireLimits::default())
        .unwrap_or_else(|error| panic!("encode {label}: {error}"))
}

fn write(output: &Path, name: &str, bytes: &[u8]) {
    fs::write(output.join(name), bytes).unwrap_or_else(|error| panic!("write {name}: {error}"));
}

fn assert_pack_request(event: Option<&WireEvent>, version: UploadPackVersion) {
    assert!(matches!(event, Some(WireEvent::PackRequested(request)) if request.version == version));
}

#[test]
#[ignore = "FG-018c E2E supplies a verified pinned-Git corpus"]
fn pinned_git_uploadpack_transcripts_match_the_owned_wire_surface() {
    let corpus = required_directory(CORPUS_ENV);
    let output = required_directory(OUTPUT_ENV);
    fs::create_dir_all(&output).expect("FG-018c output directory is creatable");

    let limits = WireLimits::default();
    let v1_advertisement_bytes = read(&corpus, "v1-advertisement.pkt");
    let v1_advertisement_packets = decode_packets(&v1_advertisement_bytes, "v1 advertisement");
    let advertisement =
        V1Advertisement::parse(&v1_advertisement_packets, GitObjectFormat::Sha1, &limits)
            .expect("pinned Git v1 advertisement is accepted");
    assert!(
        advertisement
            .refs
            .iter()
            .any(|reference| reference.name == b"refs/heads/epoch0")
    );
    let fgit_v1_advertisement = encode(
        &advertisement
            .encode(&limits)
            .expect("parsed v1 advertisement re-encodes"),
        "v1 advertisement",
    );
    write(&output, "fgit-v1-advertisement.pkt", &fgit_v1_advertisement);
    assert_eq!(fgit_v1_advertisement, v1_advertisement_bytes);

    let repository = CorpusRepository::from_advertisement(&advertisement);
    let v1_request = read(&corpus, "v1-fetch-request.pkt");
    let mut v1 = LegacyUploadPack::new(
        UploadPackVersion::V0,
        advertisement.capabilities,
        limits.clone(),
    )
    .expect("v0 request machine constructs");
    let v1_transition = v1
        .push_bytes(&v1_request, &repository)
        .expect("pinned Git v1 fetch request is accepted");
    v1.finish().expect("v1 request ends on a packet boundary");
    assert!(v1.is_complete());
    assert_pack_request(v1_transition.events.last(), UploadPackVersion::V0);
    let fgit_v1_prefix = encode(&v1_transition.output, "v1 negotiation prefix");
    write(&output, "fgit-v1-negotiation-prefix.pkt", &fgit_v1_prefix);
    assert_eq!(
        fgit_v1_prefix,
        read(&corpus, "v1-negotiation-prefix.pkt"),
        "the owned pre-pack v1 response bytes agree with Git"
    );

    let v2_advertisement =
        decode_packets(&read(&corpus, "v2-advertisement.pkt"), "v2 advertisement");
    let v2_capabilities = Capabilities::parse_v2_advertisement(&v2_advertisement, &limits)
        .expect("pinned Git v2 capability transcript is accepted");

    let mut v2_ls_refs = V2UploadPack::new(v2_capabilities.clone(), limits.clone())
        .expect("v2 ls-refs machine constructs");
    let v2_ls_refs_transition = v2_ls_refs
        .push_bytes(&read(&corpus, "v2-ls-refs-request.pkt"), &repository)
        .expect("pinned Git v2 ls-refs request is accepted");
    v2_ls_refs
        .finish()
        .expect("v2 ls-refs request ends on a packet boundary");
    let fgit_v2_ls_refs = encode(&v2_ls_refs_transition.output, "v2 ls-refs response");
    write(&output, "fgit-v2-ls-refs-response.pkt", &fgit_v2_ls_refs);
    assert_eq!(
        fgit_v2_ls_refs,
        read(&corpus, "v2-ls-refs-response.pkt"),
        "the owned v2 ls-refs response bytes agree with Git"
    );

    let mut v2_fetch =
        V2UploadPack::new(v2_capabilities, limits).expect("v2 fetch machine constructs");
    let v2_fetch_transition = v2_fetch
        .push_bytes(&read(&corpus, "v2-fetch-request.pkt"), &repository)
        .expect("pinned Git v2 fetch request is accepted");
    v2_fetch
        .finish()
        .expect("v2 fetch request ends on a packet boundary");
    assert_pack_request(v2_fetch_transition.events.last(), UploadPackVersion::V2);
    let fgit_v2_prefix = encode(&v2_fetch_transition.output, "v2 fetch prefix");
    write(&output, "fgit-v2-fetch-prefix.pkt", &fgit_v2_prefix);
    assert_eq!(
        fgit_v2_prefix,
        read(&corpus, "v2-fetch-prefix.pkt"),
        "the owned pre-pack v2 response bytes agree with Git"
    );

    let epoch0_commit = read(&corpus, "epoch0-commit.body");
    assert!(
        parse_commit(
            &epoch0_commit,
            AcceptanceProfile::GitCompatibleImport,
            &ParseLimits::default()
        )
        .is_ok(),
        "the epoch-0 commit remains importable for Git compatibility"
    );
    assert_eq!(
        parse_commit(
            &epoch0_commit,
            AcceptanceProfile::StrictCreate,
            &ParseLimits::default()
        ),
        Err(ObjectError::MissingHeaderMessageSeparator),
        "StrictCreate intentionally refuses the Git-accepted epoch-0 shape"
    );

    let verdict = concat!(
        "schema=frankengit.uploadpack-differential.v1\n",
        "oracle_v1_advertisement=match\n",
        "oracle_v1_fetch_request=match\n",
        "oracle_v1_negotiation_prefix=match\n",
        "oracle_v1_pack_suffix=accepted-divergence-with-rationale:fgit-wire-emits-PackRequest;pack-payload-is-owned-by-the-pack-writer\n",
        "oracle_v2_advertisement=accepted-divergence-with-rationale:fgit-wire-consumes-the-captured-capability-transcript;v2-advertisement-emission-is-an-adapter-seam\n",
        "oracle_v2_ls_refs=match\n",
        "oracle_v2_fetch_prefix=match\n",
        "oracle_v2_pack_suffix=accepted-divergence-with-rationale:fgit-wire-emits-PackRequest;pack-payload-is-owned-by-the-pack-writer\n",
        "epoch0_strict_create=accepted-divergence-with-rationale:GitCompatibleImport-preserves-the-bounded-Git-accepted-body;StrictCreate-refuses-new-noncanonical-objects\n",
        "non_claim=the-lane-does-not-claim-a-network-server,clone-completion,or-pack-byte-equivalence\n"
    );
    write(&output, "verdict.tsv", verdict.as_bytes());
}
