//! USTAR materialization behaviour for FG-052.
//!
//! These tests use a real `BaseView` plus its object-source boundary.  The
//! archive renderer never sees fixture paths directly: tree discovery and blob
//! reads travel through the same capability and identity verification surface a
//! production source uses.

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_treefs::archive::{ArchiveProfile, ArchiveRefusal, TarLimits, UstarArchive};
use fgit_treefs::base::{BaseView, ObjectSource, ObjectSourceError};
use fgit_treefs::capability::{ReadGrant, SymlinkPolicy, TreeCapability, WorkspaceId};
use fgit_treefs::path::{PathPolicy, TreePath};
use fgit_types::identity::RepositoryCommitId;
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryId};
use std::collections::BTreeMap;

type Oid = GitOid<Sha1>;

const TAR_BLOCK_BYTES: usize = 512;
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0x8042;

#[derive(Clone, Default)]
struct MemorySource {
    objects: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl MemorySource {
    fn insert(&mut self, kind: GitObjectKind, body: &[u8]) -> Oid {
        let oid = Oid::of_object(kind, body);
        self.objects
            .insert(oid.digest_bytes().to_vec(), body.to_vec());
        oid
    }

    fn blob(&mut self, body: &[u8]) -> Oid {
        self.insert(GitObjectKind::Blob, body)
    }

    fn tree(&mut self, entries: &[TreeEntry]) -> Oid {
        let body = emit_tree(
            entries,
            AcceptanceProfile::GitCompatibleImport,
            &ParseLimits::default(),
        )
        .expect("the fixture trees are valid Git trees");
        self.insert(GitObjectKind::Tree, &body)
    }
}

impl ObjectSource<Sha1> for MemorySource {
    fn read_object(
        &self,
        oid: &Oid,
        _kind: GitObjectKind,
        _grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        self.objects
            .get(oid.digest_bytes())
            .cloned()
            .ok_or_else(|| ObjectSourceError::NotFound {
                oid_hex: "fixture object missing".to_owned(),
            })
    }
}

fn entry(mode: &[u8], name: &[u8], oid: &Oid) -> TreeEntry {
    TreeEntry {
        mode: mode.to_vec(),
        name: name.to_vec(),
        object_id: oid.digest_bytes().to_vec(),
    }
}

/// `docs/readme.md`, executable `src/tool`, a data-only symlink, and a
/// submodule.  The normal archive capability deliberately excludes `vendor`;
/// the submodule case proves that widening it is refused instead of fabricated.
fn fixture() -> (MemorySource, Oid) {
    let mut source = MemorySource::default();
    let readme = source.blob(b"# readme\n");
    let tool = source.blob(b"#!/bin/sh\necho archive\n");
    let link = source.blob(b"../../outside-the-workspace");
    let submodule = source.blob(b"submodule-commit-stand-in");

    let docs = source.tree(&[entry(b"100644", b"readme.md", &readme)]);
    let src = source.tree(&[
        entry(b"120000", b"link", &link),
        entry(b"100755", b"tool", &tool),
    ]);
    let root = source.tree(&[
        entry(b"40000", b"docs", &docs),
        entry(b"40000", b"src", &src),
        entry(b"160000", b"vendor", &submodule),
    ]);
    (source, root)
}

const fn repository_id() -> RepositoryId {
    RepositoryId::from_bytes([0x52; 16])
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("fixture code point is nonzero"),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[0x42; 32]).expect("fixture digest is long enough"),
    )
}

fn base(root: Oid) -> BaseView<Sha1> {
    BaseView::new(
        repository_id(),
        rcr_id(),
        root,
        root,
        ParseLimits::default(),
        PathPolicy::default(),
    )
}

fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).expect("fixture path is valid")
}

fn capability(prefixes: &[&[u8]]) -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([0x19; 16]),
        repository_id(),
        prefixes.iter().map(|prefix| path(prefix)).collect(),
        Vec::new(),
    )
    .with_symlink_policy(SymlinkPolicy::DataOnly)
}

#[derive(Debug, Eq, PartialEq)]
struct TarMember {
    name: Vec<u8>,
    typeflag: u8,
    mode: u64,
    link_name: Vec<u8>,
    body: Vec<u8>,
}

fn c_string(field: &[u8]) -> Vec<u8> {
    field[..field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len())]
        .to_vec()
}

fn octal(field: &[u8]) -> u64 {
    field
        .iter()
        .take_while(|byte| **byte != 0 && **byte != b' ')
        .filter(|byte| **byte != b' ')
        .fold(0_u64, |value, byte| value * 8 + u64::from(*byte - b'0'))
}

fn checksum(header: &[u8]) -> u64 {
    header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum()
}

fn members(bytes: &[u8]) -> Vec<TarMember> {
    assert!(bytes.len() >= TAR_BLOCK_BYTES * 2);
    assert_eq!(
        &bytes[bytes.len() - TAR_BLOCK_BYTES * 2..],
        vec![0; TAR_BLOCK_BYTES * 2].as_slice(),
        "USTAR output ends with exactly the mandatory two zero records"
    );

    let mut cursor = 0_usize;
    let mut out = Vec::new();
    while bytes[cursor..cursor + TAR_BLOCK_BYTES]
        .iter()
        .any(|byte| *byte != 0)
    {
        let header = &bytes[cursor..cursor + TAR_BLOCK_BYTES];
        assert_eq!(&header[257..263], b"ustar\0");
        assert_eq!(&header[263..265], b"00");
        assert_eq!(
            octal(&header[148..156]),
            checksum(header),
            "every rendered header carries its own correct checksum"
        );

        let mut name = c_string(&header[..100]);
        let prefix = c_string(&header[345..500]);
        if !prefix.is_empty() {
            let mut whole = prefix;
            whole.push(b'/');
            whole.append(&mut name);
            name = whole;
        }
        let size = usize::try_from(octal(&header[124..136])).expect("fixture size fits usize");
        let body_start = cursor + TAR_BLOCK_BYTES;
        let body_end = body_start + size;
        out.push(TarMember {
            name,
            typeflag: header[156],
            mode: octal(&header[100..108]),
            link_name: c_string(&header[157..257]),
            body: bytes[body_start..body_end].to_vec(),
        });
        cursor = body_end.div_ceil(TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES;
    }
    out
}

#[test]
fn capability_scoped_ustar_is_byte_stable_and_never_follows_symlinks() {
    let (source, root) = fixture();
    let view = base(root);

    let mut first_capability = capability(&[b"docs", b"src"]);
    let first = UstarArchive::render(
        &view,
        &source,
        &mut first_capability,
        17,
        TarLimits::default(),
    )
    .expect("authorized regular files and a data-only symlink archive");
    let mut second_capability = capability(&[b"docs", b"src"]);
    let second = UstarArchive::render(
        &view,
        &source,
        &mut second_capability,
        17,
        TarLimits::default(),
    )
    .expect("the same authenticated base renders again");

    assert_eq!(
        first.bytes(),
        second.bytes(),
        "the same base, capability, and deterministic profile produce identical USTAR bytes"
    );
    assert_eq!(first.receipt().repository_id(), repository_id());
    assert_eq!(first.receipt().source_rcr_id(), rcr_id());
    assert_eq!(first.receipt().source_tree_oid(), &root);
    assert_eq!(first.receipt().profile(), ArchiveProfile::UstarV1);
    assert_eq!(first.receipt().entry_count(), 5);
    assert_eq!(
        first
            .receipt()
            .entry_paths()
            .iter()
            .map(TreePath::as_bytes)
            .collect::<Vec<_>>(),
        vec![
            b"docs".as_slice(),
            b"docs/readme.md".as_slice(),
            b"src".as_slice(),
            b"src/link".as_slice(),
            b"src/tool".as_slice(),
        ],
        "the receipt binds the archive's exact capability-visible member set"
    );
    assert_eq!(first.receipt().stream_bytes(), first.bytes().len());

    let rendered = members(first.bytes());
    assert_eq!(
        rendered
            .iter()
            .map(|member| &member.name)
            .collect::<Vec<_>>(),
        vec![
            &b"docs".to_vec(),
            &b"docs/readme.md".to_vec(),
            &b"src".to_vec(),
            &b"src/link".to_vec(),
            &b"src/tool".to_vec(),
        ],
        "BTreeMap path order is the stable archive order and hidden vendor is absent"
    );
    assert_eq!(rendered[0].typeflag, b'5');
    assert_eq!(rendered[1].body, b"# readme\n");
    assert_eq!(rendered[3].typeflag, b'2');
    assert_eq!(rendered[3].link_name, b"../../outside-the-workspace");
    assert!(
        rendered[3].body.is_empty(),
        "a symlink is emitted as data and is never followed into a host path"
    );
    assert_eq!(rendered[4].typeflag, b'0');
    assert_eq!(rendered[4].mode, 0o755);
    assert_eq!(rendered[4].body, b"#!/bin/sh\necho archive\n");
}

#[test]
fn submodules_are_refused_while_the_near_identical_scoped_archive_succeeds() {
    let (source, root) = fixture();
    let view = base(root);
    let mut without_submodule = capability(&[b"docs", b"src"]);
    UstarArchive::render(
        &view,
        &source,
        &mut without_submodule,
        0,
        TarLimits::default(),
    )
    .expect("a capability that cannot disclose vendor produces the permitted archive");

    let mut with_submodule = capability(&[b"docs", b"src", b"vendor"]);
    assert_eq!(
        UstarArchive::render(&view, &source, &mut with_submodule, 0, TarLimits::default(),),
        Err(ArchiveRefusal::SubmoduleUnsupported {
            path: path(b"vendor"),
        }),
        "the USTAR profile refuses a submodule instead of substituting a fake directory or blob"
    );
}

#[test]
fn bounds_refuse_before_retaining_a_partial_archive_and_the_permitted_twin_renders() {
    let (source, root) = fixture();
    let view = base(root);
    let mut limited_capability = capability(&[b"docs", b"src"]);
    let too_few_entries = TarLimits {
        max_entries: 4,
        ..TarLimits::default()
    };
    assert_eq!(
        UstarArchive::render(&view, &source, &mut limited_capability, 0, too_few_entries),
        Err(ArchiveRefusal::EntryLimitExceeded {
            observed: 5,
            limit: 4,
        }),
        "the fifth discovered member is refused before a USTAR stream is returned"
    );

    let mut permitted_capability = capability(&[b"docs", b"src"]);
    let archive = UstarArchive::render(
        &view,
        &source,
        &mut permitted_capability,
        0,
        TarLimits::default(),
    )
    .expect("the near-identical bound that admits all five entries renders");
    assert_eq!(archive.receipt().entry_count(), 5);
}

#[test]
fn nonportable_ustar_names_are_refused_while_the_100_byte_twin_renders() {
    let mut source = MemorySource::default();
    let body = source.blob(b"archive body");
    let name = vec![b'x'; 101];
    let root = source.tree(&[entry(b"100644", &name, &body)]);
    let view = base(root);
    let mut too_long_capability = capability(&[&name]);
    assert_eq!(
        UstarArchive::render(
            &view,
            &source,
            &mut too_long_capability,
            0,
            TarLimits::default(),
        ),
        Err(ArchiveRefusal::PathTooLong {
            path: path(&name),
            observed: 101,
            limit: 256,
        }),
        "the portable profile refuses a name requiring a non-USTAR extension"
    );

    let permitted_name = vec![b'x'; 100];
    let mut permitted_source = MemorySource::default();
    let permitted_body = permitted_source.blob(b"archive body");
    let permitted_root =
        permitted_source.tree(&[entry(b"100644", &permitted_name, &permitted_body)]);
    let permitted_view = base(permitted_root);
    let mut permitted_capability = capability(&[&permitted_name]);
    let archive = UstarArchive::render(
        &permitted_view,
        &permitted_source,
        &mut permitted_capability,
        0,
        TarLimits::default(),
    )
    .expect("the exact USTAR name-field limit is a permitted materialization");
    assert_eq!(members(archive.bytes())[0].name, permitted_name);
}

#[test]
fn wrong_blob_bytes_are_refused_by_the_base_identity_check() {
    let (mut source, root) = fixture();
    let tool_body = b"#!/bin/sh\necho archive\n";
    let tool_oid = Oid::of_object(GitObjectKind::Blob, tool_body);
    source.objects.insert(
        tool_oid.digest_bytes().to_vec(),
        b"corrupted body\n".to_vec(),
    );
    let view = base(root);
    let mut cap = capability(&[b"docs", b"src"]);

    assert!(matches!(
        UstarArchive::render(&view, &source, &mut cap, 0, TarLimits::default()),
        Err(ArchiveRefusal::Source(
            ObjectSourceError::IdentityMismatch { .. }
        ))
    ));
}
