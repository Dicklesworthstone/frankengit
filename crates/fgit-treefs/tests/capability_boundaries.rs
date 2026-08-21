//! Authority-boundary refusals that had no test (FG-026d).
//!
//! Found by auditing every refusal enum in the crate for variants that are
//! declared but never constructed, and for variants no test ever names. The
//! audit is worth stating because it found real defects twice: `PathTypeConflict`
//! in the exporter, and `RepositoryMismatch` here.
//!
//! A refusal variant that is never constructed is a promise the type makes that
//! the code cannot keep. A refusal that is never tested is a promise with no
//! evidence behind it. Both read as safety in a review and neither is.
//!
//! Every refusal below is paired with a near-identical PERMITTED case (§16.3).

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_treefs::base::{BaseError, BaseView, ObjectSource, ObjectSourceError};
use fgit_treefs::capability::{CapabilityRefusal, ReadGrant, TreeCapability, WorkspaceId};
use fgit_treefs::path::{PathPolicy, TreePath};
use fgit_types::identity::RepositoryCommitId;
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryId};
use std::collections::BTreeMap;

type Oid = GitOid<Sha1>;

const REPO_A: RepositoryId = RepositoryId::from_bytes([7; 16]);
const REPO_B: RepositoryId = RepositoryId::from_bytes([9; 16]);

#[derive(Default, Clone)]
struct MemorySource {
    objects: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl MemorySource {
    fn insert(&mut self, kind: GitObjectKind, body: Vec<u8>) -> Oid {
        let oid = Oid::of_object(kind, &body);
        self.objects.insert(oid.digest_bytes().to_vec(), body);
        oid
    }

    fn blob(&mut self, body: &[u8]) -> Oid {
        self.insert(GitObjectKind::Blob, body.to_vec())
    }

    fn tree(&mut self, entries: &[TreeEntry]) -> Oid {
        let body = emit_tree(
            entries,
            AcceptanceProfile::GitCompatibleImport,
            &ParseLimits::default(),
        )
        .expect("fixture tree emits");
        self.insert(GitObjectKind::Tree, body)
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
                oid_hex: String::new(),
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

fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).expect("fixture path parses")
}

fn fixture() -> (MemorySource, Oid) {
    let mut source = MemorySource::default();
    let lib = source.blob(b"fn main() {}\n");
    let src_tree = source.tree(&[entry(b"100644", b"lib.rs", &lib)]);
    let root = source.tree(&[entry(b"40000", b"src", &src_tree)]);
    (source, root)
}

fn view_for(repository: RepositoryId, root: Oid) -> BaseView<Sha1> {
    BaseView::new(
        repository,
        RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(1).expect("algorithm 1 is registered"),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[9_u8; 32]).expect("fixture digest is a legal width"),
        ),
        root,
        root,
        ParseLimits::default(),
        PathPolicy::default(),
    )
}

fn capability_for(repository: RepositoryId) -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        repository,
        vec![path(b"src"), path(b"src/lib.rs")],
        vec![path(b"src"), path(b"src/lib.rs")],
    )
}

// ---------------------------------------------------------------------------
// cross-repository confusion
// ---------------------------------------------------------------------------

/// A capability minted for one repository must not authorise another.
///
/// `TreeCapability` carries a `RepositoryId`, `BaseView` carries a
/// `RepositoryId`, and `CapabilityRefusal::RepositoryMismatch` exists with the
/// Display text "capability is for another repository". Nothing compared them,
/// so the variant was declared and never raised and the binding was decorative:
/// a capability for repository A authorised every read against repository B.
#[test]
fn a_capability_for_another_repository_cannot_read_this_one() {
    let (source, root) = fixture();
    let view = view_for(REPO_A, root);
    let mut foreign = capability_for(REPO_B);

    let outcome = view.resolve(&source, &mut foreign, &path(b"src/lib.rs"), 0);
    assert!(
        matches!(
            outcome,
            Err(BaseError::Capability(CapabilityRefusal::RepositoryMismatch))
        ),
        "a capability for another repository must be refused; got {outcome:?}"
    );

    // The permitted twin: the same path, the same scope, the right repository.
    let mut native = capability_for(REPO_A);
    let allowed = view.resolve(&source, &mut native, &path(b"src/lib.rs"), 0);
    assert!(
        allowed.is_ok(),
        "the identical capability bound to this repository must proceed; got {allowed:?}"
    );
}

/// The root listing is refused too, and that arm needed its own check.
///
/// `list(Some(path))` delegates to `resolve`, which checks for itself, but
/// `list(None)` does not — and the root listing is exactly where an unchecked
/// capability would be most useful to an attacker, because it enumerates
/// top-level names.
#[test]
fn a_foreign_capability_cannot_list_the_root() {
    let (source, root) = fixture();
    let view = view_for(REPO_A, root);
    let mut foreign = capability_for(REPO_B);

    let outcome = view.list(&source, &mut foreign, None, 0);
    assert!(
        matches!(
            outcome,
            Err(BaseError::Capability(CapabilityRefusal::RepositoryMismatch))
        ),
        "a foreign capability must not enumerate root names; got {:?}",
        outcome.map(|listing| listing.len())
    );

    let mut native = capability_for(REPO_A);
    let allowed = view.list(&source, &mut native, None, 0);
    assert!(
        allowed.is_ok(),
        "the identical capability bound to this repository lists normally; got {allowed:?}"
    );
}

/// The repository check precedes the scope check.
///
/// Otherwise the ORDER of refusals leaks which repository a path lives in: a
/// foreign capability probing an out-of-scope path would learn "wrong scope"
/// rather than "wrong repository", and the difference is information.
#[test]
fn the_repository_check_precedes_the_scope_check() {
    let (source, root) = fixture();
    let view = view_for(REPO_A, root);

    // `docs` is outside this capability's scope AND the capability is foreign.
    // The repository refusal must win.
    let mut foreign = capability_for(REPO_B);
    let outcome = view.resolve(&source, &mut foreign, &path(b"docs"), 0);
    assert!(
        matches!(
            outcome,
            Err(BaseError::Capability(CapabilityRefusal::RepositoryMismatch))
        ),
        "the repository mismatch must be reported ahead of the scope refusal, or the \
         refusal kind tells a prober which repository the path belongs to; got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// write scope
// ---------------------------------------------------------------------------

/// A readable path is not automatically writable.
///
/// `authorize_write` checks read scope first and write scope second, so a
/// capability that can read a path but not write it must be refused with
/// `WriteOutsideScope` rather than `ReadOutsideScope` — the two are different
/// facts and a caller acts on them differently.
#[test]
fn a_readable_path_outside_write_scope_is_refused_as_a_write() {
    let read_only = TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        REPO_A,
        vec![path(b"src"), path(b"docs")],
        vec![path(b"src")],
    );

    let refused = read_only.authorize_write(&path(b"docs/readme.md"), 0);
    assert!(
        matches!(
            refused,
            Err(CapabilityRefusal::WriteOutsideScope { path: ref refused_path })
                if *refused_path == path(b"docs/readme.md")
        ),
        "a readable-but-not-writable path is a WRITE refusal naming that path; got {refused:?}"
    );

    // Permitted twin: inside write scope, the identical call proceeds.
    let allowed = read_only.authorize_write(&path(b"src/lib.rs"), 0);
    assert!(
        allowed.is_ok(),
        "the same capability writes inside its write scope; got {allowed:?}"
    );

    // And the near-twin refusal: outside BOTH scopes is a READ refusal, because
    // write-without-read would let a caller replace bytes it may not observe.
    let neither = read_only.authorize_write(&path(b"vendor/thing"), 0);
    assert!(
        matches!(neither, Err(CapabilityRefusal::ReadOutsideScope { .. })),
        "outside read scope entirely must refuse as a READ, not a write; got {neither:?}"
    );
}
