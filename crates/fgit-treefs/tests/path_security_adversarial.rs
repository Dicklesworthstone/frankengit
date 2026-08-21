//! Independent adversarial path and capability corpus for FG-026b.
//!
//! This file is intentionally a consumer of the public `TreeFS` API only. It
//! must never repair an implementation defect in place: every negative below
//! is a path an untrusted repository, tool, or caller can actually present.
//! The paired permitted cases prevent an all-refusal implementation from being
//! counted as secure.
//!
//! The secret scanner is test evidence, not an enforcement boundary. `TreeFS`
//! currently has no brokered secret-handle type; until one exists, arbitrary
//! bytes can enter an overlay. The seeded scanner test proves the detector can
//! see such a leak and is deliberately explicit about that applicability limit.

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_treefs::base::{BaseEntry, BaseError, BaseView, ObjectSource, ObjectSourceError};
use fgit_treefs::capability::{
    CapabilityRefusal, GrantScope, ReadGrant, SymlinkPolicy, TreeCapability, WorkspaceId,
};
use fgit_treefs::export::{ExportLimits, ExportPlanner};
use fgit_treefs::intent::{IntentLog, TreeEditIntent};
use fgit_treefs::overlay::{ContentId, ContentRef, EntryClass, FileMode, Overlay, OverlayEntry};
use fgit_treefs::path::{PathPolicy, PathRefusal, TreePath};
use fgit_types::identity::RepositoryCommitId;
use fgit_types::{ByteCount, CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryId};
use std::cell::Cell;
use std::collections::BTreeMap;

type Oid = GitOid<Sha1>;

const SECRET_SENTINEL: &[u8] = b"FGIT-026B-SECRET-SENTINEL-5fae1a";

fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).expect("adversarial fixture path parses")
}

const fn repository_id() -> RepositoryId {
    RepositoryId::from_bytes([0x26; 16])
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(1).expect("algorithm 1 is registered"),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[0x19; 32]).expect("fixture digest width is legal"),
    )
}

fn limits() -> ParseLimits {
    ParseLimits::default()
}

#[derive(Default)]
struct MemorySource {
    objects: BTreeMap<Vec<u8>, Vec<u8>>,
    reads: Cell<usize>,
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
        let body = emit_tree(entries, AcceptanceProfile::GitCompatibleImport, &limits())
            .expect("fixture tree emits");
        self.insert(GitObjectKind::Tree, body)
    }

    const fn reads(&self) -> usize {
        self.reads.get()
    }
}

impl ObjectSource<Sha1> for MemorySource {
    fn read_object(
        &self,
        oid: &Oid,
        _kind: GitObjectKind,
        _grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        self.reads.set(self.reads.get().saturating_add(1));
        self.objects
            .get(oid.digest_bytes())
            .cloned()
            .ok_or_else(|| ObjectSourceError::NotFound {
                oid_hex: "fixture object absent".to_owned(),
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

/// `docs/readme.md`, `src/lib.rs`, and `src/escape` whose link text attempts
/// to leave the workspace. The link is legitimate Git data; traversing it is
/// not legitimate workspace authority.
fn fixture() -> (MemorySource, Oid) {
    let mut source = MemorySource::default();
    let readme = source.blob(b"private documentation\n");
    let lib = source.blob(b"pub fn permitted() {}\n");
    let escape = source.blob(b"../../.git/config");
    let src = source.tree(&[
        entry(b"120000", b"escape", &escape),
        entry(b"100644", b"lib.rs", &lib),
    ]);
    let docs = source.tree(&[entry(b"100644", b"readme.md", &readme)]);
    let root = source.tree(&[
        entry(b"40000", b"docs", &docs),
        entry(b"40000", b"src", &src),
    ]);
    (source, root)
}

fn view(root: Oid) -> BaseView<Sha1> {
    BaseView::new(
        repository_id(),
        rcr_id(),
        root,
        root,
        limits(),
        PathPolicy::default(),
    )
}

fn capability(read: Vec<TreePath>, write: Vec<TreePath>) -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([0x26; 16]),
        repository_id(),
        read,
        write,
    )
}

#[test]
fn symlink_escape_is_data_but_traversal_is_a_typed_refusal() {
    let (source, root) = fixture();
    let view = view(root);
    let mut cap = capability(vec![path(b"src")], vec![]);

    assert!(matches!(
        view.resolve(&source, &mut cap, &path(b"src/escape"), 0),
        Ok(BaseEntry::Symlink { .. })
    ));
    assert!(matches!(
        view.resolve(&source, &mut cap, &path(b"src/escape/config"), 0),
        Err(BaseError::SymlinkTraversal { path: escaped }) if escaped == path(b"src/escape")
    ));

    // Near-twin: a normal descendant remains readable through the same scope.
    assert!(matches!(
        view.resolve(&source, &mut cap, &path(b"src/lib.rs"), 0),
        Ok(BaseEntry::File { .. })
    ));
}

/// A `Refuse` policy must be enforced on the resolving path, not only when a
/// cooperative caller remembers to call `check_symlink` separately.
#[test]
fn refusing_symlink_policy_cannot_be_bypassed_by_base_resolution() {
    let (source, root) = fixture();
    let view = view(root);
    let mut cap = capability(vec![path(b"src")], vec![]).with_symlink_policy(SymlinkPolicy::Refuse);

    assert!(matches!(
        view.resolve(&source, &mut cap, &path(b"src/escape"), 0),
        Err(BaseError::Capability(CapabilityRefusal::SymlinkRefused { path: refused }))
            if refused == path(b"src/escape")
    ));

    // Same scope, non-symlink data: refusal policy must not overblock files.
    assert!(matches!(
        view.resolve(&source, &mut cap, &path(b"src/lib.rs"), 0),
        Ok(BaseEntry::File { .. })
    ));
}

#[test]
fn root_grant_is_not_a_path_grant_and_outside_scope_never_fetches() {
    let (source, root) = fixture();
    let view = view(root);
    let mut cap = capability(vec![path(b"docs")], vec![]);

    let root_grant = cap
        .authorize_root(0)
        .expect("one read prefix admits root traversal");
    assert_eq!(root_grant.scope(), &GrantScope::Root);
    assert!(
        root_grant.path().is_none(),
        "root is not represented by a magic path"
    );

    let before = source.reads();
    assert!(matches!(
        view.resolve(&source, &mut cap, &path(b"src/lib.rs"), 0),
        Err(BaseError::Capability(CapabilityRefusal::ReadOutsideScope { path: refused }))
            if refused == path(b"src/lib.rs")
    ));
    assert_eq!(
        source.reads(),
        before,
        "scope refusal precedes any source read"
    );

    assert!(matches!(
        view.resolve(&source, &mut cap, &path(b"docs/readme.md"), 0),
        Ok(BaseEntry::File { .. })
    ));
}

/// Root traversal is internally necessary to reach an authorised descendant,
/// but it must not turn a raw root listing into an existence oracle for sibling
/// names. A caller with only `docs` may learn `docs` exists; it may not learn
/// that `src` exists merely because the base tree is rooted above both.
#[test]
fn root_listing_filters_outside_scope_names_before_disclosure() {
    let (source, root) = fixture();
    let view = view(root);
    let mut cap = capability(vec![path(b"docs")], vec![]);

    let listing = view
        .list(&source, &mut cap, None, 0)
        .expect("the authorised root traversal itself succeeds");
    let names: Vec<Vec<u8>> = listing.into_iter().map(|(name, _)| name).collect();
    assert_eq!(
        names,
        vec![b"docs".to_vec()],
        "a root listing must filter siblings outside the TreeCapability before any caller can disclose them"
    );
}

/// A parent with ten bytes total after spending two has eight remaining across
/// its delegation tree. Issuing two children must not let them each consume the
/// same remaining eight bytes.
#[test]
fn sibling_attenuations_cannot_double_spend_the_remaining_fetch_budget() {
    let mut parent = capability(vec![path(b"src")], vec![path(b"src")]).with_fetch_budget(
        ByteCount::try_new("adversarial fetch budget", 10, u64::MAX)
            .expect("ten bytes is a legal budget"),
    );
    parent.charge_fetch(2).expect("initial parent work fits");

    let mut first = parent
        .attenuate(vec![path(b"src")], vec![path(b"src")])
        .expect("same-scope child is structurally an attenuation");
    let mut second = parent
        .attenuate(vec![path(b"src")], vec![path(b"src")])
        .expect("a second child is structurally an attenuation too");

    first
        .charge_fetch(8)
        .expect("the eight remaining bytes are usable once");
    assert!(matches!(
        second.charge_fetch(8),
        Err(CapabilityRefusal::FetchBudgetExceeded {
            consumed: 2,
            requested: 8,
            budget: 10,
        })
    ));
}

#[test]
fn opaque_and_unicode_spellings_preserve_raw_identity_without_path_rewriting() {
    let opaque =
        TreePath::parse_default(b"src/\xff\xfe").expect("Git path bytes need not be UTF-8");
    let nfc = TreePath::parse_default("src/caf\u{e9}.rs".as_bytes()).expect("NFC path parses");
    let nfd = TreePath::parse_default("src/cafe\u{301}.rs".as_bytes()).expect("NFD path parses");

    assert_eq!(opaque.as_bytes(), b"src/\xff\xfe");
    assert_ne!(
        nfc, nfd,
        "the core must not silently rewrite distinct Git names"
    );
    assert_ne!(nfc.as_bytes(), nfd.as_bytes());

    // A genuine traversal near-twin remains refused even among opaque names.
    assert!(TreePath::parse_default(b"src/\xff/../private").is_err());
}

/// Host adapters must detect an ASCII case alias without rewriting either Git
/// spelling, while path bytes that Git cannot represent receive their exact
/// parser-level refusal before a view can materialize anything from them.
#[test]
fn case_aliases_and_unrepresentable_bytes_are_detected_before_materialization() {
    let mixed_case = path(b"docs/Readme.md");
    let folded_case = path(b"docs/readme.md");
    assert!(mixed_case.case_aliases(&folded_case));
    assert_ne!(
        mixed_case, folded_case,
        "alias detection must not rewrite Git names"
    );

    assert!(matches!(
        TreePath::parse_default(b"docs/nul\0name"),
        Err(PathRefusal::NulByte { .. })
    ));
    assert!(matches!(
        TreePath::parse_default(b"docs/control\x1fname"),
        Err(PathRefusal::ControlByte { byte: 0x1f, .. })
    ));

    // Near-twin: opaque but representable Git bytes remain raw path identity.
    let opaque = TreePath::parse_default(b"docs/\xffname").expect("opaque Git bytes parse");
    assert_eq!(opaque.as_bytes(), b"docs/\xffname");
}

fn overlay_contains(overlay: &Overlay, needle: &[u8]) -> bool {
    overlay
        .entries()
        .values()
        .filter_map(|entry| overlay.body(entry))
        .any(|body| body.windows(needle.len()).any(|window| window == needle))
}

fn net_effect_contains(effect: &fgit_treefs::intent::TreeNetEffect, needle: &[u8]) -> bool {
    let secret_id = ContentId::of(needle);
    effect
        .effects()
        .values()
        .any(|entry| entry.content_id() == Some(secret_id))
}

fn plan_contains(plan: &fgit_treefs::export::ExportPlan<Sha1>, needle: &[u8]) -> bool {
    plan.objects().any(|object| {
        object
            .body()
            .windows(needle.len())
            .any(|window| window == needle)
    })
}

/// Detector self-test: a planted secret reaches every current in-memory layer
/// and the test-only detector catches it. This is negative evidence for the
/// absent secret-handle broker, not a claim that raw `TreeFS` content is secret
/// safe today.
#[test]
fn seeded_secret_detector_catches_overlay_effect_and_export_leaks() {
    let mut log = IntentLog::new();
    log.push(TreeEditIntent::Write {
        path: path(b"docs/generated.txt"),
        content: SECRET_SENTINEL.to_vec(),
        mode: FileMode::Regular,
        entry_class: EntryClass::Content,
    });
    let (overlay, _) = log.evaluate(&|_| false);
    let (effect, _) = log.fold(&|_| false);
    assert!(overlay_contains(&overlay, SECRET_SENTINEL));
    assert!(net_effect_contains(&effect, SECRET_SENTINEL));

    let (source, root) = fixture();
    let view = view(root);
    let mut cap = capability(vec![path(b"docs")], vec![path(b"docs")]);
    let plan = ExportPlanner::new(ExportLimits::default(), limits())
        .plan(&view, &source, &mut cap, &overlay, 0, &|| false)
        .expect("current raw-content export accepts the planted sentinel");
    assert!(plan_contains(&plan, SECRET_SENTINEL));

    let mut clean = Overlay::new();
    let clean_id = clean.intern(b"ordinary content\n".to_vec());
    clean.put(
        path(b"docs/ordinary.txt"),
        OverlayEntry::File {
            content: ContentRef::Overlay(clean_id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );
    assert!(
        !overlay_contains(&clean, SECRET_SENTINEL),
        "the detector does not report a sentinel where none was planted"
    );
}
