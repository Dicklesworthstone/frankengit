#![forbid(unsafe_code)]
//! Independent FG-066b boundary probe for the `TreeFS` object-construction cap.
//!
//! `export_budgets.rs` already covers byte, tree-width, and base-object limits.
//! It did not exercise `ExportLimits::max_objects`, so the cross-surface ceiling
//! registry could not truthfully map that configured bound to a trip/pass case.
//! This test drives only the public `TreeFS` API and keeps the two neighbors
//! identical apart from the ceiling: three candidate objects are admitted at
//! three and refused at two.

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::ParseLimits;
use fgit_treefs::{
    BaseView, ContentRef, EntryClass, ExportLimits, ExportPlanner, ExportRefusal, FileMode,
    ObjectSource, ObjectSourceError, Overlay, OverlayEntry, PathPolicy, TreeCapability, TreePath,
    WorkspaceId,
};
use fgit_types::identity::RepositoryCommitId;
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryId};
use std::collections::BTreeMap;

type Oid = GitOid<Sha1>;

#[derive(Default)]
struct MemorySource {
    objects: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl MemorySource {
    fn insert(&mut self, kind: GitObjectKind, body: Vec<u8>) -> Oid {
        let oid = Oid::of_object(kind, &body);
        self.objects.insert(oid.digest_bytes().to_vec(), body);
        oid
    }
}

impl ObjectSource<Sha1> for MemorySource {
    fn read_object(
        &self,
        oid: &Oid,
        _kind: GitObjectKind,
        _grant: &fgit_treefs::ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        self.objects
            .get(oid.digest_bytes())
            .cloned()
            .ok_or_else(|| ObjectSourceError::NotFound {
                oid_hex: String::new(),
            })
    }
}

fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).expect("fixed fixture path is valid")
}

fn fixture() -> (MemorySource, BaseView<Sha1>, TreeCapability, Overlay) {
    let mut source = MemorySource::default();
    let root = source.insert(GitObjectKind::Tree, Vec::new());
    let repository = RepositoryId::from_bytes([0x66; 16]);
    let base = BaseView::new(
        repository,
        RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("nonzero corpus fixture algorithm slot"),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[0x77; 32]).expect("32-byte corpus fixture body"),
        ),
        root,
        root,
        ParseLimits::default(),
        PathPolicy::default(),
    );
    let capability = TreeCapability::new(
        WorkspaceId::from_bytes([0x88; 16]),
        repository,
        vec![path(b"src")],
        vec![path(b"src")],
    );
    let mut overlay = Overlay::new();
    let content = overlay.intern(b"fn main() {}\n".to_vec());
    overlay.put(
        path(b"src/main.rs"),
        OverlayEntry::File {
            content: ContentRef::Overlay(content),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );
    (source, base, capability, overlay)
}

fn plan_with(limit: usize) -> Result<usize, ExportRefusal> {
    let (source, base, mut capability, overlay) = fixture();
    ExportPlanner::new(
        ExportLimits {
            max_objects: limit,
            ..ExportLimits::default()
        },
        ParseLimits::default(),
    )
    .plan(&base, &source, &mut capability, &overlay, 0, &|| false)
    .map(|plan| plan.object_count())
}

#[test]
fn object_budget_refuses_one_below_the_exact_constructed_count_and_accepts_at_it() {
    let observed = plan_with(3).expect("one blob plus src/root trees fit an object cap of three");
    assert_eq!(
        observed, 3,
        "the fixture has one blob and two rebuilt trees"
    );

    let refused = plan_with(observed - 1);
    assert_eq!(
        refused,
        Err(ExportRefusal::ObjectBudgetExceeded {
            observed,
            limit: observed - 1,
        }),
        "the identical export must name the measured object count and the one-below ceiling"
    );
}

// Non-production fixture identity: this reserved tag deliberately has no registered digest width.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);
