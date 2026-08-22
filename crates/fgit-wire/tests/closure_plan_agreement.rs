#![forbid(unsafe_code)]

//! frankengit-ovuc: the exclude-set type guard on the closure walker.
//!
//! `deepen_not` names tips whose history must not be traversed. Those oids come
//! from the wire, so the walker must not assume they are commits: it loads each
//! one and refuses anything else. AGENTS.md §6 makes refusal behaviour a
//! compatibility semantic, and §9 treats anything arriving over the wire as
//! untrusted.
//!
//! `ExpectedCommit` had no test anywhere in the workspace.
//!
//! # Its sibling in this file's title is a truthful null
//!
//! I set out to pin `SelectedObjectCountMismatch` (closure.rs:321) as well --
//! the check that a returned `PackPlan` has exactly as many entries as the
//! closure selected. **It cannot fire through the public API, and no test here
//! pretends otherwise.**
//!
//! `PackClosure::plan_selected` takes `planner: &fgit_pack::PackPlanner`, a
//! CONCRETE type, so a misbehaving planner cannot be substituted. And the real
//! `plan_selected` (fgit-pack writer.rs:330) sorts the selected ids, refuses any
//! duplicate outright with `DuplicateSelectedObject`, and then builds exactly
//! one plan entry per surviving id. On any `Ok` return its entry count is
//! therefore exactly `selected.len()`, which is exactly what the closure
//! compares against.
//!
//! That makes the guard a CROSS-CRATE CONTRACT CHECK: fgit-wire declining to
//! trust fgit-pack's one-entry-per-id promise. It is unreachable today and
//! should be kept -- it is precisely what would catch a future fgit-pack
//! regression -- but it is recorded as uncovered rather than counted.

use fgit_wire::closure::{
    ClosureError, ClosureLimits, ClosureObject, ClosureTreeEntry, CommitNode,
    ObjectClosureRepository, compute_pack_closure,
};
use fgit_wire::{
    AnyGitOid, GitObjectFormat, ObjectType, PackOptions, PackRequest, UploadPackVersion,
};

const TIP: &str = "1111111111111111111111111111111111111111";
const ROOT_TREE: &str = "2222222222222222222222222222222222222222";
const BLOB: &str = "3333333333333333333333333333333333333333";
const OLDER: &str = "4444444444444444444444444444444444444444";

fn oid(hex: &str) -> AnyGitOid {
    AnyGitOid::from_hex(GitObjectFormat::Sha1, hex).expect("fixture OID is valid SHA-1")
}

struct Graph {
    objects: Vec<(AnyGitOid, ClosureObject)>,
}

impl ObjectClosureRepository for Graph {
    fn object_format(&self) -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    fn object(&self, object_id: AnyGitOid) -> Result<ClosureObject, ClosureError> {
        self.objects
            .iter()
            .find(|(candidate, _)| *candidate == object_id)
            .map(|(_, object)| object.clone())
            .ok_or(ClosureError::InconsistentGraph { oid: object_id })
    }
}

/// A tip commit over a one-blob tree, plus an older commit that is a legitimate
/// exclude target. Every oid the walker can reach is present, so
/// `InconsistentGraph` cannot be what fires.
fn graph() -> Graph {
    Graph {
        objects: vec![
            (
                oid(TIP),
                ClosureObject::Commit(CommitNode {
                    tree: oid(ROOT_TREE),
                    parents: vec![oid(OLDER)],
                    committer_time: 200,
                }),
            ),
            (
                oid(OLDER),
                ClosureObject::Commit(CommitNode {
                    tree: oid(ROOT_TREE),
                    parents: Vec::new(),
                    committer_time: 100,
                }),
            ),
            (
                oid(ROOT_TREE),
                ClosureObject::Tree(vec![ClosureTreeEntry {
                    oid: oid(BLOB),
                    object_type: ObjectType::Blob,
                }]),
            ),
            (oid(BLOB), ClosureObject::Blob { size: 1 }),
        ],
    }
}

fn request_excluding(deepen_not: Vec<AnyGitOid>) -> PackRequest {
    PackRequest {
        version: UploadPackVersion::V2,
        wants: vec![oid(TIP)],
        haves: Vec::new(),
        shallows: Vec::new(),
        deepen: None,
        deepen_since: None,
        deepen_not,
        filter: None,
        options: PackOptions::NONE,
    }
}

fn closure_excluding(deepen_not: Vec<AnyGitOid>) -> Result<usize, ClosureError> {
    compute_pack_closure(
        &graph(),
        &request_excluding(deepen_not),
        &ClosureLimits::default(),
    )
    .map(|closure| closure.objects.len())
}

/// An excluded tip that is a blob is refused, and the refusal names the type.
#[test]
fn an_excluded_tip_that_is_a_blob_is_refused() {
    assert_eq!(
        closure_excluding(vec![oid(BLOB)]),
        Err(ClosureError::ExpectedCommit {
            oid: oid(BLOB),
            observed: ObjectType::Blob,
        }),
    );
}

/// An excluded tip that is a tree is refused, and names ITS type.
///
/// Not redundant with the blob case. The guard is a `let ... else` on
/// `ClosureObject::Commit`, so it means "not a commit" rather than "is a blob",
/// and one non-commit type cannot show that. Two different types each reporting
/// their own `observed` is what distinguishes the two readings -- and `observed`
/// is the field a server would put in the error it returns to a client.
#[test]
fn an_excluded_tip_that_is_a_tree_is_refused() {
    assert_eq!(
        closure_excluding(vec![oid(ROOT_TREE)]),
        Err(ClosureError::ExpectedCommit {
            oid: oid(ROOT_TREE),
            observed: ObjectType::Tree,
        }),
    );
}

/// The permitted twin: an excluded tip that IS a commit is accepted.
///
/// Load-bearing rather than decorative. `deepen_not` naming a commit is the
/// ordinary case the field exists for; a guard that refused every excluded tip
/// would break every shallow deepen request while both probes above still
/// passed.
#[test]
fn an_excluded_tip_that_is_a_commit_is_accepted() {
    let objects =
        closure_excluding(vec![oid(OLDER)]).expect("excluding a commit is what deepen_not is for");

    assert!(
        objects > 0,
        "the tip's own objects are still selected when an ancestor is excluded",
    );
}
