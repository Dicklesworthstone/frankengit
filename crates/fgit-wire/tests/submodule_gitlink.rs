#![forbid(unsafe_code)]
//! Gitlink closure and non-delegation coverage for FG-085.
//!
//! A mode-160000 entry is native tree data, not a request to inspect another
//! repository. These tests keep an otherwise reachable private commit in the
//! supplied graph so a regression would be observable as a parent-repository
//! lookup rather than being hidden by a missing-object error.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::env;

use fgit_git_object::{AcceptanceProfile, ParseLimits, parse_tree};
use fgit_wire::closure::{
    ClosureError, ClosureLimits, ClosureObject, ClosureObjectId, ClosureTreeEntry, CommitNode,
    ObjectClosureRepository, compute_authenticated_lazy_fetch_closure, compute_pack_closure,
};
use fgit_wire::{
    AnyGitOid, GitObjectFormat, ObjectType, PackOptions, PackRequest, UploadPackVersion,
};

const ORACLE_TREE_BODY_HEX_ENV: &str = "FGIT_SUBMODULE_GITLINK_TREE_BODY_HEX";
const ORACLE_TREE_OID_ENV: &str = "FGIT_SUBMODULE_GITLINK_TREE_OID";
const ORACLE_GITLINK_OID_ENV: &str = "FGIT_SUBMODULE_GITLINK_OID";

const TIP: &str = "1111111111111111111111111111111111111111";
const PRIVATE_TREE: &str = "4444444444444444444444444444444444444444";

fn oid(hex: &str) -> AnyGitOid {
    AnyGitOid::from_hex(GitObjectFormat::Sha1, hex).expect("SHA-1 fixture identity")
}

#[derive(Debug)]
struct RecordingGraph {
    objects: BTreeMap<AnyGitOid, ClosureObject>,
    reads: RefCell<Vec<AnyGitOid>>,
}

impl RecordingGraph {
    fn with_gitlink(root: AnyGitOid, gitlink: AnyGitOid) -> Self {
        let tip = oid(TIP);
        let private_tree = oid(PRIVATE_TREE);
        Self {
            objects: BTreeMap::from([
                (
                    tip,
                    ClosureObject::Commit(CommitNode {
                        tree: root,
                        parents: Vec::new(),
                        committer_time: 1,
                    }),
                ),
                (
                    root,
                    ClosureObject::Tree(vec![ClosureTreeEntry {
                        oid: gitlink,
                        object_type: ObjectType::Commit,
                    }]),
                ),
                // This object is deliberately reachable only through the
                // gitlink. A parent-repository walker that follows the link
                // would read it and then its tree.
                (
                    gitlink,
                    ClosureObject::Commit(CommitNode {
                        tree: private_tree,
                        parents: Vec::new(),
                        committer_time: 2,
                    }),
                ),
                (private_tree, ClosureObject::Tree(Vec::new())),
            ]),
            reads: RefCell::new(Vec::new()),
        }
    }
}

impl ObjectClosureRepository for RecordingGraph {
    fn object_format(&self) -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    fn object(&self, oid: AnyGitOid) -> Result<ClosureObject, ClosureError> {
        self.reads.borrow_mut().push(oid);
        self.objects
            .get(&oid)
            .cloned()
            .ok_or(ClosureError::InconsistentGraph { oid })
    }
}

fn request() -> PackRequest {
    PackRequest {
        version: UploadPackVersion::V2,
        wants: vec![oid(TIP)],
        haves: Vec::new(),
        shallows: Vec::new(),
        deepen: None,
        deepen_since: None,
        deepen_not: Vec::new(),
        filter: None,
        options: PackOptions::NONE,
    }
}

fn assert_gitlink_boundary(root: AnyGitOid, gitlink: AnyGitOid) {
    let graph = RecordingGraph::with_gitlink(root, gitlink);
    let closure = compute_pack_closure(&graph, &request(), &ClosureLimits::default())
        .expect("a superproject closure is computable without its submodule repository");

    assert!(closure.objects.contains(&ClosureObjectId {
        oid: oid(TIP),
        object_type: ObjectType::Commit,
    }));
    assert!(closure.objects.contains(&ClosureObjectId {
        oid: root,
        object_type: ObjectType::Tree,
    }));
    assert!(
        !closure.objects.iter().any(|object| object.oid == gitlink),
        "the gitlink OID belongs only to the tree payload, never the parent pack closure"
    );
    assert!(closure.promisor.omissions.is_empty());
    assert_eq!(
        *graph.reads.borrow(),
        vec![oid(TIP), root],
        "the parent repository may read its commit and tree, but not the gitlink target"
    );

    let refusal = compute_authenticated_lazy_fetch_closure(
        &graph,
        &closure,
        &[gitlink],
        &ClosureLimits::default(),
    )
    .expect_err("a gitlink is not a promised object and cannot trigger recursive completion");
    assert_eq!(
        refusal,
        ClosureError::UnexpectedLazyFetchWant { oid: gitlink }
    );
    assert_eq!(
        *graph.reads.borrow(),
        vec![oid(TIP), root],
        "the recursive-fetch probe is refused before the parent repository reads the gitlink"
    );
}

#[test]
fn gitlink_never_enters_parent_closure_or_is_looked_up() {
    assert_gitlink_boundary(
        oid("2222222222222222222222222222222222222222"),
        oid("3333333333333333333333333333333333333333"),
    );
}

/// Parses the exact tree bytes emitted by pinned Git before exercising the
/// pure-Rust closure boundary. The E2E suite supplies the three environment
/// values, making this a differential bridge rather than a hand-written golden.
#[test]
#[ignore = "requires the pinned-Git FG-085 E2E corpus"]
fn pinned_git_gitlink_tree_preserves_oid_without_cross_repository_lookup() {
    let body_hex = env::var(ORACLE_TREE_BODY_HEX_ENV)
        .unwrap_or_else(|_| panic!("{ORACLE_TREE_BODY_HEX_ENV} must name the pinned-Git tree"));
    let root = oid(&env::var(ORACLE_TREE_OID_ENV)
        .unwrap_or_else(|_| panic!("{ORACLE_TREE_OID_ENV} must name the pinned-Git tree OID")));
    let gitlink_hex = env::var(ORACLE_GITLINK_OID_ENV)
        .unwrap_or_else(|_| panic!("{ORACLE_GITLINK_OID_ENV} must name the gitlink OID"));
    let gitlink = oid(&gitlink_hex);
    let tree = parse_tree(
        &decode_hex(&body_hex),
        AcceptanceProfile::GitCompatibleImport,
        &ParseLimits::default(),
    )
    .expect("pinned Git tree bytes parse under the import profile");

    let gitlinks: Vec<_> = tree
        .iter()
        .filter(|entry| entry.mode == b"160000")
        .collect();
    assert_eq!(
        gitlinks.len(),
        1,
        "the oracle fixture has exactly one gitlink alongside its ordinary parent files"
    );
    assert_eq!(gitlinks[0].name, b"vendor");
    assert_eq!(hex(&gitlinks[0].object_id), gitlink_hex);
    assert_gitlink_boundary(root, gitlink);
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert!(
        input.len().is_multiple_of(2),
        "hex input must have an even width"
    );
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex is ASCII");
            u8::from_str_radix(text, 16).expect("hex digit pair")
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").expect("writing to a string cannot fail");
    }
    text
}
