#![forbid(unsafe_code)]

//! FG-018b fixture corpus for shallow and partial-clone closure semantics.
//!
//! The reference walker below deliberately uses a different representation
//! from the production closure walker: insertion-order vectors and explicit
//! duplicate checks rather than the production B-tree traversal.  Each case
//! also pins a Git-visible boundary or omission, so reference agreement alone
//! cannot turn an accidental shared implementation mistake into a pass.

use fgit_wire::closure::{
    ClosureError, ClosureLimits, ClosureObject, ClosureObjectId, ClosureTreeEntry, CommitNode,
    ObjectClosureRepository, OmissionReason, PackClosure, PromisorOmission, ShallowUpdate,
    compute_authenticated_lazy_fetch_closure, compute_pack_closure,
};
use fgit_wire::{
    AnyGitOid, GitObjectFormat, ObjectFilter, ObjectType, PackOptions, PackRequest,
    UploadPackVersion,
};

const TIP: &str = "1111111111111111111111111111111111111111";
const LEFT_MERGE: &str = "2222222222222222222222222222222222222222";
const RIGHT_MERGE: &str = "3333333333333333333333333333333333333333";
const LEFT_BASE: &str = "4444444444444444444444444444444444444444";
const RIGHT_BASE: &str = "5555555555555555555555555555555555555555";
const OCTOPUS_THIRD: &str = "6666666666666666666666666666666666666666";
const HISTORY_TREE: &str = "7777777777777777777777777777777777777777";
const FILTER_TIP: &str = "8888888888888888888888888888888888888888";
const FILTER_TREE: &str = "9999999999999999999999999999999999999999";
const FILTER_CHILD_TREE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SMALL_BLOB: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const LARGE_BLOB: &str = "cccccccccccccccccccccccccccccccccccccccc";
const DEEP_BLOB: &str = "dddddddddddddddddddddddddddddddddddddddd";

fn oid(hex: &str) -> AnyGitOid {
    AnyGitOid::from_hex(GitObjectFormat::Sha1, hex).expect("fixture OID is valid SHA-1")
}

#[derive(Clone, Debug)]
struct CorpusGraph {
    objects: Vec<(AnyGitOid, ClosureObject)>,
}

impl CorpusGraph {
    fn history_linear() -> Self {
        let tree = oid(HISTORY_TREE);
        Self {
            objects: vec![
                (
                    oid(TIP),
                    ClosureObject::Commit(CommitNode {
                        tree,
                        parents: vec![oid(LEFT_MERGE)],
                        committer_time: 100,
                    }),
                ),
                (
                    oid(LEFT_MERGE),
                    ClosureObject::Commit(CommitNode {
                        tree,
                        parents: vec![oid(LEFT_BASE)],
                        committer_time: 90,
                    }),
                ),
                (
                    oid(LEFT_BASE),
                    ClosureObject::Commit(CommitNode {
                        tree,
                        parents: Vec::new(),
                        committer_time: 80,
                    }),
                ),
                (tree, ClosureObject::Tree(Vec::new())),
            ],
        }
    }

    fn history_criss_cross() -> Self {
        let tree = oid(HISTORY_TREE);
        Self {
            objects: vec![
                (
                    oid(TIP),
                    ClosureObject::Commit(CommitNode {
                        tree,
                        parents: vec![oid(LEFT_MERGE), oid(RIGHT_MERGE)],
                        committer_time: 100,
                    }),
                ),
                (
                    oid(LEFT_MERGE),
                    ClosureObject::Commit(CommitNode {
                        tree,
                        parents: vec![oid(LEFT_BASE), oid(RIGHT_BASE)],
                        committer_time: 90,
                    }),
                ),
                (
                    oid(RIGHT_MERGE),
                    ClosureObject::Commit(CommitNode {
                        tree,
                        parents: vec![oid(RIGHT_BASE), oid(LEFT_BASE)],
                        committer_time: 85,
                    }),
                ),
                (
                    oid(LEFT_BASE),
                    ClosureObject::Commit(CommitNode {
                        tree,
                        parents: Vec::new(),
                        committer_time: 70,
                    }),
                ),
                (
                    oid(RIGHT_BASE),
                    ClosureObject::Commit(CommitNode {
                        tree,
                        parents: Vec::new(),
                        committer_time: 65,
                    }),
                ),
                (tree, ClosureObject::Tree(Vec::new())),
            ],
        }
    }

    fn history_octopus() -> Self {
        let tree = oid(HISTORY_TREE);
        Self {
            objects: vec![
                (
                    oid(TIP),
                    ClosureObject::Commit(CommitNode {
                        tree,
                        parents: vec![oid(LEFT_MERGE), oid(RIGHT_MERGE), oid(OCTOPUS_THIRD)],
                        committer_time: 100,
                    }),
                ),
                (
                    oid(LEFT_MERGE),
                    ClosureObject::Commit(CommitNode {
                        tree,
                        parents: Vec::new(),
                        committer_time: 90,
                    }),
                ),
                (
                    oid(RIGHT_MERGE),
                    ClosureObject::Commit(CommitNode {
                        tree,
                        parents: Vec::new(),
                        committer_time: 85,
                    }),
                ),
                (
                    oid(OCTOPUS_THIRD),
                    ClosureObject::Commit(CommitNode {
                        tree,
                        parents: Vec::new(),
                        committer_time: 80,
                    }),
                ),
                (tree, ClosureObject::Tree(Vec::new())),
            ],
        }
    }

    fn partial_clone() -> Self {
        let tip = oid(FILTER_TIP);
        let root = oid(FILTER_TREE);
        let child = oid(FILTER_CHILD_TREE);
        Self {
            objects: vec![
                (
                    tip,
                    ClosureObject::Commit(CommitNode {
                        tree: root,
                        parents: Vec::new(),
                        committer_time: 100,
                    }),
                ),
                (
                    root,
                    ClosureObject::Tree(vec![
                        ClosureTreeEntry {
                            oid: oid(SMALL_BLOB),
                            object_type: ObjectType::Blob,
                        },
                        ClosureTreeEntry {
                            oid: child,
                            object_type: ObjectType::Tree,
                        },
                        ClosureTreeEntry {
                            oid: oid(LARGE_BLOB),
                            object_type: ObjectType::Blob,
                        },
                    ]),
                ),
                (
                    child,
                    ClosureObject::Tree(vec![ClosureTreeEntry {
                        oid: oid(DEEP_BLOB),
                        object_type: ObjectType::Blob,
                    }]),
                ),
                (oid(SMALL_BLOB), ClosureObject::Blob { size: 1 }),
                (oid(LARGE_BLOB), ClosureObject::Blob { size: 1_024 }),
                (oid(DEEP_BLOB), ClosureObject::Blob { size: 2 }),
            ],
        }
    }

    fn fact(&self, oid: AnyGitOid) -> ClosureObject {
        self.objects
            .iter()
            .find(|(candidate, _)| *candidate == oid)
            .map(|(_, object)| object.clone())
            .expect("fixture contains every referenced OID")
    }
}

impl ObjectClosureRepository for CorpusGraph {
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

fn request(want: AnyGitOid) -> PackRequest {
    PackRequest {
        version: UploadPackVersion::V2,
        wants: vec![want],
        haves: Vec::new(),
        shallows: Vec::new(),
        deepen: None,
        deepen_since: None,
        deepen_not: Vec::new(),
        filter: None,
        options: PackOptions::NONE,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ReferenceClosure {
    objects: Vec<ClosureObjectId>,
    shallow_update: ShallowUpdate,
    omissions: Vec<PromisorOmission>,
}

fn reference_closure(graph: &CorpusGraph, request: &PackRequest) -> ReferenceClosure {
    let excluded = reference_excluded(graph, &request.deepen_not);
    let (commits, boundaries) = reference_commits(graph, request, &excluded);
    let mut old_shallows = request.shallows.clone();
    old_shallows.sort_unstable();
    old_shallows.dedup();
    let mut shallow = boundaries;
    shallow.sort_unstable();
    let mut unshallow = old_shallows
        .into_iter()
        .filter(|old| commits.iter().any(|(commit, _)| commit == old) && !shallow.contains(old))
        .collect::<Vec<_>>();
    unshallow.sort_unstable();

    let (objects, omissions) = reference_objects(graph, &commits, request.filter.as_ref());
    ReferenceClosure {
        objects,
        shallow_update: ShallowUpdate { shallow, unshallow },
        omissions,
    }
}

fn reference_excluded(graph: &CorpusGraph, roots: &[AnyGitOid]) -> Vec<AnyGitOid> {
    let mut pending = roots.iter().rev().copied().collect::<Vec<_>>();
    let mut excluded = Vec::new();
    while let Some(current) = pending.pop() {
        if excluded.contains(&current) {
            continue;
        }
        let ClosureObject::Commit(commit) = graph.fact(current) else {
            panic!("history fixture names commits only");
        };
        excluded.push(current);
        pending.extend(commit.parents.into_iter().rev());
    }
    excluded
}

fn reference_commits(
    graph: &CorpusGraph,
    request: &PackRequest,
    excluded: &[AnyGitOid],
) -> (Vec<(AnyGitOid, CommitNode)>, Vec<AnyGitOid>) {
    let mut pending = request
        .wants
        .iter()
        .rev()
        .map(|want| (*want, 1_u32))
        .collect::<Vec<_>>();
    let mut commits = Vec::new();
    let mut boundaries = Vec::new();
    while let Some((current, depth)) = pending.pop() {
        if excluded.contains(&current) || commits.iter().any(|(seen, _)| *seen == current) {
            continue;
        }
        let ClosureObject::Commit(commit) = graph.fact(current) else {
            panic!("history fixture wants commits only");
        };
        let at_depth = request.deepen.is_some_and(|maximum| depth >= maximum);
        let before_time = request
            .deepen_since
            .is_some_and(|minimum| commit.committer_time < minimum);
        let touches_excluded = commit
            .parents
            .iter()
            .any(|parent| excluded.contains(parent));
        if at_depth || before_time || touches_excluded {
            boundaries.push(current);
        } else {
            let next_depth = depth
                .checked_add(1)
                .expect("fixture depth does not overflow");
            pending.extend(
                commit
                    .parents
                    .iter()
                    .rev()
                    .map(|parent| (*parent, next_depth)),
            );
        }
        commits.push((current, commit));
    }
    (commits, boundaries)
}

fn reference_objects(
    graph: &CorpusGraph,
    commits: &[(AnyGitOid, CommitNode)],
    filter: Option<&ObjectFilter>,
) -> (Vec<ClosureObjectId>, Vec<PromisorOmission>) {
    let mut pending = commits
        .iter()
        .map(|(commit, node)| (node.tree, Some(*commit), 0_u32))
        .collect::<Vec<_>>();
    pending.reverse();
    let mut paths = Vec::<ReferencePath>::new();
    while let Some((current, parent, depth)) = pending.pop() {
        let fact = graph.fact(current);
        if let Some(existing) = paths.iter_mut().find(|path| path.oid == current) {
            if depth > existing.depth || (depth == existing.depth && parent >= existing.parent) {
                continue;
            }
            *existing = ReferencePath {
                oid: current,
                fact: fact.clone(),
                parent,
                depth,
            };
        } else {
            paths.push(ReferencePath {
                oid: current,
                fact: fact.clone(),
                parent,
                depth,
            });
        }
        match fact {
            ClosureObject::Tree(entries) => {
                let next_depth = depth
                    .checked_add(1)
                    .expect("fixture tree depth does not overflow");
                pending.extend(
                    entries
                        .into_iter()
                        .rev()
                        .map(|entry| (entry.oid, Some(current), next_depth)),
                );
            }
            ClosureObject::Tag { target } => pending.push((target, Some(current), depth)),
            ClosureObject::Blob { .. } => {}
            ClosureObject::Commit(_) => panic!("tree frontier does not contain commits"),
        }
    }
    let mut objects = commits
        .iter()
        .map(|(commit, _)| ClosureObjectId {
            oid: *commit,
            object_type: ObjectType::Commit,
        })
        .collect::<Vec<_>>();
    let mut omissions = Vec::new();
    for path in paths {
        if let Some(reason) = reference_omission_reason(filter, &path.fact, path.depth) {
            omissions.push(PromisorOmission {
                oid: path.oid,
                object_type: path.fact.object_type(),
                parent: path.parent,
                depth: path.depth,
                reason,
            });
        } else {
            objects.push(ClosureObjectId {
                oid: path.oid,
                object_type: path.fact.object_type(),
            });
        }
    }
    objects.sort_unstable_by_key(|object| object.oid);
    omissions.sort_unstable_by_key(|omission| omission.oid);
    (objects, omissions)
}

#[derive(Clone, Debug)]
struct ReferencePath {
    oid: AnyGitOid,
    fact: ClosureObject,
    parent: Option<AnyGitOid>,
    depth: u32,
}

fn reference_omission_reason(
    filter: Option<&ObjectFilter>,
    object: &ClosureObject,
    depth: u32,
) -> Option<OmissionReason> {
    let filter = filter?;
    if matches!(object, ClosureObject::Tree(_) | ClosureObject::Blob { .. })
        && !reference_tree_depth_permits(filter, depth)
    {
        return Some(OmissionReason::TreeDepth);
    }
    if matches!(object, ClosureObject::Blob { .. }) && !reference_blob_permits(filter, object) {
        return Some(OmissionReason::BlobFilter);
    }
    None
}

fn reference_tree_depth_permits(filter: &ObjectFilter, depth: u32) -> bool {
    match filter {
        ObjectFilter::TreeDepth(exclusive_depth) => depth < *exclusive_depth,
        ObjectFilter::Combine(parts) => parts
            .iter()
            .all(|part| reference_tree_depth_permits(part, depth)),
        ObjectFilter::BlobNone
        | ObjectFilter::BlobLimit(_)
        | ObjectFilter::SparsePath(_)
        | ObjectFilter::SparseObject(_) => true,
    }
}

fn reference_blob_permits(filter: &ObjectFilter, object: &ClosureObject) -> bool {
    let ClosureObject::Blob { size } = object else {
        return true;
    };
    match filter {
        ObjectFilter::BlobNone => false,
        ObjectFilter::BlobLimit(limit) => *size < *limit,
        ObjectFilter::Combine(parts) => parts
            .iter()
            .all(|part| reference_blob_permits(part, object)),
        ObjectFilter::TreeDepth(_)
        | ObjectFilter::SparsePath(_)
        | ObjectFilter::SparseObject(_) => true,
    }
}

fn assert_reference_case(graph: &CorpusGraph, request: &PackRequest) -> PackClosure {
    let actual = compute_pack_closure(graph, request, &ClosureLimits::default())
        .expect("corpus closure is bounded and well formed");
    let reference = reference_closure(graph, request);
    assert_eq!(actual.objects, reference.objects);
    assert_eq!(actual.shallow_update, reference.shallow_update);
    assert_eq!(actual.promisor.omissions, reference.omissions);
    assert!(actual.promisor.is_authenticated());
    actual
}

#[test]
fn criss_cross_depth_crosses_the_old_boundary_and_matches_reference() {
    let graph = CorpusGraph::history_criss_cross();
    let mut fetch = request(oid(TIP));
    fetch.deepen = Some(3);
    fetch.shallows = vec![oid(LEFT_MERGE)];

    let closure = assert_reference_case(&graph, &fetch);

    assert_eq!(
        closure.shallow_update.shallow,
        vec![oid(LEFT_BASE), oid(RIGHT_BASE)]
    );
    assert_eq!(closure.shallow_update.unshallow, vec![oid(LEFT_MERGE)]);
}

#[test]
fn octopus_depth_and_deepen_since_boundaries_match_reference() {
    let octopus = CorpusGraph::history_octopus();
    let mut depth_fetch = request(oid(TIP));
    depth_fetch.deepen = Some(2);
    let depth_closure = assert_reference_case(&octopus, &depth_fetch);
    assert_eq!(
        depth_closure.shallow_update.shallow,
        vec![oid(LEFT_MERGE), oid(RIGHT_MERGE), oid(OCTOPUS_THIRD)]
    );

    let criss_cross = CorpusGraph::history_criss_cross();
    let mut since_fetch = request(oid(TIP));
    since_fetch.deepen_since = Some(95);
    let since_closure = assert_reference_case(&criss_cross, &since_fetch);
    assert_eq!(
        since_closure.shallow_update.shallow,
        vec![oid(LEFT_MERGE), oid(RIGHT_MERGE)]
    );
}

#[test]
fn deepen_not_boundary_and_permitted_twin_match_reference() {
    let graph = CorpusGraph::history_criss_cross();
    let permitted = request(oid(TIP));
    let permitted_closure = assert_reference_case(&graph, &permitted);
    assert!(permitted_closure.shallow_update.shallow.is_empty());

    let mut excluded = request(oid(TIP));
    excluded.deepen_not = vec![oid(LEFT_MERGE)];
    let excluded_closure = assert_reference_case(&graph, &excluded);
    assert_eq!(excluded_closure.shallow_update.shallow, vec![oid(TIP)]);
}

#[test]
fn blob_none_and_tree_depth_filters_match_reference_promisor_manifest() {
    let graph = CorpusGraph::partial_clone();
    let mut blob_none = request(oid(FILTER_TIP));
    blob_none.filter = Some(ObjectFilter::BlobNone);
    let blob_none_closure = assert_reference_case(&graph, &blob_none);
    assert_eq!(
        blob_none_closure.lazy_fetch_wants(),
        vec![oid(SMALL_BLOB), oid(LARGE_BLOB), oid(DEEP_BLOB)]
    );

    let mut tree_depth = request(oid(FILTER_TIP));
    tree_depth.filter = Some(ObjectFilter::TreeDepth(0));
    let tree_depth_closure = assert_reference_case(&graph, &tree_depth);
    assert_eq!(
        tree_depth_closure.promisor.omissions,
        vec![
            PromisorOmission {
                oid: oid(FILTER_TREE),
                object_type: ObjectType::Tree,
                parent: Some(oid(FILTER_TIP)),
                depth: 0,
                reason: OmissionReason::TreeDepth,
            },
            PromisorOmission {
                oid: oid(FILTER_CHILD_TREE),
                object_type: ObjectType::Tree,
                parent: Some(oid(FILTER_TREE)),
                depth: 1,
                reason: OmissionReason::TreeDepth,
            },
            PromisorOmission {
                oid: oid(SMALL_BLOB),
                object_type: ObjectType::Blob,
                parent: Some(oid(FILTER_TREE)),
                depth: 1,
                reason: OmissionReason::TreeDepth,
            },
            PromisorOmission {
                oid: oid(LARGE_BLOB),
                object_type: ObjectType::Blob,
                parent: Some(oid(FILTER_TREE)),
                depth: 1,
                reason: OmissionReason::TreeDepth,
            },
            PromisorOmission {
                oid: oid(DEEP_BLOB),
                object_type: ObjectType::Blob,
                parent: Some(oid(FILTER_CHILD_TREE)),
                depth: 2,
                reason: OmissionReason::TreeDepth,
            },
        ]
    );
}

#[test]
fn tree_depth_and_blob_limit_apply_git_exclusive_cutoffs() {
    let graph = CorpusGraph::partial_clone();
    let mut tree_two = request(oid(FILTER_TIP));
    tree_two.filter = Some(ObjectFilter::TreeDepth(2));
    let tree_two_closure = assert_reference_case(&graph, &tree_two);
    assert_eq!(
        tree_two_closure.promisor.omissions,
        vec![PromisorOmission {
            oid: oid(DEEP_BLOB),
            object_type: ObjectType::Blob,
            parent: Some(oid(FILTER_CHILD_TREE)),
            depth: 2,
            reason: OmissionReason::TreeDepth,
        }]
    );

    let mut blob_limit = request(oid(FILTER_TIP));
    blob_limit.filter = Some(ObjectFilter::BlobLimit(2));
    let blob_limit_closure = assert_reference_case(&graph, &blob_limit);
    assert_eq!(
        blob_limit_closure.lazy_fetch_wants(),
        vec![oid(LARGE_BLOB), oid(DEEP_BLOB)]
    );
}

#[test]
fn combined_filter_refuses_leaks_and_allows_selected_pack_twin() {
    let graph = CorpusGraph::partial_clone();
    let mut filtered = request(oid(FILTER_TIP));
    filtered.filter = Some(ObjectFilter::Combine(vec![
        ObjectFilter::BlobNone,
        ObjectFilter::TreeDepth(0),
    ]));
    let closure = assert_reference_case(&graph, &filtered);

    assert_eq!(closure.verify_pack_objects(&closure.objects), Ok(()));
    assert_eq!(
        closure.verify_pack_objects(&[ClosureObjectId {
            oid: oid(SMALL_BLOB),
            object_type: ObjectType::Blob,
        }]),
        Err(ClosureError::FilteredObjectLeak {
            oid: oid(SMALL_BLOB),
            object_type: ObjectType::Blob,
        })
    );
}

#[test]
fn authenticated_lazy_follow_up_completes_promised_object_and_refuses_twin() {
    let graph = CorpusGraph::partial_clone();
    let mut initial = request(oid(FILTER_TIP));
    initial.filter = Some(ObjectFilter::BlobNone);
    let original = assert_reference_case(&graph, &initial);

    let completed = compute_authenticated_lazy_fetch_closure(
        &graph,
        &original,
        &[oid(LARGE_BLOB)],
        &ClosureLimits::default(),
    )
    .expect("promised blob is permitted for lazy completion");
    assert_eq!(
        completed.objects,
        vec![ClosureObjectId {
            oid: oid(LARGE_BLOB),
            object_type: ObjectType::Blob,
        }]
    );
    assert!(completed.promisor.omissions.is_empty());

    assert_eq!(
        compute_authenticated_lazy_fetch_closure(
            &graph,
            &original,
            &[oid(FILTER_TIP)],
            &ClosureLimits::default(),
        ),
        Err(ClosureError::UnexpectedLazyFetchWant {
            oid: oid(FILTER_TIP),
        })
    );
}

#[test]
fn corpus_cases_are_deterministic_across_repeated_evaluation() {
    let graph = CorpusGraph::partial_clone();
    let mut fetch = request(oid(FILTER_TIP));
    fetch.filter = Some(ObjectFilter::Combine(vec![
        ObjectFilter::BlobNone,
        ObjectFilter::TreeDepth(0),
    ]));

    let first = compute_pack_closure(&graph, &fetch, &ClosureLimits::default())
        .expect("first corpus evaluation");
    let second = compute_pack_closure(&graph, &fetch, &ClosureLimits::default())
        .expect("second corpus evaluation");
    assert_eq!(first, second);
}

fn oracle_receipt_value(receipt: &str, key: &str) -> String {
    receipt
        .lines()
        .find_map(|line| {
            line.strip_prefix(key)
                .and_then(|value| value.strip_prefix('='))
        })
        .map(str::to_owned)
        .unwrap_or_else(|| panic!("oracle receipt omits {key}"))
}

/// E3 bridge from the pinned oracle's clone observations to this pure Rust
/// closure.  The companion E2E script alone sets the input path, so ordinary
/// unit runs never acquire or invoke Git.
#[test]
#[ignore = "requires a pinned-oracle corpus generated by the E2E suite"]
fn pinned_oracle_clone_cells_match_the_pure_closure() {
    let receipt_path = std::env::var("FGIT_SHALLOW_PARTIAL_ORACLE_RECEIPT")
        .expect("E2E suite provides the attested oracle receipt path");
    let receipt = std::fs::read_to_string(receipt_path).expect("E2E receipt is readable");

    assert_eq!(
        oracle_receipt_value(&receipt, "schema"),
        "frankengit.shallow-partial-oracle-corpus.v1"
    );
    assert_eq!(oracle_receipt_value(&receipt, "oracle_pin"), "git-2.54.0");
    assert_eq!(oracle_receipt_value(&receipt, "depth_commit_count"), "2");
    assert_eq!(oracle_receipt_value(&receipt, "depth_is_shallow"), "true");
    assert_eq!(
        oracle_receipt_value(&receipt, "blob_missing_before"),
        "true"
    );
    assert_eq!(
        oracle_receipt_value(&receipt, "blob_missing_after"),
        "false"
    );
    assert_eq!(oracle_receipt_value(&receipt, "tree_filter"), "tree:0");

    let linear = CorpusGraph::history_linear();
    let mut depth_two = request(oid(TIP));
    depth_two.deepen = Some(2);
    let depth_closure = compute_pack_closure(&linear, &depth_two, &ClosureLimits::default())
        .expect("depth-two closure");
    let commit_count = depth_closure
        .objects
        .iter()
        .filter(|object| object.object_type == ObjectType::Commit)
        .count();
    assert_eq!(commit_count, 2);
    assert_eq!(depth_closure.shallow_update.shallow, vec![oid(LEFT_MERGE)]);

    let partial = CorpusGraph::partial_clone();
    let mut blob_none = request(oid(FILTER_TIP));
    blob_none.filter = Some(ObjectFilter::BlobNone);
    let original = compute_pack_closure(&partial, &blob_none, &ClosureLimits::default())
        .expect("blob:none closure");
    assert!(!original.promisor.omissions.is_empty());
    let follow_up = compute_authenticated_lazy_fetch_closure(
        &partial,
        &original,
        &[oid(LARGE_BLOB)],
        &ClosureLimits::default(),
    )
    .expect("promised blob completion");
    assert_eq!(follow_up.objects.len(), 1);

    let mut tree_zero = request(oid(FILTER_TIP));
    tree_zero.filter = Some(ObjectFilter::TreeDepth(0));
    let tree_closure = compute_pack_closure(&partial, &tree_zero, &ClosureLimits::default())
        .expect("tree-depth closure");
    assert!(
        tree_closure
            .promisor
            .omissions
            .iter()
            .any(|omission| omission.reason == OmissionReason::TreeDepth)
    );
}
