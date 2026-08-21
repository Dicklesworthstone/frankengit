#![forbid(unsafe_code)]

use fgit_crypto::{git_object_id, sha256_digest};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, ObjectFormat, PackLimits, PackPlanner,
    PackWriteError, PackWriteProfile,
};
use fgit_wire::closure::{
    ClosureError, ClosureLimits, ClosureObject, ClosureObjectId, ClosureTreeEntry, CommitNode,
    ObjectClosureRepository, OmissionReason, PackClosurePlanError, PromisorOmission,
    compute_authenticated_lazy_fetch_closure, compute_pack_closure,
};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, ObjectFilter, ObjectType, PackOptions,
    PackRequest, Packet, UploadPackRepository, UploadPackVersion, V2UploadPack, WireEvent,
    WireLimits,
};

fn oid(hex: &str) -> AnyGitOid {
    AnyGitOid::from_hex(GitObjectFormat::Sha1, hex).expect("SHA-1 fixture identity")
}

const TOP: &str = "1111111111111111111111111111111111111111";
const LEFT: &str = "2222222222222222222222222222222222222222";
const RIGHT: &str = "3333333333333333333333333333333333333333";
const BASE: &str = "4444444444444444444444444444444444444444";
const THIRD: &str = "5555555555555555555555555555555555555555";
const ROOT_TREE: &str = "6666666666666666666666666666666666666666";
const CHILD_TREE: &str = "7777777777777777777777777777777777777777";
const SMALL_BLOB: &str = "8888888888888888888888888888888888888888";
const LARGE_BLOB: &str = "9999999999999999999999999999999999999999";

#[derive(Clone, Debug)]
struct FixtureGraph {
    objects: Vec<(AnyGitOid, ClosureObject)>,
}

impl FixtureGraph {
    fn with_criss_cross() -> Self {
        let root = oid(ROOT_TREE);
        Self {
            objects: vec![
                (
                    oid(TOP),
                    ClosureObject::Commit(CommitNode {
                        tree: root,
                        parents: vec![oid(LEFT), oid(RIGHT)],
                        committer_time: 100,
                    }),
                ),
                (
                    oid(LEFT),
                    ClosureObject::Commit(CommitNode {
                        tree: root,
                        parents: vec![oid(BASE)],
                        committer_time: 90,
                    }),
                ),
                (
                    oid(RIGHT),
                    ClosureObject::Commit(CommitNode {
                        tree: root,
                        parents: vec![oid(BASE)],
                        committer_time: 80,
                    }),
                ),
                (
                    oid(BASE),
                    ClosureObject::Commit(CommitNode {
                        tree: root,
                        parents: Vec::new(),
                        committer_time: 70,
                    }),
                ),
                (root, ClosureObject::Tree(Vec::new())),
            ],
        }
    }

    fn with_filter_tree() -> Self {
        let top = oid(TOP);
        let root = oid(ROOT_TREE);
        let child = oid(CHILD_TREE);
        Self {
            objects: vec![
                (
                    top,
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
                            oid: oid(LARGE_BLOB),
                            object_type: ObjectType::Blob,
                        },
                        ClosureTreeEntry {
                            oid: child,
                            object_type: ObjectType::Tree,
                        },
                    ]),
                ),
                (
                    child,
                    ClosureObject::Tree(vec![ClosureTreeEntry {
                        oid: oid(SMALL_BLOB),
                        object_type: ObjectType::Blob,
                    }]),
                ),
                (oid(SMALL_BLOB), ClosureObject::Blob { size: 1 }),
                (oid(LARGE_BLOB), ClosureObject::Blob { size: 10_000 }),
            ],
        }
    }
}

impl ObjectClosureRepository for FixtureGraph {
    fn object_format(&self) -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    fn object(&self, oid: AnyGitOid) -> Result<ClosureObject, ClosureError> {
        self.objects
            .iter()
            .find(|(candidate, _)| *candidate == oid)
            .map(|(_, object)| object.clone())
            .ok_or(ClosureError::InconsistentGraph { oid })
    }
}

struct NegotiationRepository {
    refs: Vec<AdvertisedRef>,
}

impl NegotiationRepository {
    fn new() -> Self {
        let limits = WireLimits::default();
        Self {
            refs: vec![
                AdvertisedRef::new(oid(TOP), b"refs/heads/main", &limits)
                    .expect("main fixture ref"),
                AdvertisedRef::new(oid(LEFT), b"refs/heads/stop", &limits)
                    .expect("stop fixture ref"),
            ],
        }
    }
}

impl UploadPackRepository for NegotiationRepository {
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
}

fn request(wants: Vec<AnyGitOid>) -> PackRequest {
    PackRequest {
        version: UploadPackVersion::V2,
        wants,
        haves: Vec::new(),
        shallows: Vec::new(),
        deepen: None,
        deepen_since: None,
        deepen_not: Vec::new(),
        filter: None,
        options: PackOptions::SIDE_BAND_64K,
    }
}

fn object_ids(closure: &fgit_wire::closure::PackClosure) -> Vec<AnyGitOid> {
    closure.objects.iter().map(|entry| entry.oid).collect()
}

#[test]
fn criss_cross_deepen_crosses_old_boundary_and_is_deterministic() {
    let graph = FixtureGraph::with_criss_cross();
    let mut request = request(vec![oid(TOP)]);
    request.deepen = Some(3);
    request.shallows = vec![oid(LEFT)];

    let first = compute_pack_closure(&graph, &request, &ClosureLimits::default())
        .expect("bounded criss-cross closure");
    let second = compute_pack_closure(&graph, &request, &ClosureLimits::default())
        .expect("repeat bounded criss-cross closure");

    assert_eq!(first, second);
    assert_eq!(first.shallow_update.shallow, vec![oid(BASE)]);
    assert_eq!(first.shallow_update.unshallow, vec![oid(LEFT)]);
    assert!(object_ids(&first).contains(&oid(RIGHT)));
}

#[test]
fn octopus_depth_boundary_is_complete_and_sorted() {
    let mut graph = FixtureGraph::with_criss_cross();
    let root = oid(ROOT_TREE);
    graph.objects.push((
        oid(THIRD),
        ClosureObject::Commit(CommitNode {
            tree: root,
            parents: vec![oid(BASE)],
            committer_time: 85,
        }),
    ));
    graph.objects[0].1 = ClosureObject::Commit(CommitNode {
        tree: root,
        parents: vec![oid(LEFT), oid(RIGHT), oid(THIRD)],
        committer_time: 100,
    });
    let mut request = request(vec![oid(TOP)]);
    request.deepen = Some(2);

    let closure =
        compute_pack_closure(&graph, &request, &ClosureLimits::default()).expect("octopus closure");

    assert_eq!(
        closure.shallow_update.shallow,
        vec![oid(LEFT), oid(RIGHT), oid(THIRD)]
    );
    assert!(object_ids(&closure).contains(&oid(TOP)));
}

#[test]
fn deepen_not_and_deepen_since_produce_distinct_typed_boundaries() {
    let graph = FixtureGraph::with_criss_cross();
    let mut deepen_not = request(vec![oid(TOP)]);
    deepen_not.deepen_not = vec![oid(LEFT)];
    let excluded = compute_pack_closure(&graph, &deepen_not, &ClosureLimits::default())
        .expect("deepen-not closure");
    assert_eq!(excluded.shallow_update.shallow, vec![oid(TOP)]);

    let mut since = request(vec![oid(TOP)]);
    since.deepen_since = Some(95);
    let timed = compute_pack_closure(&graph, &since, &ClosureLimits::default())
        .expect("deepen-since closure");
    assert_eq!(timed.shallow_update.shallow, vec![oid(LEFT), oid(RIGHT)]);
}

#[test]
fn combined_filters_mark_authenticated_omissions_and_reject_leaks() {
    let graph = FixtureGraph::with_filter_tree();
    let mut request = request(vec![oid(TOP)]);
    request.filter = Some(ObjectFilter::Combine(vec![
        ObjectFilter::BlobNone,
        ObjectFilter::TreeDepth(0),
    ]));

    let closure = compute_pack_closure(&graph, &request, &ClosureLimits::default())
        .expect("filtered closure");

    assert!(closure.promisor.is_authenticated());
    assert_eq!(object_ids(&closure), vec![oid(TOP)]);
    assert_eq!(
        closure.lazy_fetch_wants(),
        vec![
            oid(ROOT_TREE),
            oid(CHILD_TREE),
            oid(SMALL_BLOB),
            oid(LARGE_BLOB),
        ]
    );
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
fn promisor_manifest_commitment_matches_canonical_one_shot_encoding() {
    let graph = FixtureGraph::with_filter_tree();
    let mut request = request(vec![oid(TOP)]);
    request.filter = Some(ObjectFilter::Combine(vec![
        ObjectFilter::BlobNone,
        ObjectFilter::TreeDepth(0),
    ]));
    let closure = compute_pack_closure(&graph, &request, &ClosureLimits::default())
        .expect("filtered closure");

    assert_eq!(
        closure.promisor.commitment,
        sha256_digest(&canonical_omission_encoding(&closure.promisor.omissions))
    );
}

fn canonical_omission_encoding(omissions: &[PromisorOmission]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"fgit-promisor-omissions-v1\0");
    for omission in omissions {
        bytes.extend_from_slice(&omission.oid.algorithm().code_point().to_be_bytes());
        bytes.extend_from_slice(omission.oid.as_bytes());
        bytes.push(object_type_code(omission.object_type));
        match omission.parent {
            Some(parent) => {
                bytes.push(1);
                bytes.extend_from_slice(&parent.algorithm().code_point().to_be_bytes());
                bytes.extend_from_slice(parent.as_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&omission.depth.to_be_bytes());
        bytes.push(omission_reason_code(omission.reason));
    }
    bytes
}

const fn object_type_code(object_type: ObjectType) -> u8 {
    match object_type {
        ObjectType::Blob => 1,
        ObjectType::Tree => 2,
        ObjectType::Commit => 3,
        ObjectType::Tag => 4,
    }
}

const fn omission_reason_code(reason: OmissionReason) -> u8 {
    match reason {
        OmissionReason::BlobFilter => 1,
        OmissionReason::TreeDepth => 2,
    }
}

#[test]
fn lazy_fetch_follow_up_completes_an_omitted_blob() {
    let graph = FixtureGraph::with_filter_tree();
    let mut request = request(vec![oid(TOP)]);
    request.filter = Some(ObjectFilter::BlobNone);
    let original = compute_pack_closure(&graph, &request, &ClosureLimits::default())
        .expect("filtered promisor closure");
    let follow_up = compute_authenticated_lazy_fetch_closure(
        &graph,
        &original,
        &[oid(SMALL_BLOB)],
        &ClosureLimits::default(),
    )
    .expect("lazy promisor follow-up");

    assert_eq!(
        follow_up.objects,
        vec![ClosureObjectId {
            oid: oid(SMALL_BLOB),
            object_type: ObjectType::Blob,
        }]
    );
    assert!(follow_up.promisor.omissions.is_empty());
}

#[test]
fn lazy_fetch_refuses_non_promised_or_tampered_omissions() {
    let graph = FixtureGraph::with_filter_tree();
    let mut request = request(vec![oid(TOP)]);
    request.filter = Some(ObjectFilter::BlobNone);
    let mut original = compute_pack_closure(&graph, &request, &ClosureLimits::default())
        .expect("filtered promisor closure");

    assert_eq!(
        compute_authenticated_lazy_fetch_closure(
            &graph,
            &original,
            &[oid(TOP)],
            &ClosureLimits::default(),
        ),
        Err(ClosureError::UnexpectedLazyFetchWant { oid: oid(TOP) })
    );

    original.promisor.omissions.clear();
    assert_eq!(
        compute_authenticated_lazy_fetch_closure(
            &graph,
            &original,
            &[oid(SMALL_BLOB)],
            &ClosureLimits::default(),
        ),
        Err(ClosureError::UnauthenticatedPromisorManifest)
    );
}

#[derive(Clone, Debug)]
struct PackFixtureSource {
    objects: Vec<CanonicalPackObject>,
}

impl CanonicalObjectSource for PackFixtureSource {
    fn load(&self, id: &AnyGitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.objects
            .iter()
            .find(|object| object.id() == *id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}

fn filtered_pack_fixture() -> (FixtureGraph, PackFixtureSource, AnyGitOid) {
    let omitted_body = b"promised blob".to_vec();
    let omitted = git_object_id(GitObjectFormat::Sha1, ObjectType::Blob, &omitted_body);
    let mut tree_body = b"100644 promised\0".to_vec();
    tree_body.extend_from_slice(omitted.as_bytes());
    let tree = git_object_id(GitObjectFormat::Sha1, ObjectType::Tree, &tree_body);
    let commit_body = format!(
        "tree {tree}\nauthor A <a@example.test> 1 +0000\ncommitter A <a@example.test> 1 +0000\n\nfiltered\n"
    )
    .into_bytes();
    let commit = git_object_id(GitObjectFormat::Sha1, ObjectType::Commit, &commit_body);
    let graph = FixtureGraph {
        objects: vec![
            (
                commit,
                ClosureObject::Commit(CommitNode {
                    tree,
                    parents: Vec::new(),
                    committer_time: 1,
                }),
            ),
            (
                tree,
                ClosureObject::Tree(vec![ClosureTreeEntry {
                    oid: omitted,
                    object_type: ObjectType::Blob,
                }]),
            ),
            (omitted, ClosureObject::Blob { size: 13 }),
        ],
    };
    let source = PackFixtureSource {
        objects: vec![
            CanonicalPackObject::new(commit, ObjectType::Commit, commit_body, vec![tree], 1, 0),
            CanonicalPackObject::new(tree, ObjectType::Tree, tree_body, vec![omitted], 0, 1),
        ],
    };
    (graph, source, omitted)
}

fn reference_blob_none_closure(
    graph: &FixtureGraph,
    root: AnyGitOid,
) -> (Vec<ClosureObjectId>, Vec<PromisorOmission>) {
    let mut visited = Vec::new();
    let mut objects = Vec::new();
    let mut omissions = Vec::new();
    reference_visit_blob_none(
        graph,
        root,
        None,
        0,
        &mut visited,
        &mut objects,
        &mut omissions,
    );
    objects.sort_by_key(|object| object.oid);
    omissions.sort_by_key(|omission| omission.oid);
    (objects, omissions)
}

fn reference_visit_blob_none(
    graph: &FixtureGraph,
    oid: AnyGitOid,
    parent: Option<AnyGitOid>,
    depth: u32,
    visited: &mut Vec<AnyGitOid>,
    objects: &mut Vec<ClosureObjectId>,
    omissions: &mut Vec<PromisorOmission>,
) {
    if visited.contains(&oid) {
        return;
    }
    visited.push(oid);
    let object = graph
        .objects
        .iter()
        .find(|(candidate, _)| *candidate == oid)
        .map(|(_, object)| object.clone())
        .expect("reference fixture contains every graph edge");
    match object {
        ClosureObject::Commit(commit) => {
            objects.push(ClosureObjectId {
                oid,
                object_type: ObjectType::Commit,
            });
            reference_visit_blob_none(
                graph,
                commit.tree,
                Some(oid),
                0,
                visited,
                objects,
                omissions,
            );
            for parent_commit in commit.parents {
                reference_visit_blob_none(
                    graph,
                    parent_commit,
                    Some(oid),
                    0,
                    visited,
                    objects,
                    omissions,
                );
            }
        }
        ClosureObject::Tree(entries) => {
            objects.push(ClosureObjectId {
                oid,
                object_type: ObjectType::Tree,
            });
            for entry in entries {
                let entry_depth = depth.checked_add(1).expect("fixture depth fits u32");
                reference_visit_blob_none(
                    graph,
                    entry.oid,
                    Some(oid),
                    entry_depth,
                    visited,
                    objects,
                    omissions,
                );
            }
        }
        ClosureObject::Blob { .. } => omissions.push(PromisorOmission {
            oid,
            object_type: ObjectType::Blob,
            parent,
            depth,
            reason: OmissionReason::BlobFilter,
        }),
        ClosureObject::Tag { target } => {
            objects.push(ClosureObjectId {
                oid,
                object_type: ObjectType::Tag,
            });
            reference_visit_blob_none(graph, target, Some(oid), depth, visited, objects, omissions);
        }
    }
}

#[test]
fn filtered_closure_equals_independent_reference_model() {
    let (graph, _source, _omitted) = filtered_pack_fixture();
    let root = graph.objects[0].0;
    let mut request = request(vec![root]);
    request.filter = Some(ObjectFilter::BlobNone);

    let actual = compute_pack_closure(&graph, &request, &ClosureLimits::default())
        .expect("filtered closure");
    let (expected_objects, expected_omissions) = reference_blob_none_closure(&graph, root);

    assert_eq!(actual.objects, expected_objects);
    assert_eq!(actual.promisor.omissions, expected_omissions);
}

#[test]
fn authenticated_filtered_closure_plans_only_selected_pack_objects() {
    let (graph, source, omitted) = filtered_pack_fixture();
    let mut request = request(vec![graph.objects[0].0]);
    request.filter = Some(ObjectFilter::BlobNone);
    let closure = compute_pack_closure(&graph, &request, &ClosureLimits::default())
        .expect("filtered closure");
    let planner = PackPlanner::new(
        ObjectFormat::Sha1,
        PackWriteProfile::STORED_V1,
        PackLimits::default(),
    );
    let mut deadline = || true;

    let plan = closure
        .plan_selected(&planner, &source, &mut deadline, &ClosureLimits::default())
        .expect("authenticated selected closure plan");
    assert_eq!(plan.entries().len(), closure.objects.len());
    assert!(
        plan.entries()
            .iter()
            .all(|entry| entry.object().id() != omitted),
        "promised omission must not leak into the pack plan"
    );

    let mut tampered = closure;
    tampered.promisor.omissions.clear();
    assert_eq!(
        tampered.plan_selected(&planner, &source, &mut deadline, &ClosureLimits::default()),
        Err(PackClosurePlanError::Closure(
            ClosureError::UnauthenticatedPromisorManifest
        ))
    );
}

#[test]
fn zero_deepen_and_tiny_graph_budget_are_typed_refusals() {
    let graph = FixtureGraph::with_criss_cross();
    let mut zero = request(vec![oid(TOP)]);
    zero.deepen = Some(0);
    assert_eq!(
        compute_pack_closure(&graph, &zero, &ClosureLimits::default()),
        Err(ClosureError::InvalidDeepenDepth)
    );

    let limits = ClosureLimits {
        max_commits: 1,
        ..ClosureLimits::default()
    };
    assert_eq!(
        compute_pack_closure(&graph, &request(vec![oid(TOP)]), &limits),
        Err(ClosureError::ResourceLimit {
            field: "commits",
            limit: 1,
        })
    );
}

#[test]
fn v2_negotiation_carries_deepen_since_and_deepen_not_to_closure() {
    let repository = NegotiationRepository::new();
    let caps = Capabilities::parse_v2_advertisement(
        &[
            Packet::Data(b"version 2\n".to_vec()),
            Packet::Data(b"fetch=shallow filter\n".to_vec()),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .expect("fixture v2 capabilities");
    let mut machine = V2UploadPack::new(caps, WireLimits::default()).expect("v2 machine");
    let mut pack_requested = false;
    for packet in [
        Packet::Data(b"command=fetch\n".to_vec()),
        Packet::Delimiter,
        Packet::Data(format!("want {TOP}\n").into_bytes()),
        Packet::Data(b"deepen-since 95\n".to_vec()),
        Packet::Data(b"deepen-not refs/heads/stop\n".to_vec()),
        Packet::Data(b"done\n".to_vec()),
        Packet::Flush,
    ] {
        let transition = machine
            .push_packet(&packet, &repository)
            .expect("accepted v2 shallow request");
        if let Some(WireEvent::PackRequested(request)) = transition.events.last() {
            pack_requested = true;
            assert_eq!(request.deepen_since, Some(95));
            assert_eq!(request.deepen_not, vec![oid(LEFT)]);
        }
    }
    assert!(pack_requested, "completed fetch must carry a pack request");
}
