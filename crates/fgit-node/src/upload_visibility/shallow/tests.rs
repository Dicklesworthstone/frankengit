use super::*;
use fgit_wire::{ObjectFilter, PackOptions};

struct Graph {
    format: GitHashAlgorithm,
    objects: BTreeMap<GitOid, FilterObject>,
    next: usize,
}

impl Graph {
    fn new(format: GitHashAlgorithm) -> Self {
        Self {
            format,
            objects: BTreeMap::new(),
            next: 1,
        }
    }
    fn add(&mut self, kind: ObjectType, edges: Vec<(GitOid, ObjectType)>) -> GitOid {
        let width = self.format.digest_len() * 2;
        let id = GitOid::from_hex(self.format, &format!("{:0width$x}", self.next)).unwrap();
        self.next += 1;
        self.objects.insert(
            id,
            FilterObject {
                commit_time: None,
                kind,
                size: 4,
                edges,
            },
        );
        id
    }
    fn commit(&mut self, parents: &[GitOid]) -> (GitOid, GitOid, GitOid) {
        let blob = self.add(ObjectType::Blob, Vec::new());
        let tree = self.add(ObjectType::Tree, vec![(blob, ObjectType::Blob)]);
        let mut edges = vec![(tree, ObjectType::Tree)];
        edges.extend(parents.iter().map(|id| (*id, ObjectType::Commit)));
        (self.add(ObjectType::Commit, edges), tree, blob)
    }
}

fn request(
    want: GitOid,
    depth: Option<u32>,
    shallows: Vec<GitOid>,
    haves: Vec<GitOid>,
) -> PackRequest {
    PackRequest {
        version: UploadPackVersion::V2,
        wants: vec![want],
        haves,
        shallows,
        deepen: depth,
        deepen_since: None,
        deepen_not: Vec::new(),
        filter: None,
        options: PackOptions::NONE,
    }
}

fn ids(graph: &Graph, request: &PackRequest) -> BTreeSet<GitOid> {
    select(&graph.objects, request, &PackLimits::default(), &mut || {
        true
    })
    .unwrap()
    .into_iter()
    .collect()
}

fn update(graph: &Graph, request: &PackRequest) -> ShallowUpdate {
    boundary_update(&graph.objects, request, &PackLimits::default(), &mut || {
        true
    })
    .unwrap()
}

#[test]
fn depth_one_contains_only_the_tip_and_its_tree_but_never_ancestor_bodies() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut graph = Graph::new(format);
        let (root, _, _) = graph.commit(&[]);
        let (tip, tree, blob) = graph.commit(&[root]);
        let request = request(tip, Some(1), Vec::new(), Vec::new());
        assert_eq!(ids(&graph, &request), BTreeSet::from([tip, tree, blob]));
        assert_eq!(
            update(&graph, &request),
            ShallowUpdate {
                shallow: vec![tip],
                unshallow: vec![]
            }
        );
    }
}

#[test]
fn a_have_at_the_old_boundary_does_not_subtract_the_ancestors_being_deepened() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut graph = Graph::new(format);
        let root = graph.commit(&[]);
        let middle = graph.commit(&[root.0]);
        let tip = graph.commit(&[middle.0]);
        let request = request(tip.0, Some(2), vec![tip.0], vec![tip.0]);
        assert_eq!(
            ids(&graph, &request),
            BTreeSet::from([middle.0, middle.1, middle.2])
        );
        assert_eq!(
            update(&graph, &request),
            ShallowUpdate {
                shallow: vec![middle.0],
                unshallow: vec![tip.0]
            }
        );
    }
}

#[test]
fn unshallow_also_removes_an_authorized_natural_root_outside_the_wanted_history() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut graph = Graph::new(format);
        let root = graph.commit(&[]);
        let middle = graph.commit(&[root.0]);
        let tip = graph.commit(&[middle.0]);
        let unrelated = graph.commit(&[]);
        let request = request(
            tip.0,
            Some(2_147_483_647),
            vec![middle.0, unrelated.0],
            vec![tip.0],
        );
        assert_eq!(
            ids(&graph, &request),
            BTreeSet::from([root.0, root.1, root.2])
        );
        assert_eq!(
            update(&graph, &request),
            ShallowUpdate {
                shallow: vec![],
                unshallow: vec![middle.0, unrelated.0]
            }
        );
    }
}

#[test]
fn ordinary_fetch_preserves_existing_shallow_history_without_unshallowing_it() {
    let mut graph = Graph::new(GitHashAlgorithm::Sha1);
    let root = graph.commit(&[]);
    let previous = graph.commit(&[root.0]);
    let tip = graph.commit(&[previous.0]);
    let request = request(tip.0, None, vec![previous.0], vec![previous.0]);
    assert_eq!(ids(&graph, &request), BTreeSet::from([tip.0, tip.1, tip.2]));
    assert_eq!(
        update(&graph, &request),
        ShallowUpdate {
            shallow: vec![],
            unshallow: vec![]
        }
    );
}

#[test]
fn shared_ancestry_uses_the_shortest_path_independent_of_want_and_parent_order() {
    let mut graph = Graph::new(GitHashAlgorithm::Sha256);
    let root = graph.commit(&[]);
    let shared = graph.commit(&[root.0]);
    let long = graph.commit(&[shared.0]);
    let merge = graph.commit(&[long.0, shared.0]);
    let mut request = request(merge.0, Some(3), vec![], vec![]);
    assert!(ids(&graph, &request).contains(&root.0));
    assert_eq!(update(&graph, &request).shallow, vec![root.0]);
    for wants in [vec![merge.0, shared.0], vec![shared.0, merge.0, shared.0]] {
        request.wants = wants;
        assert!(update(&graph, &request).shallow.is_empty());
        assert_eq!(ids(&graph, &request).len(), graph.objects.len());
    }
}

#[test]
fn a_natural_root_at_the_exact_depth_is_shallow_but_a_deeper_request_is_not() {
    let mut graph = Graph::new(GitHashAlgorithm::Sha1);
    let root = graph.commit(&[]);
    assert_eq!(
        update(&graph, &request(root.0, Some(1), vec![], vec![])).shallow,
        vec![root.0]
    );
    assert!(
        update(&graph, &request(root.0, Some(2), vec![], vec![]))
            .shallow
            .is_empty()
    );
}

#[test]
fn annotated_tags_and_explicit_tree_or_blob_wants_survive_history_selection() {
    let mut graph = Graph::new(GitHashAlgorithm::Sha256);
    let root = graph.commit(&[]);
    let tip = graph.commit(&[root.0]);
    let inner = graph.add(ObjectType::Tag, vec![(tip.0, ObjectType::Commit)]);
    let outer = graph.add(ObjectType::Tag, vec![(inner, ObjectType::Tag)]);
    let mut request = request(outer, Some(1), vec![], vec![]);
    request.wants.push(root.1);
    assert_eq!(
        ids(&graph, &request),
        BTreeSet::from([outer, inner, tip.0, tip.1, tip.2, root.1, root.2])
    );
    assert_eq!(update(&graph, &request).shallow, vec![tip.0]);
}

#[test]
fn unknown_client_markers_are_not_disclosed_and_never_authorize_wants() {
    let mut graph = Graph::new(GitHashAlgorithm::Sha1);
    let tip = graph.commit(&[]);
    let missing = GitOid::from_hex(graph.format, &"f".repeat(40)).unwrap();
    let mut request = request(tip.0, Some(2), vec![missing], vec![missing]);
    assert_eq!(ids(&graph, &request), BTreeSet::from([tip.0, tip.1, tip.2]));
    assert_eq!(
        update(&graph, &request),
        ShallowUpdate {
            shallow: vec![],
            unshallow: vec![]
        }
    );
    request.wants.push(missing);
    assert!(
        matches!(select(&graph.objects, &request, &PackLimits::default(), &mut || true),
        Err(NodePackMaterializationRefusal::RequestedWantOutsideClosure(id)) if id == missing)
    );
}

#[test]
fn depth_selection_composes_with_blobless_and_treeless_filters_and_lazy_roots() {
    let mut graph = Graph::new(GitHashAlgorithm::Sha1);
    let root = graph.commit(&[]);
    let tip = graph.commit(&[root.0]);
    for (filter, expected) in [
        (ObjectFilter::BlobNone, BTreeSet::from([tip.0, tip.1])),
        (ObjectFilter::TreeDepth(0), BTreeSet::from([tip.0])),
    ] {
        let mut request = request(tip.0, Some(1), vec![], vec![]);
        let mut selection = select(
            &graph.objects,
            &request,
            &PackLimits::default(),
            &mut || true,
        )
        .unwrap();
        request.deepen = None;
        request.filter = Some(filter);
        super::super::partial_clone::apply_selection(
            &graph.objects,
            &mut selection,
            &request,
            &PackLimits::default(),
            &mut || true,
        )
        .unwrap();
        assert_eq!(selection.into_iter().collect::<BTreeSet<_>>(), expected);
    }
    let mut request = request(tip.2, None, vec![tip.0], vec![tip.0]);
    let mut selection = select(
        &graph.objects,
        &request,
        &PackLimits::default(),
        &mut || true,
    )
    .unwrap();
    request.shallows.clear();
    request.filter = Some(ObjectFilter::BlobNone);
    super::super::partial_clone::apply_selection(
        &graph.objects,
        &mut selection,
        &request,
        &PackLimits::default(),
        &mut || true,
    )
    .unwrap();
    assert_eq!(selection, vec![tip.2]);
}

#[test]
fn every_cancellation_checkpoint_refuses_without_returning_a_partial_selection() {
    let mut graph = Graph::new(GitHashAlgorithm::Sha256);
    let root = graph.commit(&[]);
    let tip = graph.commit(&[root.0]);
    let request = request(tip.0, Some(2), vec![tip.0], vec![tip.0]);
    let mut polls = 0;
    select(
        &graph.objects,
        &request,
        &PackLimits::default(),
        &mut || {
            polls += 1;
            true
        },
    )
    .unwrap();
    for stop in 1..=polls {
        let mut seen = 0;
        assert!(
            matches!(select(&graph.objects, &request, &PackLimits::default(), &mut || {
            seen += 1; seen < stop
        }), Err(NodePackMaterializationRefusal::Pack(error)) if matches!(*error, PackWriteError::Pack(PackError::DeadlineExceeded)))
        );
    }
}

#[test]
fn bounds_and_unsupported_controls_fail_before_returning_a_selection() {
    let mut graph = Graph::new(GitHashAlgorithm::Sha1);
    let tip = graph.commit(&[]);
    let mut request = request(tip.0, Some(1), vec![], vec![]);
    for limits in [
        PackLimits {
            max_entries: 2,
            ..PackLimits::default()
        },
        PackLimits {
            max_delta_work: 1,
            ..PackLimits::default()
        },
    ] {
        assert!(matches!(
            select(&graph.objects, &request, &limits, &mut || true),
            Err(NodePackMaterializationRefusal::DisclosureGraph(
                RefusalCode::ResourceBudgetExceeded
            ))
        ));
    }
    request.deepen_since = Some(1);
    assert!(matches!(
        select(
            &graph.objects,
            &request,
            &PackLimits::default(),
            &mut || true
        ),
        Err(NodePackMaterializationRefusal::UnsupportedFetch(
            "depth and time/ref cutoffs cannot be combined"
        ))
    ));
    request.deepen_since = None;
    request.shallows.push(tip.2);
    assert!(matches!(
        select(
            &graph.objects,
            &request,
            &PackLimits::default(),
            &mut || true
        ),
        Err(NodePackMaterializationRefusal::DisclosureGraph(
            RefusalCode::EvidenceInvalid
        ))
    ));
}

#[test]
fn unshallow_supplies_other_visible_histories_but_finite_depth_does_not() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut graph = Graph::new(format);
        let root = graph.commit(&[]);
        let middle = graph.commit(&[root.0]);
        let tip = graph.commit(&[middle.0]);
        let other_root = graph.commit(&[]);
        let other_tip = graph.commit(&[other_root.0]);
        let unknown = GitOid::from_hex(format, &"f".repeat(format.digest_len() * 2)).unwrap();
        let mut request = request(
            tip.0,
            Some(2_147_483_647),
            vec![middle.0, other_tip.0, unknown],
            vec![tip.0, other_tip.0],
        );
        assert_eq!(
            update(&graph, &request),
            ShallowUpdate {
                shallow: vec![],
                unshallow: vec![middle.0, other_tip.0],
            }
        );
        assert_eq!(
            ids(&graph, &request),
            BTreeSet::from([
                root.0,
                root.1,
                root.2,
                other_root.0,
                other_root.1,
                other_root.2,
            ]),
            "every removed visible boundary receives its complete missing parent history"
        );
        request.deepen = Some(4);
        assert_eq!(
            update(&graph, &request),
            ShallowUpdate {
                shallow: vec![],
                unshallow: vec![middle.0],
            }
        );
        assert_eq!(
            ids(&graph, &request),
            BTreeSet::from([root.0, root.1, root.2]),
            "a finite depth change does not remove a separate client's boundary"
        );
    }
}

#[path = "relative_tests.rs"]
mod relative_tests;
