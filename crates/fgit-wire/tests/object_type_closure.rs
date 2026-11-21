#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use fgit_wire::closure::{
    ClosureError, ClosureLimits, ClosureObject, ClosureTreeEntry, CommitNode,
    ObjectClosureRepository, OmissionReason, PackClosure, compute_authenticated_lazy_fetch_closure,
    compute_pack_closure,
};
use fgit_wire::{
    AnyGitOid, GitObjectFormat, ObjectFilter, ObjectType, PackOptions, PackRequest,
    UploadPackVersion,
};

struct History {
    format: GitObjectFormat,
    objects: BTreeMap<AnyGitOid, ClosureObject>,
}

impl History {
    fn id(&self, byte: u8) -> AnyGitOid {
        AnyGitOid::from_hex(
            self.format,
            &format!("{byte:02x}").repeat(self.format.digest_len()),
        )
        .unwrap()
    }

    fn new(format: GitObjectFormat) -> Self {
        let mut result = Self {
            format,
            objects: BTreeMap::new(),
        };
        // Two history generations, each with different content; the tip also
        // has a nested tree. Type omission must never hide selected objects
        // behind an omitted ancestor commit or a chain of omitted trees.
        let entry = |byte, object_type| ClosureTreeEntry {
            oid: result.id(byte),
            object_type,
        };
        let objects = [
            (
                1,
                ClosureObject::Commit(CommitNode {
                    tree: result.id(3),
                    parents: vec![result.id(2)],
                    committer_time: 2,
                }),
            ),
            (
                2,
                ClosureObject::Commit(CommitNode {
                    tree: result.id(4),
                    parents: Vec::new(),
                    committer_time: 1,
                }),
            ),
            (
                3,
                ClosureObject::Tree(vec![entry(5, ObjectType::Tree), entry(6, ObjectType::Blob)]),
            ),
            (4, ClosureObject::Tree(vec![entry(7, ObjectType::Blob)])),
            (5, ClosureObject::Tree(vec![entry(8, ObjectType::Blob)])),
            (6, ClosureObject::Blob { size: 1 }),
            (7, ClosureObject::Blob { size: 2 }),
            (8, ClosureObject::Blob { size: 4 }),
        ];
        for (byte, object) in objects {
            result.objects.insert(result.id(byte), object);
        }
        result
    }

    fn request(&self, filter: ObjectFilter) -> PackRequest {
        PackRequest {
            version: UploadPackVersion::V2,
            wants: vec![self.id(1)],
            haves: Vec::new(),
            shallows: Vec::new(),
            deepen: None,
            deepen_since: None,
            deepen_not: Vec::new(),
            filter: Some(filter),
            options: PackOptions::NONE,
        }
    }

    fn ids(&self, bytes: &[u8]) -> BTreeSet<AnyGitOid> {
        bytes.iter().map(|byte| self.id(*byte)).collect()
    }
}

impl ObjectClosureRepository for History {
    fn object_format(&self) -> GitObjectFormat {
        self.format
    }

    fn object(&self, oid: AnyGitOid) -> Result<ClosureObject, ClosureError> {
        self.objects
            .get(&oid)
            .cloned()
            .ok_or(ClosureError::InconsistentGraph { oid })
    }
}

fn selected(closure: &PackClosure) -> BTreeSet<AnyGitOid> {
    closure.objects.iter().map(|object| object.oid).collect()
}

#[test]
fn object_type_closure_filters_history_without_pruning_selected_descendants() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let history = History::new(format);
        for (kind, bytes) in [
            (ObjectType::Commit, &[1, 2][..]),
            (ObjectType::Tree, &[1, 3, 4, 5][..]),
            (ObjectType::Blob, &[1, 6, 7, 8][..]),
            (ObjectType::Tag, &[1][..]),
        ] {
            let request = history.request(ObjectFilter::ObjectType(kind));
            let closure =
                compute_pack_closure(&history, &request, &ClosureLimits::default()).unwrap();
            assert_eq!(
                selected(&closure),
                history.ids(bytes),
                "{format:?} {kind:?}"
            );
            assert!(closure.promisor.is_authenticated());
            let omitted = closure
                .promisor
                .omissions
                .iter()
                .map(|omission| {
                    assert_eq!(omission.reason, OmissionReason::ObjectTypeFilter);
                    assert_ne!(omission.object_type, kind);
                    omission.oid
                })
                .collect::<BTreeSet<_>>();
            assert!(omitted.is_disjoint(&selected(&closure)));
            assert_eq!(
                omitted
                    .union(&selected(&closure))
                    .copied()
                    .collect::<BTreeSet<_>>(),
                history.objects.keys().copied().collect(),
                "every traversed object is selected or authenticated as omitted",
            );
        }
    }
}

#[test]
fn explicit_commit_roots_override_type_and_compound_filters_intersect() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let history = History::new(format);
        for (filter, bytes) in [
            (
                ObjectFilter::Combine(vec![
                    ObjectFilter::ObjectType(ObjectType::Blob),
                    ObjectFilter::BlobLimit(4),
                    ObjectFilter::TreeDepth(2),
                ]),
                &[1, 6, 7][..],
            ),
            (
                ObjectFilter::Combine(vec![
                    ObjectFilter::ObjectType(ObjectType::Blob),
                    ObjectFilter::ObjectType(ObjectType::Tree),
                ]),
                &[1][..],
            ),
        ] {
            let closure = compute_pack_closure(
                &history,
                &history.request(filter),
                &ClosureLimits::default(),
            )
            .unwrap();
            assert_eq!(selected(&closure), history.ids(bytes));
        }
        let mut request = history.request(ObjectFilter::ObjectType(ObjectType::Tag));
        request.wants.push(history.id(2));
        let expected = compute_pack_closure(&history, &request, &ClosureLimits::default()).unwrap();
        assert_eq!(selected(&expected), history.ids(&[1, 2]));
        request.wants = vec![history.id(2), history.id(1), history.id(2)];
        assert_eq!(
            compute_pack_closure(&history, &request, &ClosureLimits::default()).unwrap(),
            expected,
            "root order and duplicate wants do not change omission commitments",
        );
    }
}

#[test]
fn object_type_omissions_support_authenticated_lazy_fetch_and_keep_graph_bounds() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let history = History::new(format);
        let request = history.request(ObjectFilter::ObjectType(ObjectType::Tag));
        let closure = compute_pack_closure(&history, &request, &ClosureLimits::default()).unwrap();
        for (want, bytes) in [(2, &[2, 4, 7][..]), (8, &[8][..])] {
            let lazy = compute_authenticated_lazy_fetch_closure(
                &history,
                &closure,
                &[history.id(want)],
                &ClosureLimits::default(),
            )
            .unwrap();
            assert_eq!(selected(&lazy), history.ids(bytes));
            assert!(lazy.promisor.omissions.is_empty());
        }
        let mut altered = closure.clone();
        altered.promisor.omissions[0].reason = OmissionReason::BlobFilter;
        assert!(matches!(
            compute_authenticated_lazy_fetch_closure(
                &history,
                &altered,
                &[history.id(2)],
                &ClosureLimits::default(),
            ),
            Err(ClosureError::UnauthenticatedPromisorManifest),
        ));
        // A small final pack does not exempt its complete input graph from
        // traversal limits: the omitted trees and blobs are still charged.
        let limits = ClosureLimits {
            max_objects: 2,
            ..ClosureLimits::default()
        };
        assert!(matches!(
            compute_pack_closure(&history, &request, &limits),
            Err(ClosureError::ResourceLimit { .. }),
        ));
        let mut shallow = request;
        shallow.deepen = Some(1);
        let clipped = compute_pack_closure(&history, &shallow, &ClosureLimits::default()).unwrap();
        assert_eq!(selected(&clipped), history.ids(&[1]));
        assert_eq!(clipped.shallow_update.shallow, vec![history.id(1)]);
        assert!(
            clipped
                .promisor
                .omissions
                .iter()
                .all(|omission| !history.ids(&[2, 4, 7]).contains(&omission.oid)),
            "shallow-excluded history never becomes a filter promise",
        );
    }
}

#[test]
fn commits_and_filtered_descendants_share_the_exact_object_budget() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let history = History::new(format);
        for (filter, selected_count) in [
            (None, 8),
            (Some(ObjectFilter::BlobNone), 5),
            (Some(ObjectFilter::ObjectType(ObjectType::Tag)), 1),
        ] {
            let mut request = history.request(ObjectFilter::BlobNone);
            request.filter = filter;
            for maximum in [6, 7, 8] {
                let limits = ClosureLimits {
                    max_objects: maximum,
                    ..ClosureLimits::default()
                };
                let result = compute_pack_closure(&history, &request, &limits);
                if maximum < 8 {
                    assert_eq!(
                        result,
                        Err(ClosureError::ResourceLimit {
                            field: "objects",
                            limit: maximum,
                        }),
                        "{format:?} {:?}: omitted commits and descendants retain their charge",
                        request.filter,
                    );
                } else {
                    let closure = result.unwrap();
                    assert_eq!(closure.objects.len(), selected_count);
                    assert_eq!(closure.objects.len() + closure.promisor.omissions.len(), 8);
                }
            }
        }
    }
}
