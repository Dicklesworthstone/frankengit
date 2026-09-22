use super::*;
use std::collections::BTreeMap;

struct Fixture {
    format: Format,
    objects: BTreeMap<Oid, (ObjectType, Vec<u8>)>,
}
impl Fixture {
    fn new(format: Format) -> Self {
        Self {
            format,
            objects: BTreeMap::new(),
        }
    }
    fn body(&mut self, body: Vec<u8>) -> Oid {
        let id = fgit_crypto::git_object_id(self.format, GitObjectKind::Commit, &body);
        self.objects.insert(id, (ObjectType::Commit, body));
        id
    }
    fn commit(&mut self, parents: &[Oid], message: &str) -> Oid {
        let tree = fgit_crypto::git_object_id(self.format, GitObjectKind::Tree, &[]);
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            body.push_str(&format!("parent {parent}\n"));
        }
        body.push_str(&format!("author A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\n{message}\n"));
        self.body(body.into_bytes())
    }
    fn run(&self, tip: Oid, wanted: Oid, limits: Limits) -> Result<Receipt, NodeWorkspaceRefusal> {
        walk(
            self.format,
            tip,
            wanted,
            limits,
            &mut |id, _| self.objects.get(&id).cloned().ok_or_else(invalid_source),
            &mut || Ok(()),
        )
    }
}
fn is_budget(result: Result<Receipt, NodeWorkspaceRefusal>) -> bool {
    matches!(result, Err(NodeWorkspaceRefusal::SourceBrowse(ref e)) if matches!(e.as_ref(), SourceBrowseError::Budget(_)))
}

#[test]
fn ancestry_reaches_non_first_parents_in_both_native_formats() {
    for format in [Format::Sha1, Format::Sha256] {
        let mut f = Fixture::new(format);
        let root = f.commit(&[], "root");
        let left = f.commit(&[root], "left");
        let right = f.commit(&[root], "right");
        let tip = f.commit(&[left, right], "merge");
        let expected = &f.objects[&right].1;
        let mut reads = Vec::new();
        let result = walk(
            format,
            tip,
            right,
            Limits::default(),
            &mut |id, maximum| {
                reads.push((id, maximum));
                f.objects.get(&id).cloned().ok_or_else(invalid_source)
            },
            &mut || Ok(()),
        )
        .unwrap();
        assert_eq!(&result.body, expected);
        assert_eq!(
            reads.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            vec![tip, left, right]
        );
        assert_eq!(
            result.bytes,
            reads
                .iter()
                .map(|(id, _)| f.objects[id].1.len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            f.run(tip, root, Limits::default()).unwrap().body,
            f.objects[&root].1
        );
    }
}

#[test]
fn an_unrelated_admitted_commit_is_never_read_by_its_supplied_id() {
    for format in [Format::Sha1, Format::Sha256] {
        let mut f = Fixture::new(format);
        let root = f.commit(&[], "root");
        let tip = f.commit(&[root], "tip");
        let secret = f.commit(&[], "another branch");
        let mut reads = Vec::new();
        let result = walk(
            format,
            tip,
            secret,
            Limits::default(),
            &mut |id, _| {
                assert_ne!(id, secret);
                reads.push(id);
                f.objects.get(&id).cloned().ok_or_else(invalid_source)
            },
            &mut || Ok(()),
        );
        assert!(matches!(result, Err(NodeWorkspaceRefusal::RefUnavailable)));
        assert_eq!(reads, vec![tip, root]);
    }
}

#[test]
fn missing_corrupt_wrong_kind_and_ambiguous_metadata_are_not_not_found() {
    let mut f = Fixture::new(Format::Sha1);
    let root = f.commit(&[], "root");
    let tip = f.commit(&[root], "tip");
    let original = f.objects[&root].clone();
    f.objects.remove(&root);
    assert!(matches!(
        f.run(tip, root, Limits::default()),
        Err(NodeWorkspaceRefusal::Object(_))
    ));
    f.objects.insert(root, original.clone());
    f.objects.get_mut(&root).unwrap().1.push(b'!');
    assert!(matches!(
        f.run(tip, root, Limits::default()),
        Err(NodeWorkspaceRefusal::Object(_))
    ));
    f.objects.insert(root, (ObjectType::Blob, original.1));
    assert!(matches!(
        f.run(tip, root, Limits::default()),
        Err(NodeWorkspaceRefusal::Object(_))
    ));
    let tree = fgit_crypto::git_object_id(f.format, GitObjectKind::Tree, &[]);
    for extra in [format!("tree {tree}\n"), " continued\n".to_owned()] {
        let bad = f.body(format!("tree {tree}\n{extra}author A <a@invalid> 1 +0000\ncommitter A <a@invalid> 1 +0000\n\nbad\n").into_bytes());
        assert!(matches!(
            f.run(bad, bad, Limits::default()),
            Err(NodeWorkspaceRefusal::Object(_))
        ));
    }
    let continued = f.body(format!("tree {tree}\nparent {tip}\n continued\nauthor A <a@invalid> 1 +0000\ncommitter A <a@invalid> 1 +0000\n\nbad parent\n").into_bytes());
    assert!(matches!(
        f.run(continued, continued, Limits::default()),
        Err(NodeWorkspaceRefusal::Object(_))
    ));
}

#[test]
fn every_work_and_byte_limit_refuses_instead_of_truncating_ancestry() {
    let mut f = Fixture::new(Format::Sha256);
    let root = f.commit(&[], "root");
    let tip = f.commit(&[root], "tip");
    assert!(is_budget(f.run(
        tip,
        root,
        Limits {
            commits: 1,
            ..Limits::default()
        }
    )));
    assert!(is_budget(f.run(
        tip,
        root,
        Limits {
            edges: 0,
            ..Limits::default()
        }
    )));
    assert!(is_budget(f.run(
        tip,
        root,
        Limits {
            object_bytes: 1,
            ..Limits::default()
        }
    )));
    assert!(is_budget(f.run(
        tip,
        root,
        Limits {
            bytes: 1,
            ..Limits::default()
        }
    )));
    let first_bytes = f.objects[&tip].1.len();
    let mut maxima = Vec::new();
    let result = walk(
        f.format,
        tip,
        root,
        Limits {
            bytes: first_bytes + 7,
            ..Limits::default()
        },
        &mut |id, maximum| {
            maxima.push(maximum);
            f.objects.get(&id).cloned().ok_or_else(invalid_source)
        },
        &mut || Ok(()),
    );
    assert!(is_budget(result));
    assert_eq!(maxima, vec![first_bytes + 7, 7]);
}

#[test]
fn duplicate_parent_edges_do_not_duplicate_reads_but_still_consume_work() {
    let mut f = Fixture::new(Format::Sha1);
    let root = f.commit(&[], "root");
    let tip = f.commit(&[root, root], "repeated parent");
    let mut reads = Vec::new();
    walk(
        f.format,
        tip,
        root,
        Limits::default(),
        &mut |id, _| {
            reads.push(id);
            f.objects.get(&id).cloned().ok_or_else(invalid_source)
        },
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(reads, vec![tip, root]);
    assert!(is_budget(f.run(
        tip,
        root,
        Limits {
            edges: 1,
            ..Limits::default()
        }
    )));
}

#[test]
fn cancellation_at_every_checkpoint_prevents_a_success_receipt() {
    let mut f = Fixture::new(Format::Sha256);
    let root = f.commit(&[], "root");
    let tip = f.commit(&[root], "tip");
    let mut total = 0;
    walk(
        f.format,
        tip,
        root,
        Limits::default(),
        &mut |id, _| f.objects.get(&id).cloned().ok_or_else(invalid_source),
        &mut || {
            total += 1;
            Ok(())
        },
    )
    .unwrap();
    for stop in 1..=total {
        let mut checks = 0;
        let result = walk(
            f.format,
            tip,
            root,
            Limits::default(),
            &mut |id, _| f.objects.get(&id).cloned().ok_or_else(invalid_source),
            &mut || {
                checks += 1;
                if checks >= stop {
                    Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None })
                } else {
                    Ok(())
                }
            },
        );
        assert!(
            matches!(result, Err(NodeWorkspaceRefusal::Cancelled { .. })),
            "checkpoint {stop}"
        );
    }
}

#[test]
fn selection_needs_both_head_and_exact_target_without_oid_domain_aliases() {
    let mut f = Fixture::new(Format::Sha1);
    let target = f.commit(&[], "target");
    let selection = Selection {
        expected_ref_tip: target,
        commit: target,
    };
    let mut query = SourceBrowseQuery {
        path: None,
        expected_head: None,
        expected_commit: Some(target),
        action: SourceBrowseAction::List {
            after: None,
            limit: 1,
        },
    };
    assert!(selection.validate(f.format, &query).is_err());
    use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes};
    query.expected_head = Some(RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[1; 32]).unwrap(),
    ));
    assert!(selection.validate(f.format, &query).is_ok());
    query.expected_commit = None;
    assert!(selection.validate(f.format, &query).is_err());
    query.expected_commit = Some(target);
    assert!(selection.validate(Format::Sha256, &query).is_err());
    let zero = Oid::from_hex(f.format, &"0".repeat(f.format.digest_len() * 2)).unwrap();
    assert!(matches!(
        f.run(target, zero, Limits::default()),
        Err(NodeWorkspaceRefusal::ObjectFormatMismatch)
    ));
}
