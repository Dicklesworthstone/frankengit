//! The real host adapter creates ancestor directories but copies/clones only
//! the selected nested file; sharing never joins writable job inodes.

use super::*;

fn exercise_nested<A: GitHashAlgorithm>() {
    let root = Scratch::new();
    let mut fixture = Fixture::<A>::new(9, 7);
    let component = *fixture.base.base_tree_oid();
    let mut packages = b"40000 component\0".to_vec();
    packages.extend_from_slice(component.digest_bytes());
    packages.extend_from_slice(b"100644 private\0");
    packages.extend_from_slice(fixture.blob.digest_bytes());
    let packages = fixture.source.put::<A>(GitObjectKind::Tree, packages);
    let mut tree = b"40000 packages\0".to_vec();
    tree.extend_from_slice(packages.digest_bytes());
    tree.extend_from_slice(b"100644 private\0");
    tree.extend_from_slice(fixture.blob.digest_bytes());
    let tree = fixture.source.put::<A>(GitObjectKind::Tree, tree);
    let commit = fixture.source.put::<A>(
        GitObjectKind::Commit,
        format!(
            "tree {}\nparent {}\nauthor Test <test@example.invalid> 2 +0000\ncommitter Test <test@example.invalid> 2 +0000\n\nNested workspace\n",
            hex(tree.digest_bytes()), hex(fixture.base.base_commit_oid().digest_bytes()),
        ).into_bytes(),
    );
    fixture.base = BaseView::new(
        fixture.base.repository_id(),
        fixture.base.base_rcr_id(),
        commit,
        tree,
        ParseLimits {
            tree_reference_bytes: A::DIGEST_LEN,
            ..ParseLimits::default()
        },
        PathPolicy::default(),
    );
    let selected = path(b"packages/component/input\xff");
    let mut capability = TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        fixture.base.repository_id(),
        vec![selected.clone()],
        vec![selected.clone()],
    );
    let manifest = fixture.manifest(&mut capability);
    assert_eq!(manifest.entries().len(), 3);
    assert_eq!(manifest.receipt().payload_bytes(), fixture.body.len());
    let capability_b = TreeCapability::new(
        WorkspaceId::from_bytes([2; 16]),
        fixture.base.repository_id(),
        vec![selected.clone()],
        vec![selected.clone()],
    );
    let plan_b = SparseWorkspacePlan::new(
        Arc::clone(&manifest),
        vec![selected.clone()],
        &capability_b,
        0,
        LIMITS,
    )
    .unwrap();
    let plan =
        SparseWorkspacePlan::new(manifest, vec![selected.clone()], &capability, 0, LIMITS).unwrap();
    assert_ne!(plan.reservation().plan, plan_b.reservation().plan);
    let (mut cache, cache_ledger) = cache(&plan, &root, SharedInputPolicy::PreferReflink);
    let (a, ledger_a) = materialize(plan, &capability, &root, b"a", Some(&mut cache));
    let (b, ledger_b) = materialize(plan_b, &capability_b, &root, b"b", Some(&mut cache));
    let filename = OsStr::from_bytes(selected.as_bytes());
    let first = root.0.join("a").join(filename);
    let second = root.0.join("b").join(filename);
    for slot in ["a", "b"] {
        let directory = root.0.join(slot);
        assert_eq!(fs::read(directory.join(filename)).unwrap(), fixture.body);
        for excluded in [
            "private",
            "packages/private",
            "packages/component/copy.bin",
            "packages/component/tool.bin",
        ] {
            assert!(
                !directory.join(excluded).exists(),
                "unselected source must remain absent: {excluded}"
            );
        }
    }
    let first_metadata = fs::metadata(&first).unwrap();
    let second_metadata = fs::metadata(&second).unwrap();
    assert_eq!(first_metadata.nlink(), 1);
    assert_eq!(second_metadata.nlink(), 1);
    assert_ne!(
        (first_metadata.dev(), first_metadata.ino()),
        (second_metadata.dev(), second_metadata.ino())
    );
    fs::write(&first, b"one job's private edit\n").unwrap();
    assert_eq!(fs::read(&second).unwrap(), fixture.body);
    assert_eq!(
        fixture.source.0[fixture.blob.digest_bytes()].1,
        fixture.body
    );
    let a = close_workspace(a, ledger_a);
    let b = close_workspace(b, ledger_b);
    let cache = close_cache(cache, cache_ledger);
    assert_eq!(
        a.copied_bytes + a.shared_host_bytes,
        fixture.body.len() as u64
    );
    assert_eq!(
        b.copied_bytes + b.shared_host_bytes,
        fixture.body.len() as u64
    );
    assert_eq!(
        cache.stats.cloned_bytes + cache.stats.fallback_bytes,
        2 * fixture.body.len() as u64
    );
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
}

#[test]
fn narrow_nested_inputs_reach_real_private_workspaces_without_sibling_files() {
    exercise_nested::<Sha1>();
    exercise_nested::<Sha256>();
}
