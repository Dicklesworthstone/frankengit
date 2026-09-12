import pathlib,sys
root=pathlib.Path(sys.argv[1]).resolve()
def edit(path,old,new,count=1):
    p=root/path;s=p.read_text();assert s.count(old)==count,(path,old[:100],s.count(old));p.write_text(s.replace(old,new))
s='crates/fgit-node/src/upload_visibility/shallow.rs'
edit(s,'            if commits.contains(&id) && !boundaries.contains(&id) {','''            // Git's INFINITE_DEPTH removes every supplied boundary present
            // in the server's complete repository, not only wanted ancestry.
            // Here membership is narrowed to the authenticated visible graph.
            if (request.deepen == Some(2_147_483_647) || commits.contains(&id))
                && !boundaries.contains(&id)
            {''')
edit(s,'''    let desired = walk(
        objects,
        &request.wants,
        &history.boundaries,
        false,
        &mut work,
    )?;''','''    let mut roots = BTreeSet::new();
    for &id in &request.wants {
        work.insert(&mut roots, id)?;
    }
    // Removing an old boundary is a promise to deliver its missing parents,
    // including visible shallow histories on other client branches. Starting
    // at parents avoids retransmitting a natural root solely for unshallow.
    // All lookups remain inside the same verified graph and work ledger.
    for &boundary in &history.update.unshallow {
        work.tick()?;
        for &(parent, kind) in &object(objects, boundary)?.edges {
            work.tick()?;
            if kind == ObjectType::Commit {
                work.insert(&mut roots, parent)?;
            }
        }
    }
    let mut desired_roots = Vec::new();
    desired_roots.try_reserve_exact(roots.len()).map_err(|_| budget())?;
    for root in roots {
        work.tick()?;
        desired_roots.push(root);
    }
    let desired = walk(objects, &desired_roots, &history.boundaries, false, &mut work)?;''')
t='crates/fgit-node/src/upload_visibility/shallow/tests.rs'
edit(t,'fn unshallow_supplies_missing_history_and_removes_only_crossed_client_boundaries()', 'fn unshallow_also_removes_an_authorized_natural_root_outside_the_wanted_history()')
edit(t,'                unshallow: vec![middle.0]\n','                unshallow: vec![middle.0, unrelated.0]\n')
p=root/t
p.write_text(p.read_text()+'''
#[test]
fn unshallow_supplies_other_visible_histories_but_finite_depth_does_not() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut graph = Graph::new(format);
        let root = graph.commit(&[]);
        let middle = graph.commit(&[root.0]);
        let tip = graph.commit(&[middle.0]);
        let other_root = graph.commit(&[]);
        let other_tip = graph.commit(&[other_root.0]);
        let unknown = GitOid::from_hex(format, &"f".repeat(format.digest_len()*2)).unwrap();
        let mut request = request(tip.0, Some(2_147_483_647),
            vec![middle.0, other_tip.0, unknown], vec![tip.0, other_tip.0]);
        assert_eq!(update(&graph, &request), ShallowUpdate {
            shallow: vec![], unshallow: vec![middle.0, other_tip.0],
        });
        assert_eq!(ids(&graph, &request), BTreeSet::from([
            root.0, root.1, root.2, other_root.0, other_root.1, other_root.2,
        ]), "every removed visible boundary receives its complete missing parent history");
        request.deepen = Some(4);
        assert_eq!(update(&graph, &request), ShallowUpdate {
            shallow: vec![], unshallow: vec![middle.0],
        });
        assert_eq!(ids(&graph, &request), BTreeSet::from([root.0, root.1, root.2]),
            "a finite depth change does not remove a separate client's boundary");
    }
}
''')
c='scripts/e2e/oracle/partial_clone_client.py'
edit(c,'"unshallow", "fetch",', '"unshallow", "fetch", "fetch-private",',3)
edit(c,'        if operation in {"depth", "unshallow", "fetch"}:', '        if operation in {"depth", "unshallow", "fetch", "fetch-private"}:')
edit(c,'        elif operation in {"unshallow", "fetch"}:','''        elif operation == "fetch-private":
            if value != "1":
                refuse("multi-branch campaign admits only depth one")
            command = ["fetch", "--no-tags", "--depth=1", "origin", "refs/heads/private:refs/remotes/origin/private"]
        elif operation in {"unshallow", "fetch"}:''')
r='crates/fgit-node/src/upload_visibility/tests/shallow_oracle.rs'
p=root/r
p.write_text(p.read_text()+'''
#[test]
#[ignore = "requires source/binary-verified Git 2.54.0 and Bubblewrap via FGIT_ORACLE_ROOT"]
fn pinned_git_unshallow_completes_all_visible_client_branch_boundaries() {
    let oracle = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/oracle/oracle.sh");
    let output = Command::new(&oracle).args(["create-run", "git-2.54.0", "shallow-multiple-branches"]).output().unwrap();
    assert!(output.status.success(), "verified oracle unavailable: {}", String::from_utf8_lossy(&output.stderr));
    let run = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture { scratch, mut node, public, private, ancestor, .. } = fixture(format);
        // Both branches are deliberately visible. Do not let historical-only
        // storage authorize the extra boundary selected by --unshallow.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let repository = String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        for version in ["0", "1", "2"] {
            let client = format!("multi-{}-{version}", format.as_str());
            let (returned, _) = live_client(node, &listener, command(&run, "shallow-clone", &client, &[&endpoint, &repository, version, "1"])); node = returned;
            assert_eq!(markers(&run, &client), BTreeSet::from([public]));
            let (returned, _) = live_client(node, &listener, command(&run, "fetch-private", &client, &[&endpoint, &repository, version, "1"])); node = returned;
            assert_eq!(markers(&run, &client), BTreeSet::from([public, private]));
            let (returned, _) = live_client(node, &listener, command(&run, "unshallow", &client, &[&endpoint, &repository, version, "-"])); node = returned;
            assert!(markers(&run, &client).is_empty(), "infinite depth clears both visible boundaries, not only the fetched public branch");
            assert_eq!(history(&run, &client), BTreeSet::from([public.to_string(), ancestor.to_string()]));
            checked(command(&run, "fsck", &client, &[]));
            eprintln!("PINNED_SHALLOW_MULTI format={} protocol={} all_visible_boundaries=passed", format.as_str(), version);
        }
        node.shutdown().unwrap(); drop(scratch);
    }
}
''')
print('Completed source-derived unshallow semantics and added disjoint-history and pinned multi-branch coverage',flush=True)
