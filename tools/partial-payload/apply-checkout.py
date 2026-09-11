from pathlib import Path
root=Path.cwd()
def replace(path,old,new):
    p=root/path; text=p.read_text()
    assert text.count(old)==1,(path,old[:120],text.count(old))
    p.write_text(text.replace(old,new))
p='crates/fgit-node/src/upload_visibility/tests/partial_oracle.rs'
replace(p,'''        let start = std::time::Instant::now();
        while !stopping.load(Ordering::Relaxed) && start.elapsed() < Duration::from_secs(90) {''','''        let start = std::time::Instant::now();
        let mut results = Vec::new();
        while !stopping.load(Ordering::Relaxed)
            && start.elapsed() < Duration::from_secs(90)
            && results.len() < 32
        {''')
replace(p,'''                    return (node, Some(result));''','''                    let failed = result.is_err();
                    results.push(result);
                    if failed { break; }''')
replace(p,'''        (node, None)
    });''','''        (node, results)
    });''')
replace(p,'''    let (node, result) = worker.join().unwrap();''','''    let (node, results) = worker.join().unwrap();''')
replace(p,'''        matches!(result, Some(Ok(GitDaemonSessionOutcome::Pack(_)))),
        "real server must emit its pack: {result:?}"''','''        results.iter().all(Result::is_ok)
            && results.iter().any(|result| matches!(result, Ok(GitDaemonSessionOutcome::Pack(_)))),
        "all real sessions must succeed and at least one must emit a pack: {results:?}"''')
replace(p,'''        let wanted_blob = git_object_id(format, GitObjectKind::Blob, b"current public content");''','''        let checkout_blob = git_object_id(format, GitObjectKind::Blob, b"current public content");
        let wanted_blob = git_object_id(format, GitObjectKind::Blob, b"common ancestor body");
        let checkout_tree = git_object_id(format, GitObjectKind::Tree, &tree_bytes(&[
            (b"100644", b"public", checkout_blob),
            (b"160000", b"submodule", private),
        ]));''')
replace(p,'''                checked(command(&run, "fsck", &client, &[]));
                let (returned, output) = live_client(''','''                checked(command(&run, "fsck", &client, &[]));
                // Exercise the ordinary user operation, not just a known-OID
                // blob request. A treeless clone can need successive lazy
                // tree and blob fetch sessions while checking out this commit.
                let (returned, _) = live_client(
                    node, &listener,
                    command(&run, "checkout", &client,
                        &[&endpoint, &repository, version, &public.to_string()]),
                );
                node = returned;
                assert_eq!(std::fs::read(PathBuf::from(&run).join("work").join(&client).join("public")).unwrap(),
                    b"current public content");
                let mut hydrated = expected.clone();
                hydrated.extend([checkout_blob.to_string(), checkout_tree.to_string()]);
                assert_eq!(inventory(&run, &client), hydrated,
                    "checkout hydrates only its tree and file, not unrelated ancestor contents or gitlinks");
                assert!(!hydrated.contains(&wanted_blob.to_string()),
                    "the subsequent historical blob read must still require a real lazy fetch");
                checked(command(&run, "fsck", &client, &[]));
                let (returned, output) = live_client(''')
replace(p,'''                assert_eq!(output.stdout, b"current public content");
                let mut complete = expected;''','''                assert_eq!(output.stdout, b"common ancestor body");
                let mut complete = hydrated;''')
p='scripts/e2e/oracle/partial_clone_client.py'
replace(p,'RUN clone|read|inventory|fsck CLIENT','RUN clone|read|checkout|inventory|fsck CLIENT')
replace(p,'if operation not in {"clone", "read", "inventory", "fsck"}:','if operation not in {"clone", "read", "checkout", "inventory", "fsck"}:')
replace(p,'network = operation in {"clone", "read"}','network = operation in {"clone", "read", "checkout"}')
replace(p,'if operation == "read":','if operation in {"read", "checkout"}:')
replace(p,'            command = ["cat-file", "blob", value]','''            command = ["cat-file", "blob", value] if operation == "read" else ["checkout", "--detach", "--force", value]''')
print('Pinned client campaign now exercises ordinary checkout, bounded multi-session lazy hydration, and an independently missing historical blob')
