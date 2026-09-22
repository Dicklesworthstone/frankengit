use super::*;
use std::cell::Cell;

fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "Author <a@example.invalid>".into(),
        committer: "Committer <c@example.invalid>".into(),
        timestamp: 1,
        message: b"Initial\n".to_vec(),
    }
}
fn add(path: &str, body: &[u8], executable: bool) -> Vec<u8> {
    let mode = if executable { "100755" } else { "100644" };
    let mut patch = format!(
        "diff --git a/{path} b/{path}\nnew file mode {mode}\n--- /dev/null\n+++ b/{path}\n"
    )
    .into_bytes();
    if !body.is_empty() {
        let lines: Vec<_> = body.split_inclusive(|b| *b == b'\n').collect();
        patch.extend(format!("@@ -0,0 +1,{} @@\n", lines.len()).as_bytes());
        for line in lines {
            patch.push(b'+');
            patch.extend(line);
        }
        if !body.ends_with(b"\n") {
            patch.extend(b"\n\\ No newline at end of file\n");
        }
    }
    patch
}
fn prepare(format: GitHashAlgorithm, patch: &[u8]) -> InitialCommitPlan {
    prepare_initial_commit(format, patch, &metadata(), PatchLimits::default(), &|| {
        false
    })
    .unwrap()
}
fn object(plan: &InitialCommitPlan, id: GitOid) -> &PlannedMergeObject {
    plan.objects.iter().find(|o| o.id == id).unwrap()
}

#[test]
fn complete_root_closure_and_git_tree_order_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let patch = [
            add("dir/file", b"same\n", true),
            add("dir.c", b"same\n", false),
            add("empty", b"", false),
            add("crlf", b"one\r\ntwo", false),
        ]
        .concat();
        let plan = prepare(format, &patch);
        let names: Vec<_> = plan.files.iter().map(|f| f.path.as_slice()).collect();
        assert_eq!(
            names,
            vec![b"crlf".as_slice(), b"dir.c", b"dir/file", b"empty"]
        );
        let shared = git_object_id(format, GitObjectKind::Blob, b"same\n");
        let nested = [b"100755 file\0".as_slice(), shared.as_bytes()].concat();
        let nested_id = git_object_id(format, GitObjectKind::Tree, &nested);
        let crlf = git_object_id(format, GitObjectKind::Blob, b"one\r\ntwo");
        let blank = git_object_id(format, GitObjectKind::Blob, b"");
        let tree = [
            b"100644 crlf\0".as_slice(),
            crlf.as_bytes(),
            b"100644 dir.c\0",
            shared.as_bytes(),
            b"40000 dir\0",
            nested_id.as_bytes(),
            b"100644 empty\0",
            blank.as_bytes(),
        ]
        .concat();
        assert_eq!(object(&plan, plan.tree).body, tree);
        assert_eq!(object(&plan, nested_id).body, nested);
        let commit = format!(
            "tree {}\nauthor Author <a@example.invalid> 1 +0000\ncommitter Committer <c@example.invalid> 1 +0000\n\nInitial\n",
            plan.tree
        );
        assert_eq!(object(&plan, plan.commit).body, commit.as_bytes());
        assert!(!commit.contains("\nparent "));
        assert_eq!(plan.objects.len(), 6); // Three blobs, two trees, one commit.
        for o in &plan.objects {
            assert_eq!(o.id, git_object_id(format, o.kind, &o.body));
        }
    }
}

#[test]
fn section_order_deduplicates_content_without_changing_native_identity() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let a = add("a/x/y", b"contents\n", false);
        let b = add("b/x/y", b"contents\n", false);
        let p = prepare(format, &[a.clone(), b.clone()].concat());
        let q = prepare(format, &[b, a].concat());
        assert_eq!(p.commit, q.commit);
        assert_eq!(p.objects, q.objects);
        assert_eq!(p.files, q.files);
        assert_ne!(p.patch_sha256, q.patch_sha256);
        assert_eq!(p.objects.len(), 5); // Blob, identical y trees, identical x trees, root, commit.
        let total = p.objects.iter().map(|o| o.body.len()).sum();
        let limits = PatchLimits {
            max_output_bytes: total,
            ..PatchLimits::default()
        };
        assert_eq!(
            prepare_initial_commit(
                format,
                &[
                    add("a/x/y", b"contents\n", false),
                    add("b/x/y", b"contents\n", false)
                ]
                .concat(),
                &metadata(),
                limits,
                &|| false
            )
            .unwrap()
            .commit,
            p.commit
        );
    }
}

#[test]
fn root_creation_requires_only_creates_and_rejects_unsafe_overlapping_paths() {
    let modify = b"diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-old\n+new\n";
    assert!(matches!(
        prepare_initial_commit(
            GitHashAlgorithm::Sha1,
            modify,
            &metadata(),
            PatchLimits::default(),
            &|| false
        ),
        Err(InitialCommitError::CreationRequired)
    ));
    for patch in [
        Vec::new(),
        [add("f", b"a\n", false), add("f/x", b"b\n", false)].concat(),
        add("../escape", b"x\n", false),
        add(".git/config", b"x\n", false),
        [add("f", b"a\n", false), add("f", b"b\n", false)].concat(),
    ] {
        assert!(
            prepare_initial_commit(
                GitHashAlgorithm::Sha1,
                &patch,
                &metadata(),
                PatchLimits::default(),
                &|| false
            )
            .is_err()
        );
    }
}

#[test]
fn index_prefixes_match_absence_and_result_in_selected_domain() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let oid = git_object_id(format, GitObjectKind::Blob, b"value\n").to_string();
        let original = String::from_utf8(add("file", b"value\n", false)).unwrap();
        let valid = original.replace(
            "new file mode 100644\n",
            &format!(
                "new file mode 100644\nindex {}..{}\n",
                "0".repeat(format.digest_len() * 2),
                oid
            ),
        );
        assert_eq!(
            prepare(format, valid.as_bytes()).files[0].blob.to_string(),
            oid
        );
        for index in [
            format!("1111111..{}", &oid[..7]),
            "0000000..0000000".into(),
            format!("{}..{}", "0".repeat(65), oid),
        ] {
            let bad = original.replace(
                "new file mode 100644\n",
                &format!("new file mode 100644\nindex {index}\n"),
            );
            assert!(
                prepare_initial_commit(
                    format,
                    bad.as_bytes(),
                    &metadata(),
                    PatchLimits::default(),
                    &|| false
                )
                .is_err()
            );
        }
    }
}

#[test]
fn exact_total_budget_includes_tree_and_commit_and_cancellation_discards_all() {
    let patch = add("a/b", b"content\n", false);
    let plan = prepare(GitHashAlgorithm::Sha256, &patch);
    let total = plan.objects.iter().map(|o| o.body.len()).sum();
    let limits = PatchLimits {
        max_output_bytes: total,
        ..PatchLimits::default()
    };
    assert!(
        prepare_initial_commit(
            GitHashAlgorithm::Sha256,
            &patch,
            &metadata(),
            limits,
            &|| false
        )
        .is_ok()
    );
    assert!(
        prepare_initial_commit(
            GitHashAlgorithm::Sha256,
            &patch,
            &metadata(),
            PatchLimits {
                max_output_bytes: total - 1,
                ..limits
            },
            &|| false
        )
        .is_err()
    );
    for stop in [0, 1, 3, 12, 24] {
        let calls = Cell::new(0usize);
        let cancel = || {
            let n = calls.get();
            calls.set(n + 1);
            n >= stop
        };
        assert!(matches!(
            prepare_initial_commit(
                GitHashAlgorithm::Sha256,
                &patch,
                &metadata(),
                PatchLimits::default(),
                &cancel
            ),
            Err(InitialCommitError::Patch(PatchError::Cancelled))
        ));
    }
}

#[test]
fn quoted_raw_names_and_missing_final_newline_remain_exact() {
    let patch = b"diff --git \"a/\\377\" \"b/\\377\"\nnew file mode 100644\n--- /dev/null\n+++ \"b/\\377\"\n@@ -0,0 +1 @@\n+raw\n\\ No newline at end of file\n";
    let plan = prepare(GitHashAlgorithm::Sha1, patch);
    assert_eq!(plan.files[0].path, [255]);
    assert_eq!(object(&plan, plan.files[0].blob).body, b"raw");
}
