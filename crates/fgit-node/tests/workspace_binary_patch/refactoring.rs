//! Real native decoding, atomic relocation and ordinary admission, not a decoder double.
use super::*;
fn relocated(format: GitHashAlgorithm, old: &[u8], new: &[u8], destination: &str) -> Vec<u8> {
    let bytes = patch(format, "asset.bin", Some(old), Some(new));
    let first = bytes.iter().position(|b| *b == b'\n').unwrap() + 1;
    [format!("diff --git a/asset.bin b/{destination}\nrename from asset.bin\nrename to {destination}\n").as_bytes(), &bytes[first..]].concat()
}
fn prepare(
    f: &Fixture,
    bytes: &[u8],
    limits: PatchLimits,
) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
    let n = f.node();
    n.runtime().block_on(n.prepare_trusted_binary_refactor_in(
        &n.request_context(),
        &reference(),
        f.base,
        [0x75; 16],
        bytes,
        &metadata(),
        limits,
    ))
}
#[test]
fn edited_binary_relocation_is_one_native_candidate() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let old = b"old\0binary\xff";
        let new = b"new\0binary\xfe\r\n";
        let mut f = Fixture::new(format, Some(old));
        let bytes = relocated(format, old, new, "moved.bin");
        let before = f.observed();
        assert!(
            f.prepare(&bytes, Default::default()).is_err(),
            "legacy grammar must not widen"
        );
        let c = prepare(&f, &bytes, Default::default()).unwrap();
        assert_eq!(f.observed(), before);
        let new_id = git_object_id(format, GitObjectKind::Blob, new);
        let tree = [
            b"100644 keep.bin\0".as_slice(),
            f.kept.as_bytes(),
            b"100644 moved.bin\0",
            new_id.as_bytes(),
        ]
        .concat();
        assert_eq!(
            c.root_tree,
            git_object_id(format, GitObjectKind::Tree, &tree)
        );
        assert_eq!(c.paths.len(), 2);
        assert_eq!(c.paths[0].path, b"asset.bin");
        assert_eq!(c.paths[0].new_blob, None);
        assert_eq!(c.paths[1].path, b"moved.bin");
        assert_eq!(c.paths[1].new_blob, Some(new_id));
        assert_eq!(c.paths[1].hunks, 2);
        assert_eq!(
            prepare(&f, &bytes, Default::default())
                .unwrap()
                .bundle_bytes(),
            c.bundle_bytes()
        );
        let terminal = f.apply(&c, b"binary-relocation");
        assert!(matches!(
            terminal.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(f.node().read_git_object(new_id).unwrap().payload(), new);
        assert_eq!(
            f.node().read_git_object(c.root_tree).unwrap().payload(),
            tree
        );
        let after = f.observed();
        f.reopen();
        assert_eq!(f.apply(&c, b"binary-relocation"), terminal);
        assert_eq!(f.observed(), after);
        assert!(prepare(&f, &bytes, Default::default()).is_err());
    }
}

#[test]
fn git_delta_relocation_and_empty_result_keep_native_identities() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let old: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let new = [&old[..333], b"changed\0\xff", &old[341..]].concat();
        let golden: &[u8] = match format {
            GitHashAlgorithm::Sha1 => {
                include_bytes!("../../../fgit-pack/src/binary_patch/fixtures/delta-sha1.patch")
            }
            GitHashAlgorithm::Sha256 => {
                include_bytes!("../../../fgit-pack/src/binary_patch/fixtures/delta-sha256.patch")
            }
        };
        let end = golden.iter().position(|b| *b == b'\n').unwrap() + 1;
        let bytes = [
            b"diff --git a/asset.bin b/moved.bin\nrename from asset.bin\nrename to moved.bin\n"
                .as_slice(),
            &golden[end..],
        ]
        .concat();
        let f = Fixture::new(format, Some(&old));
        let c = prepare(&f, &bytes, Default::default()).unwrap();
        let id = git_object_id(format, GitObjectKind::Blob, &new);
        assert_eq!(c.paths[1].new_blob, Some(id));
        let terminal = f.apply(&c, b"delta-move");
        assert!(matches!(
            terminal.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(f.node().read_git_object(id).unwrap().payload(), new);
        let f = Fixture::new(format, Some(b"old\0"));
        let bytes = String::from_utf8(relocated(format, b"old\0", b"", "moved.bin"))
            .unwrap()
            .replace("index ", "old mode 100644\nnew mode 100755\nindex ")
            .replace(" 100644\nGIT", "\nGIT");
        let c = prepare(&f, bytes.as_bytes(), Default::default()).unwrap();
        assert_eq!(
            c.paths[1].new_blob,
            Some(git_object_id(format, GitObjectKind::Blob, b""))
        );
        assert_eq!(c.paths[1].new_mode, Some(0o100755));
    }
}

#[test]
fn binary_move_refusals_preserve_the_whole_repository() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format, Some(b"old\0"));
        let before = f.observed();
        let good = relocated(format, b"old\0", b"new\0", "moved.bin");
        let old_id = git_object_id(format, GitObjectKind::Blob, b"old\0").to_string();
        let new_id = git_object_id(format, GitObjectKind::Blob, b"new\0").to_string();
        let text = String::from_utf8(good.clone()).unwrap();
        let reverse = member(b"old\0");
        let mut corrupt = good[..good.len() - reverse.len()].to_vec();
        corrupt.extend(member(b"bad\0"));
        let mut late = good.clone();
        late.extend(b"diff --git a/zzz b/zzz\n--- a/zzz\n+++ b/zzz\n@@ -1 +1 @@\n-missing\n+bad\n");
        for bytes in [
            corrupt,
            late,
            relocated(format, b"old\0", b"new\0", "keep.bin"),
            text.replace(&old_id, &f.kept.to_string()).into_bytes(),
            text.replace(&new_id, &f.kept.to_string()).into_bytes(),
            text.replace("rename from", "similarity index 100%\nrename from")
                .into_bytes(),
            good[..good.len() - reverse.len()].to_vec(),
        ] {
            assert!(prepare(&f, &bytes, Default::default()).is_err());
            assert_eq!(f.observed(), before);
        }
        assert!(
            f.node()
                .read_git_object(git_object_id(format, GitObjectKind::Blob, b"new\0"))
                .is_err()
        );
        assert!(prepare(&f, &good, Default::default()).is_ok());
        assert_eq!(f.observed(), before);
    }
}

#[test]
fn binary_relocation_checks_both_paths_and_cancellation_before_disclosure() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, Some(b"old\0"));
    let before = f.observed();
    let bytes = relocated(f.format, b"old\0", b"new\0", "moved.bin");
    let n = f.node();
    let path = |s: &[u8]| TreePath::parse_default(s).unwrap();
    let all = vec![path(b"asset.bin"), path(b"keep.bin"), path(b"moved.bin")];
    let run =
        |caps: &mut TreeCapability, hidden: &RefVisibility, cx: &fgit_node::NodeRequestContext| {
            n.runtime()
                .block_on(n.prepare_workspace_binary_refactor_in::<Sha1>(
                    cx,
                    &reference(),
                    f.base,
                    hidden,
                    caps,
                    &bytes,
                    0,
                    &metadata(),
                    Default::default(),
                ))
        };
    let cx = n.request_context();
    for writes in [vec![], vec![path(b"asset.bin")], vec![path(b"moved.bin")]] {
        let mut caps = TreeCapability::new(
            WorkspaceId::from_bytes([0x75; 16]),
            REPO,
            all.clone(),
            writes,
        );
        assert!(run(&mut caps, &RefVisibility::new(), &cx).is_err());
        assert_eq!(caps.fetched_files(), 0);
    }
    let capability = || {
        TreeCapability::new(
            WorkspaceId::from_bytes([0x75; 16]),
            REPO,
            all.clone(),
            vec![path(b"asset.bin"), path(b"moved.bin")],
        )
    };
    let mut hidden = RefVisibility::new();
    hidden
        .push_rule(b"refs/heads/main", &Default::default())
        .unwrap();
    assert!(run(&mut capability(), &hidden, &cx).is_err());
    assert!(run(&mut capability(), &RefVisibility::new(), &cx).is_ok());
    cx.cancel();
    assert!(run(&mut capability(), &RefVisibility::new(), &cx).is_err());
    assert_eq!(f.observed(), before);
}

#[test]
fn binary_relocation_shares_decode_budget_with_other_changes() {
    let f = Fixture::new(GitHashAlgorithm::Sha256, Some(b"old\0"));
    let before = f.observed();
    let bytes = relocated(f.format, b"old\0", b"new\0", "moved.bin");
    let limits = PatchLimits {
        max_file_bytes: 4,
        max_output_bytes: 16,
        ..Default::default()
    };
    assert!(prepare(&f, &bytes, limits).is_ok());
    assert!(
        prepare(
            &f,
            &bytes,
            PatchLimits {
                max_output_bytes: 7,
                ..limits
            }
        )
        .is_err()
    );
    let second = patch(f.format, "second.bin", None, Some(b"data\0"));
    let mut both = bytes.clone();
    both.extend(second);
    assert!(
        prepare(
            &f,
            &both,
            PatchLimits {
                max_output_bytes: 12,
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(prepare(&f, &both, Default::default()).is_ok());
    assert_eq!(f.observed(), before);
}
