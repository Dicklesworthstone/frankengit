#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real trusted tools consume explicit private link copies and export exact Git trees.

#[allow(dead_code)]
#[path = "source_http/support.rs"]
mod support;

use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_git_object::{AcceptanceProfile, ParseLimits, parse_tree};
use fgit_node::{
    OneNode, WorkspaceInputSharing, WorkspaceSymlinkInputs, WorkspaceToolFailure,
    WorkspaceToolResult,
};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use support::*;

const FORMATS: [GitHashAlgorithm; 2] = [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256];
const ORIGINAL: &[u8] = b"original\n";
const LINK_TEXT: &[u8] = b"./alpha.txt";

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}

fn reads() -> Vec<Vec<u8>> {
    vec![b"alpha.txt".to_vec(), b"empty".to_vec(), b"link".to_vec()]
}

fn parent(root: &Scratch) -> std::path::PathBuf {
    let parent = root.0.join("workspaces");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    parent
}

fn execute(
    node: &OneNode,
    commit: GitOid,
    parent: &Path,
    inputs: &[Vec<u8>],
    outputs: &[Vec<u8>],
    sharing: WorkspaceInputSharing,
    policy: WorkspaceSymlinkInputs,
    script: &str,
) -> Result<WorkspaceToolResult, WorkspaceToolFailure> {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", script]);
    node.runtime()
        .block_on(node.run_trusted_workspace_tool_profiled_at_in(
            &node.request_context(),
            &reference(),
            (None, Some(commit)),
            [0x71; 16],
            parent,
            inputs,
            outputs,
            sharing,
            policy,
            &mut command,
            Duration::from_secs(30),
            ("Fixture <fixture@example.invalid>", 2, b"link copy\n"),
        ))
}

fn expected_tree(node: &OneNode, format: GitHashAlgorithm, commit: GitOid) -> GitOid {
    let object = node.read_git_object(commit).unwrap();
    let header = object
        .payload()
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap();
    let tree = GitOid::from_hex(
        format,
        std::str::from_utf8(header.strip_prefix(b"tree ").unwrap()).unwrap(),
    )
    .unwrap();
    let tree = node.read_git_object(tree).unwrap();
    let entries = parse_tree(
        tree.payload(),
        AcceptanceProfile::GitCompatibleImport,
        &ParseLimits {
            tree_reference_bytes: format.digest_len(),
            ..Default::default()
        },
    )
    .unwrap();
    let mut bytes = Vec::new();
    let changed_blob = git_object_id(format, GitObjectKind::Blob, ORIGINAL);
    let link_blob = git_object_id(format, GitObjectKind::Blob, LINK_TEXT);
    for entry in entries {
        if entry.name == b"link" {
            assert_eq!(entry.mode, b"120000");
            assert_eq!(entry.object_id, link_blob.as_bytes());
        }
        bytes.extend_from_slice(&entry.mode);
        bytes.push(b' ');
        bytes.extend_from_slice(&entry.name);
        bytes.push(0);
        bytes.extend_from_slice(if entry.name == b"empty" {
            changed_blob.as_bytes()
        } else {
            &entry.object_id
        });
    }
    git_object_id(format, GitObjectKind::Tree, &bytes)
}

#[test]
fn private_link_copies_run_real_tools_and_preserve_the_original_git_symlink() {
    for format in FORMATS {
        let root = Scratch::new();
        let (node, commit) =
            fixture_with_text_and_link(&root, format, root.config(format), ORIGINAL, LINK_TEXT);
        let parent = parent(&root);
        let before = generation(&node);
        let expected = expected_tree(&node, format, commit);
        let mut previous = None;
        for sharing in [
            WorkspaceInputSharing::Copy,
            WorkspaceInputSharing::PreferReflink,
        ] {
            let result = execute(
                &node, commit, &parent, &reads(), &[b"empty".to_vec()], sharing,
                WorkspaceSymlinkInputs::SelectedFileCopies,
                "test -f link && test ! -L link && test \"$(cat link)\" = original && cat link > empty",
            )
            .unwrap();
            assert_eq!(result.source_commit, commit);
            assert_eq!(result.root_tree, expected);
            assert_eq!(result.changed_paths, vec![b"empty".to_vec()]);
            assert_eq!(result.object_count, 3);
            if let Some(previous) = &previous {
                assert_eq!(result.pack_bytes(), previous);
            }
            previous = Some(result.pack_bytes().to_vec());
            assert!(node.read_git_object(result.candidate_commit).is_err());
            assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
            assert_eq!(generation(&node), before);
        }
        node.shutdown().unwrap();
        let reopened = reopen(&root.config(format));
        assert_eq!(generation(&reopened), before);
        assert_eq!(
            reopened
                .read_git_object(git_object_id(format, GitObjectKind::Blob, LINK_TEXT))
                .unwrap()
                .payload(),
            LINK_TEXT,
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn default_unselected_targets_and_output_aliases_refuse_before_spawning() {
    for format in FORMATS {
        let root = Scratch::new();
        let (node, commit) =
            fixture_with_text_and_link(&root, format, root.config(format), ORIGINAL, LINK_TEXT);
        let parent = parent(&root);
        let before = generation(&node);
        for (inputs, outputs, policy) in [
            (
                reads(),
                vec![b"empty".to_vec()],
                WorkspaceSymlinkInputs::Refuse,
            ),
            (
                vec![b"link".to_vec(), b"empty".to_vec()],
                vec![b"empty".to_vec()],
                WorkspaceSymlinkInputs::SelectedFileCopies,
            ),
            (
                reads(),
                vec![b"link".to_vec()],
                WorkspaceSymlinkInputs::SelectedFileCopies,
            ),
            (
                reads(),
                vec![b"alpha.txt".to_vec()],
                WorkspaceSymlinkInputs::SelectedFileCopies,
            ),
        ] {
            let error = execute(
                &node,
                commit,
                &parent,
                &inputs,
                &outputs,
                WorkspaceInputSharing::Copy,
                policy,
                "exit 97",
            )
            .unwrap_err();
            assert!(matches!(error, WorkspaceToolFailure::Host(_)), "{error:?}");
            assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
            assert_eq!(generation(&node), before);
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn changed_link_copies_or_targets_cannot_produce_a_successful_candidate() {
    for format in FORMATS {
        let root = Scratch::new();
        let (node, commit) =
            fixture_with_text_and_link(&root, format, root.config(format), ORIGINAL, LINK_TEXT);
        let parent = parent(&root);
        let before = generation(&node);
        for script in [
            "chmod u+w link && printf changed > link && printf candidate > empty",
            "rm link && ln -s alpha.txt link && printf candidate > empty",
            "chmod u+w alpha.txt && printf changed > alpha.txt && printf candidate > empty",
        ] {
            let error = execute(
                &node,
                commit,
                &parent,
                &reads(),
                &[b"empty".to_vec()],
                WorkspaceInputSharing::Copy,
                WorkspaceSymlinkInputs::SelectedFileCopies,
                script,
            )
            .unwrap_err();
            assert!(matches!(error, WorkspaceToolFailure::Host(_)), "{error:?}");
            assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
            assert_eq!(generation(&node), before);
        }
        node.shutdown().unwrap();
    }
}
