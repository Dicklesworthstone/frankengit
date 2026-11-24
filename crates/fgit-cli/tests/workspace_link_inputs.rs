#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real command execution, candidate custody and recovery for selected file links.

#[path = "../../fgit-node/tests/source_http/support.rs"]
mod support;

use fgit_crypto::sha256_digest;
use fgit_node::{NodeConfig, WorkspaceInputSharing, WorkspaceSymlinkInputs};
use fgit_schema::json::{self, Value};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;
use support::{Scratch, fixture_with_text_and_link, generation, hex, reopen};

const FORMATS: [GitHashAlgorithm; 2] = [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256];
const PROFILE: &str = "selected-file-link-copies-v1";
const AUTHOR: &str = "Link input <link@example.invalid>";
const MESSAGE: &str = "consume selected link input\n";
const READS: &[&str] = &["alpha.txt", "link", "empty"];
const TOOL: &str = "test -f link && test ! -L link && test \"$(cat link)\" = original && cmp alpha.txt link && printf 'updated\n' > empty";

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}

fn private_parent(root: &Scratch, name: &str) -> PathBuf {
    let path = root.0.join(name);
    DirBuilder::new().mode(0o700).create(&path).unwrap();
    path
}

fn arguments(
    root: &Scratch,
    parent: &Path,
    id: [u8; 16],
    profile: Option<&str>,
    reads: &[&str],
    writes: &[&str],
    script: &str,
    marker: &Path,
) -> Vec<String> {
    let mut args = vec![
        "workspace".into(),
        "run".into(),
        root.0.join("node").to_str().unwrap().into(),
        "31".repeat(16),
        "32".repeat(16),
        "refs/heads/main".into(),
        parent.to_str().unwrap().into(),
        hex(&id),
        "candidate.bundle".into(),
        "--trusted-local".into(),
        "--shared-inputs".into(),
        "copy".into(),
        "--author".into(),
        AUTHOR.into(),
        "--timestamp".into(),
        "7".into(),
        "--message".into(),
        MESSAGE.into(),
        "--timeout-secs".into(),
        "30".into(),
    ];
    for read in reads {
        args.extend(["--read".into(), (*read).into()]);
    }
    for write in writes {
        args.extend(["--write".into(), (*write).into()]);
    }
    if let Some(profile) = profile {
        args.extend(["--symlink-inputs".into(), profile.into()]);
    }
    args.extend([
        "--".into(),
        "/bin/sh".into(),
        "-c".into(),
        script.into(),
        "workspace-link-input".into(),
        marker.to_str().unwrap().into(),
    ]);
    args
}

fn invoke(args: &[String], code: i32) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_fg"))
        .args(args)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn decode(bytes: &[u8]) -> Value {
    json::parse_with(
        bytes,
        json::Limits {
            input: 1024 * 1024,
            depth: 16,
            nodes: 32_768,
            items: 4096,
            string: 1024 * 1024,
        },
    )
    .unwrap()
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    &value.object().unwrap()[key]
}

fn unchanged_authority(config: &NodeConfig, before: u64, source: GitOid) {
    let node = reopen(config);
    assert_eq!(generation(&node), before);
    let current = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap();
    assert_eq!(current.snapshot().refs[&reference()], source);
    node.shutdown().unwrap();
}

#[test]
fn selected_file_copies_export_the_native_candidate_and_recover_without_execution() {
    for format in FORMATS {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, source) = fixture_with_text_and_link(
            &root,
            format,
            config.clone(),
            b"original\n",
            b"./alpha.txt",
        );
        let before = generation(&node);
        let native_parent = private_parent(&root, "native");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", TOOL]);
        let expected = node
            .runtime()
            .block_on(
                node.run_trusted_workspace_tool_profiled_at_in(
                    &node.request_context(),
                    &reference(),
                    (None, Some(source)),
                    [0x70; 16],
                    &native_parent,
                    &READS
                        .iter()
                        .map(|path| path.as_bytes().to_vec())
                        .collect::<Vec<_>>(),
                    &[b"empty".to_vec()],
                    WorkspaceInputSharing::Copy,
                    WorkspaceSymlinkInputs::SelectedFileCopies,
                    &mut command,
                    Duration::from_secs(30),
                    (AUTHOR, 7, MESSAGE.as_bytes()),
                ),
            )
            .unwrap();
        assert_eq!(expected.source_commit, source);
        assert_eq!(expected.changed_paths, vec![b"empty".to_vec()]);
        assert_eq!(expected.object_count, 3, "new blob, root tree and commit");
        assert_eq!(fs::read_dir(&native_parent).unwrap().count(), 0);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();

        let parent = private_parent(&root, "cli");
        let marker = root.0.join("executions");
        let args = arguments(
            &root,
            &parent,
            [0x71; 16],
            Some(PROFILE),
            READS,
            &["empty"],
            &format!("{TOOL} && printf x >> \"$1\""),
            &marker,
        );
        let receipt = decode(&invoke(&args, 0).stdout);
        assert_eq!(field(&receipt, "type").text(), Some("workspace_candidate"));
        assert_eq!(
            field(&receipt, "published_to_repository"),
            &Value::Bool(false)
        );
        assert_eq!(field(&receipt, "symlink_inputs").text(), Some(PROFILE));
        assert_eq!(
            field(&receipt, "object_format").text(),
            Some(format.as_str())
        );
        assert_eq!(
            field(&receipt, "source_commit").text(),
            Some(source.to_string().as_str())
        );
        assert_eq!(
            field(&receipt, "source_rcr").text(),
            Some(expected.source_rcr.to_string().as_str())
        );
        assert_eq!(
            field(&receipt, "candidate_commit").text(),
            Some(expected.candidate_commit.to_string().as_str())
        );
        assert_eq!(
            field(&receipt, "root_tree").text(),
            Some(expected.root_tree.to_string().as_str())
        );
        assert_eq!(field(&receipt, "objects").unsigned(), Some(3));
        assert_eq!(
            field(&receipt, "changed_paths_hex"),
            &Value::Array(vec![Value::String(hex(b"empty"))])
        );
        assert_eq!(fs::read(&marker).unwrap(), b"x");

        let bundle = fs::read(parent.join("candidate.bundle")).unwrap();
        let header = format!(
            "# v3 git bundle\n@object-format={}\n-{source} TreeFS source prerequisite\n{} refs/heads/main\n\n",
            format.as_str(),
            expected.candidate_commit,
        );
        assert_eq!(bundle, [header.as_bytes(), expected.pack_bytes()].concat());
        unchanged_authority(&config, before, source);

        let directory = PathBuf::from(field(&receipt, "invocation_directory").text().unwrap());
        let request_id = field(&receipt, "request_sha256").text().unwrap();
        let terminal_id = field(&receipt, "terminal_sha256").text().unwrap();
        let request = fs::read(directory.join("request")).unwrap();
        let terminal = fs::read(directory.join("terminal")).unwrap();
        assert_eq!(hex(&sha256_digest(&request)), request_id);
        assert_eq!(hex(&sha256_digest(&terminal)), terminal_id);
        assert!(
            request
                .windows(PROFILE.len())
                .any(|bytes| bytes == PROFILE.as_bytes())
        );
        assert_eq!(
            fs::read(directory.join("candidate.bundle")).unwrap(),
            bundle
        );
        let saved_receipt = fs::read(directory.join("receipt.json")).unwrap();
        assert_eq!(
            field(&decode(&saved_receipt), "symlink_inputs").text(),
            Some(PROFILE)
        );

        let recovered_path = parent.join("recovered.bundle");
        let recovery = decode(
            &invoke(
                &[
                    "workspace".into(),
                    "recover".into(),
                    directory.to_str().unwrap().into(),
                    "--trusted-local".into(),
                    "--request-id".into(),
                    request_id.into(),
                    "--terminal-id".into(),
                    terminal_id.into(),
                    "--output".into(),
                    recovered_path.to_str().unwrap().into(),
                ],
                0,
            )
            .stdout,
        );
        assert_eq!(field(&recovery, "type").text(), Some("workspace_recovery"));
        assert_eq!(field(&recovery, "state").text(), Some("ready"));
        assert_eq!(field(&recovery, "request_sha256").text(), Some(request_id));
        assert_eq!(
            field(&recovery, "terminal_sha256").text(),
            Some(terminal_id)
        );
        assert_eq!(field(&recovery, "reexecuted"), &Value::Bool(false));
        assert_eq!(
            field(&recovery, "published_to_repository"),
            &Value::Bool(false)
        );
        assert_eq!(
            field(&recovery, "receipt_json").text().unwrap().as_bytes(),
            saved_receipt
        );
        assert_eq!(fs::read(recovered_path).unwrap(), bundle);
        assert_eq!(fs::read(directory.join("request")).unwrap(), request);
        assert_eq!(fs::read(directory.join("terminal")).unwrap(), terminal);
        assert_eq!(
            fs::read(&marker).unwrap(),
            b"x",
            "recovery must not execute the command"
        );

        // A fresh destination avoids the independent existing-bundle guard, so
        // this refusal proves the persisted invocation claim prevents reruns.
        let mut repeated = args;
        repeated[8] = "repeated.bundle".into();
        let refused = invoke(&repeated, 2);
        assert!(refused.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&refused.stderr)
                .contains("workspace invocation already reserved")
        );
        assert!(!parent.join("repeated.bundle").exists());
        assert_eq!(fs::read(&marker).unwrap(), b"x");
        unchanged_authority(&config, before, source);
    }
}

fn refused_before_command(
    root: &Scratch,
    name: &str,
    id: [u8; 16],
    profile: Option<&str>,
    reads: &[&str],
    writes: &[&str],
) {
    let parent = private_parent(root, name);
    let marker = root.0.join(format!("{name}-executions"));
    let args = arguments(
        root,
        &parent,
        id,
        profile,
        reads,
        writes,
        "printf ran >> \"$1\"",
        &marker,
    );
    let output = invoke(&args, 2);
    assert!(output.stdout.is_empty());
    let detail = String::from_utf8_lossy(&output.stderr);
    assert!(detail.contains("UnsupportedEntry"), "{name}: {detail}");
    assert!(!marker.exists(), "{name}: a refused plan must not execute");
    assert!(!parent.join("candidate.bundle").exists());
    assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
    let suffix = format!("-{}", hex(&id));
    let claimed = fs::read_dir(root.0.join("node/workspace-invocations"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with(&suffix)
        })
        .unwrap();
    assert!(claimed.join("request").is_file());
    assert!(claimed.join("terminal").is_file());
    assert!(!claimed.join("candidate.bundle").exists());
    assert!(!claimed.join("receipt.json").exists());
}

#[test]
fn file_links_require_opt_in_selected_targets_and_nonoverlapping_outputs() {
    for format in FORMATS {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, source) = fixture_with_text_and_link(
            &root,
            format,
            config.clone(),
            b"original\n",
            b"./alpha.txt",
        );
        let before = generation(&node);
        node.shutdown().unwrap();
        refused_before_command(&root, "default", [0x80; 16], None, READS, &["empty"]);
        refused_before_command(
            &root,
            "explicit-refuse",
            [0x81; 16],
            Some("refuse"),
            READS,
            &["empty"],
        );
        refused_before_command(
            &root,
            "unselected-target",
            [0x82; 16],
            Some(PROFILE),
            &["link", "empty"],
            &["empty"],
        );
        refused_before_command(
            &root,
            "target-output",
            [0x83; 16],
            Some(PROFILE),
            READS,
            &["alpha.txt"],
        );
        refused_before_command(
            &root,
            "link-output",
            [0x84; 16],
            Some(PROFILE),
            READS,
            &["link"],
        );
        unchanged_authority(&config, before, source);
    }
}

#[test]
fn selected_file_copy_profile_never_resolves_links_against_the_host() {
    for format in FORMATS {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, source) = fixture_with_text_and_link(
            &root,
            format,
            config.clone(),
            b"original\n",
            b"../../outside-secret",
        );
        let before = generation(&node);
        node.shutdown().unwrap();
        let outside = fs::read(root.0.join("outside-secret")).unwrap();
        refused_before_command(
            &root,
            "escaping-target",
            [0x85; 16],
            Some(PROFILE),
            READS,
            &["empty"],
        );
        assert_eq!(fs::read(root.0.join("outside-secret")).unwrap(), outside);
        unchanged_authority(&config, before, source);
    }
}
