//! Actual durable native PR and check publications, without a foreign VCS.
use super::*;
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    TenantId,
};
use std::path::Path;

fn config(scratch: &Scratch, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        scratch.0.join("node"),
        TenantId::from_hex(TENANT).unwrap(),
        RepositoryId::from_hex(REPOSITORY).unwrap(),
    )
    .with_object_format(format)
    .with_worker_threads(2)
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_hex(ACTOR).unwrap(),
        IdempotencyKey::new(key.to_vec()).unwrap(),
    )
}
fn loose(
    root: &Path,
    format: GitHashAlgorithm,
    kind: GitObjectKind,
    label: &str,
    body: &[u8],
) -> GitOid {
    let oid = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut frame = vec![0x78, 0x01, 0x01];
    frame.extend(length.to_le_bytes());
    frame.extend((!length).to_le_bytes());
    frame.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    frame.extend(((b << 16) | a).to_be_bytes());
    let name = oid.to_string();
    let directory = root.join("objects").join(&name[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&name[2..]), frame).unwrap();
    oid
}
fn commit(terminal: TerminalOutcome) -> TerminalOutcome {
    assert!(
        matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
        "{terminal:?}"
    );
    terminal
}
fn apply(node: &OneNode, command: &PullRequestCommand, key: &[u8]) -> TerminalOutcome {
    commit(
        node.runtime()
            .block_on(node.admit_pull_request_durable_in(
                &node.request_context(),
                &session(key),
                command,
                Default::default(),
            ))
            .unwrap()
            .1,
    )
}
fn fixture(
    scratch: &Scratch,
    format: GitHashAlgorithm,
) -> (OneNode, PullRequestCommand, TerminalOutcome) {
    let source = scratch.0.join("source");
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(source.join("config"),match format {
        GitHashAlgorithm::Sha1=>"[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256=>"[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let yaml=b"name: snapshot\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf snapshot-check\n";
    let blob = loose(&source, format, GitObjectKind::Blob, "blob", yaml);
    let tree = loose(
        &source,
        format,
        GitObjectKind::Tree,
        "tree",
        &[b"100644 workflow.yml\0".as_slice(), blob.as_bytes()].concat(),
    );
    let body = format!(
        "tree {tree}\nauthor Snapshot <snapshot@example.invalid> 1 +0000\ncommitter Snapshot <snapshot@example.invalid> 1 +0000\n\nactual snapshot fixture\n"
    );
    let tip = loose(
        &source,
        format,
        GitObjectKind::Commit,
        "commit",
        body.as_bytes(),
    );
    for name in ["main", "topic"] {
        fs::write(source.join("refs/heads").join(name), format!("{tip}\n")).unwrap();
    }
    let (mut node, _) = OneNode::init(config(scratch, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.request_context(),
            &source,
            PrincipalId::from_hex(ACTOR).unwrap(),
            b"snapshot-source",
        ))
        .unwrap();
    assert_eq!(imported.commands.len(), 2);
    for result in imported.commands {
        commit(result.terminal);
    }
    let command = PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: tip,
            target_tip: tip,
            title: "Actual native snapshot".into(),
            body: "Metadata survives current and historical reads".into(),
        },
    };
    let opened = apply(&node, &command, b"snapshot-open");
    (node, command, opened)
}
fn query(scratch: &Scratch, position: &str, tail: &[&str]) -> AtReport {
    let mut args = words(&[
        "at",
        scratch.0.join("node").to_str().unwrap(),
        TENANT,
        REPOSITORY,
        position,
    ]);
    args.extend(words(tail));
    match run(&args).unwrap() {
        CliOutcome::At(report) => report,
        other => panic!("unexpected snapshot result: {other:?}"),
    }
}
fn prs(scratch: &Scratch, position: &str) -> Vec<(u64, String, String, String)> {
    match query(scratch, position, &["prs"]) {
        AtReport::PullRequests { pull_requests, .. } => pull_requests,
        other => panic!("{other:?}"),
    }
}

#[test]
fn native_pr_current_aliases_history_and_reopen_diff_retain_real_state() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, mut command, opened) = fixture(&scratch, format);
        command.action = PullRequestAction::Close;
        command.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        let closed = apply(&node, &command, b"snapshot-close");
        node.shutdown().unwrap();
        fs::remove_dir_all(scratch.0.join("source")).unwrap();
        let expected = vec![(
            1,
            "Actual native snapshot".to_owned(),
            "closed".to_owned(),
            "refs/heads/main".to_owned(),
        )];
        assert_eq!(prs(&scratch, "latest"), expected);
        assert_eq!(
            prs(&scratch, &format!("decision:{}", closed.decision_sequence)),
            expected
        );
        let head = match query(&scratch, "latest", &[]) {
            AtReport::Summary {
                head_id,
                prs_count,
                snapshot_summary,
                ..
            } => {
                assert_eq!(prs_count, 1);
                assert!(snapshot_summary.contains("Native Pull Requests: 1"));
                head_id
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(prs(&scratch, &format!("head:{head}")), expected);
        let original = prs(&scratch, &format!("decision:{}", opened.decision_sequence));
        assert_eq!(original[0].2, "open");
        assert_eq!(original[0].1, "Actual native snapshot");
        assert!(matches!(
            query(
                &scratch,
                &format!("decision:{}", opened.decision_sequence),
                &["diff", "latest"]
            ),
            AtReport::Diff {
                ref_changes_count: 0,
                pr_changes_count: 1,
                ..
            }
        ));
        match query(&scratch, "latest", &["checks", "1"]) {
            AtReport::Checks {
                page: Some(page), ..
            } => {
                assert!(page.checks.is_empty());
                assert!(page.source_current);
                assert_eq!(page.source_tip, command.data.source_tip);
            }
            other => panic!("{other:?}"),
        }
        let mut node = OneNode::open_existing(config(&scratch, format)).unwrap();
        let auth = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.bring_into_service(auth.receipt().generation())
            .unwrap();
        command.action = PullRequestAction::Reopen;
        command.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
        command.data.title = "Reopened native snapshot".into();
        apply(&node, &command, b"snapshot-reopen");
        node.shutdown().unwrap();
        let reopened = prs(&scratch, "latest");
        assert_eq!(reopened[0].1, "Reopened native snapshot");
        assert_eq!(reopened[0].2, "open");
        assert!(matches!(
            query(
                &scratch,
                &format!("decision:{}", closed.decision_sequence),
                &["diff", "latest"]
            ),
            AtReport::Diff {
                ref_changes_count: 0,
                pr_changes_count: 1,
                ..
            }
        ));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn actual_workflow_observation_is_selected_by_decision_and_survives_reopen() {
    use fgit_forge::event::workflow_check::WorkflowCheckConclusion;
    use std::os::unix::fs::PermissionsExt;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, command, opened) = fixture(&scratch, format);
        let workflow_parent = scratch.0.join("workflow-runs");
        fs::create_dir(&workflow_parent).unwrap();
        fs::set_permissions(&workflow_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let run = node
            .runtime()
            .block_on(node.run_trusted_workflow_in(
                &node.request_context(),
                &command.data.source_ref,
                b"workflow.yml",
                [0x31; 16],
                &workflow_parent,
                &[b"workflow.yml".to_vec()],
                (None, Some(command.data.source_tip)),
                Default::default(),
            ))
            .unwrap();
        assert!(run.succeeded());
        let mut journal = run.open_check_journal(None, &|| true).unwrap();
        let history = journal
            .read_history(None, None, 128, 1024 * 1024, &|| true)
            .unwrap();
        let mut record = None;
        for entry in history.entries() {
            for (index, fact) in entry.batch().facts().iter().enumerate() {
                if fact.conclusion.is_some() {
                    let evidence = journal
                        .read_evidence(fact.receipt_commitment.unwrap())
                        .unwrap();
                    record = Some(
                        OneNode::workflow_check_record_from_batch(
                            command.data.source_ref.clone(),
                            entry.batch(),
                            index,
                            &evidence,
                            &|| true,
                        )
                        .unwrap(),
                    );
                }
            }
        }
        let record = record.expect("real runner completed one job");
        assert_eq!(record.conclusion, WorkflowCheckConclusion::Success);
        let published = commit(
            node.runtime()
                .block_on(node.admit_trusted_workflow_check_in(
                    &node.request_context(),
                    &session(b"snapshot-check"),
                    &record,
                    Default::default(),
                ))
                .unwrap()
                .1,
        );
        node.shutdown().unwrap();
        fs::remove_dir_all(scratch.0.join("source")).unwrap();
        match query(
            &scratch,
            &format!("decision:{}", opened.decision_sequence),
            &["checks", "1"],
        ) {
            AtReport::Checks {
                page: Some(page), ..
            } => assert!(page.checks.is_empty()),
            other => panic!("{other:?}"),
        }
        let page = match query(
            &scratch,
            &format!("decision:{}", published.decision_sequence),
            &["checks", "1"],
        ) {
            AtReport::Checks {
                page: Some(page), ..
            } => page,
            other => panic!("{other:?}"),
        };
        assert_eq!(page.checks.len(), 1);
        assert!(page.source_current);
        assert_eq!(page.source_tip, command.data.source_tip);
        let check = &page.checks[0];
        assert_eq!(check.job, "build");
        assert_eq!(check.conclusion, WorkflowCheckConclusion::Success);
        assert_eq!(
            check.evidence_sha256,
            fgit_crypto::sha256_digest(&record.evidence)
        );
        assert_eq!(check.evidence_bytes, record.evidence.len() as u64);
        assert!(
            matches!(query(&scratch,"latest",&["checks","1"]),AtReport::Checks {page:Some(current),..} if current==page)
        );
        let process = std::process::Command::new(env!("CARGO_BIN_EXE_fg"))
            .args([
                "at",
                scratch.0.join("node").to_str().unwrap(),
                TENANT,
                REPOSITORY,
                "latest",
                "checks",
                "1",
            ])
            .env("PATH", scratch.0.join("no-external-programs"))
            .output()
            .unwrap();
        assert!(
            process.status.success(),
            "{}",
            String::from_utf8_lossy(&process.stderr)
        );
        let text = String::from_utf8(process.stdout).unwrap();
        assert!(text.contains(&check.id.to_string()));
        assert!(text.contains("[Success] build"));
        assert!(text.contains("1 observations"));
    }
}
