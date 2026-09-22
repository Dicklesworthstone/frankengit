use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::{
    ExpectedVersion,
    event::protection::{ProtectedBranch, ProtectionCommand},
};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, PolicyEpoch, PrincipalId, RefName};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const ADMIN: PrincipalId = PrincipalId::from_bytes([0x53; 16]);
const REVIEWER: PrincipalId = PrincipalId::from_bytes([0x54; 16]);
fn arguments() -> Vec<String> {
    vec![
        "/unused".into(),
        "51".repeat(16),
        "52".repeat(16),
        "--trusted-local".into(),
        "--allow-read".into(),
        "--expected-incarnation".into(),
        "55".repeat(16),
    ]
}
struct Fixture {
    root: PathBuf,
    args: Vec<String>,
}
impl Fixture {
    fn new(format: GitHashAlgorithm, install: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-protection-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let config = NodeConfig::new(
            root.join("node"),
            TenantId::from_bytes([0x51; 16]),
            RepositoryId::from_bytes([0x52; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        if install {
            let command = ProtectionCommand {
                expected_version: ExpectedVersion::NewStream,
                expected_epoch: PolicyEpoch::try_new(1).unwrap(),
                protection: ReviewProtection {
                    administrators: vec![ADMIN],
                    branches: vec![ProtectedBranch {
                        name: RefName::try_new(b"refs/heads/protected-\xff").unwrap(),
                        reviewers: vec![REVIEWER],
                    }],
                },
            };
            let session = LoopbackReceiveSession::authenticated(
                ADMIN,
                IdempotencyKey::new(b"install".to_vec()).unwrap(),
            );
            let request = node.request_context();
            let (_, terminal) = node
                .runtime()
                .block_on(node.admit_review_protection_durable_in(
                    &request,
                    &session,
                    &command,
                    Default::default(),
                ))
                .unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
        }
        let mut args = arguments();
        args[0] = root.join("node").to_str().unwrap().into();
        args[6] = node.repository_incarnation_id().to_string();
        args.extend(["--object-format".into(), format.as_str().into()]);
        node.shutdown().unwrap();
        Self { root, args }
    }
    fn open(&self) -> ProtectionTools {
        ProtectionTools::open(parse(&self.args).unwrap()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn protection_launch_requires_explicit_scope_and_an_exact_incarnation() {
    assert!(parse(&arguments()).is_ok());
    for flag in ["--trusted-local", "--allow-read"] {
        let mut args = arguments();
        args.retain(|s| s != flag);
        assert!(parse(&args).is_err());
    }
    let mut args = arguments();
    args.truncate(5);
    assert!(parse(&args).is_err());
    for extra in [
        vec!["--allow-source"],
        vec!["--allow-reviewed-merges"],
        vec!["--allow-read"],
        vec!["--max-messages", "0"],
        vec!["--max-messages", "01"],
        vec!["--object-format", "auto"],
    ] {
        let mut args = arguments();
        args.extend(extra.into_iter().map(str::to_owned));
        assert!(parse(&args).is_err());
    }
}

#[test]
fn complete_authority_selected_policy_survives_reopen_without_any_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for installed in [false, true] {
            let fixture = Fixture::new(format, installed);
            let mut tools = fixture.open();
            let first = tools.call(SHOW, &Object::new()).unwrap();
            let fields = first.object().unwrap();
            assert_eq!(fields["installed"], Value::Bool(installed));
            assert_eq!(fields["enabled"], Value::Bool(installed));
            assert_eq!(
                fields["version"].text(),
                Some(if installed { "1" } else { "0" })
            );
            assert_eq!(
                fields["policy_epoch"].text(),
                Some(if installed { "2" } else { "1" })
            );
            assert_eq!(fields["read_only"], Value::Bool(true));
            assert_eq!(fields["transaction_created"], Value::Bool(false));
            if installed {
                let policy = fields["policy"].object().unwrap();
                assert_eq!(
                    policy["administrators"],
                    Value::Array(vec![text(ADMIN.to_string())])
                );
                let Value::Array(branches) = &policy["branches"] else {
                    panic!("branches")
                };
                let branch = branches[0].object().unwrap();
                assert_eq!(branch["reference_utf8"], Value::Null);
                assert_eq!(
                    branch["reference_hex"].text(),
                    Some(hex(b"refs/heads/protected-\xff").as_str())
                );
            } else {
                assert_eq!(fields["policy"], Value::Null);
            }
            let mut pinned = Object::new();
            pinned.insert("expected_head".into(), fields["snapshot_token"].clone());
            assert_eq!(tools.call(SHOW, &pinned).unwrap(), first);
            assert_eq!(tools.tools().len(), 1);
            assert!(!tools.is_mutation(SHOW));
            for name in [
                "frankengit_issue_list",
                "frankengit_pull_merge",
                "frankengit_transaction_outcome",
                "shell",
            ] {
                assert!(tools.call(name, &Object::new()).is_err());
            }
            let mut injected = pinned.clone();
            injected.insert("principal".into(), text("admin"));
            assert!(tools.call(SHOW, &injected).unwrap_err().invalid);
            tools.close().unwrap();
            let mut tools = fixture.open();
            assert_eq!(tools.call(SHOW, &pinned).unwrap(), first);
            tools.close().unwrap();
        }
    }
}

#[test]
fn wrong_repository_incarnation_never_opens_a_policy_reader() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, false);
    let mut launch = parse(&fixture.args).unwrap();
    launch.options.incarnation = Some(RepositoryIncarnationId::from_bytes([0xff; 16]));
    assert!(ProtectionTools::open(launch).is_err());
}

#[test]
fn installed_disabled_policy_is_not_reinterpreted_as_no_policy() {
    let policy = ReviewProtection {
        administrators: vec![ADMIN],
        branches: Vec::new(),
    };
    policy.validate().unwrap();
    let value = policy_value(&policy);
    assert_eq!(
        value.object().unwrap()["branches"],
        Value::Array(Vec::new())
    );
    assert_eq!(
        value.object().unwrap()["administrators"],
        Value::Array(vec![text(ADMIN.to_string())])
    );
    assert_ne!(value, Value::Null);
}
