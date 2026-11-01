//! Real prestart custody: a verified read-only node selects and prepares, but
//! its ordinary receive gate refuses before scripts or a start fence exist.
#[path = "../trusted_merge_workflow/support.rs"]
mod base;
pub(super) use base::*;

use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::merge_queue::{QueueCommand, QueueCommandAction};
use fgit_forge::preparation::{MergeCommitStyle, MergeMetadata, MergeProfile};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_node::workflow_watch::{PullRequestMergeWatchConfig, WorkflowWatchConfig};
use fgit_node::{
    LoopbackReceiveSession, OneNode, TrustedWorkflowArtifactConfig, TrustedWorkflowFailure,
};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_runner::workflow::WorkflowLimits;
use fgit_schema::json::{self, Value};
use fgit_types::cell::{CellState, CellTransitionCause};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName};
use std::{collections::BTreeMap, fs, path::PathBuf, time::Duration};

#[derive(Clone, Copy, Debug)]
pub(super) enum Mode {
    PullRequest,
    Queue,
}
impl Mode {
    pub(super) fn reference(self) -> RefName {
        if matches!(self, Self::Queue) {
            target_ref()
        } else {
            source_ref()
        }
    }
}
pub(super) fn ci_ref() -> RefName {
    RefName::try_new(b"refs/heads/ci/recovery").unwrap()
}
pub(super) fn inputs() -> Vec<Vec<u8>> {
    vec![b"ci".to_vec(), b"left".to_vec(), b"right".to_vec()]
}
pub(super) fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "CI <ci@example.test>".into(),
        committer: "CI <ci@example.test>".into(),
        timestamp: 1700000000,
        message: b"Recover original candidate\n".to_vec(),
    }
}
pub(super) fn config() -> PullRequestMergeWatchConfig {
    PullRequestMergeWatchConfig::try_new(
        ci_ref(),
        OWNER,
        metadata(),
        MergeProfile::PathMergeV1,
        MergeCommitStyle::TwoParent,
    )
    .unwrap()
}
pub(super) fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(OWNER, IdempotencyKey::new(key.to_vec()).unwrap())
}
pub(super) fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.object().unwrap().get(key).unwrap()
}
pub(super) fn text_field<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key).text().unwrap()
}
pub(super) fn json(bytes: &[u8]) -> Value {
    json::parse(bytes).unwrap()
}
pub(super) fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

struct Objects(BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>);
impl Objects {
    fn put(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let oid = git_object_id(format, kind, &body);
        self.0.insert(oid, (kind, body));
        oid
    }
    fn pack(&self, format: GitHashAlgorithm) -> Vec<u8> {
        let limits = PackLimits::default();
        let plan = PackPlanner::new(
            format,
            PackWriteProfile::COMPRESSED_NO_DELTA_V1,
            limits.clone(),
        )
        .plan_selected(
            self,
            &self.0.keys().copied().collect::<Vec<_>>(),
            &mut || true,
        )
        .unwrap();
        PackWriter::new(limits)
            .write(&plan, &mut || true)
            .unwrap()
            .0
    }
}
impl CanonicalObjectSource for Objects {
    fn load(&self, oid: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, body) = self
            .0
            .get(oid)
            .ok_or(PackWriteError::MissingCanonicalObject(*oid))?;
        Ok(CanonicalPackObject::new(
            *oid,
            *kind,
            body.clone(),
            Vec::new(),
            0,
            0,
        ))
    }
}
fn header(format: GitHashAlgorithm) -> Vec<u8> {
    match format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    }
}
fn install_workflow(f: &mut Fixture) {
    let format = f.source.algorithm();
    let mut objects = Objects(BTreeMap::new());
    let definition = format!(
        "name: recovery\non: pull_request\njobs:\n  check:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: test \"$(cat left)\" = target && test \"$(cat right)\" = source || exit 7; printf x >> '{}'\n",
        f.root.join("executed").display()
    );
    let workflow = objects.put(format, GitObjectKind::Blob, definition.into_bytes());
    let ci = objects.put(
        format,
        GitObjectKind::Tree,
        [b"100644 check.yml\0".as_slice(), workflow.as_bytes()].concat(),
    );
    let left = objects.put(format, GitObjectKind::Blob, b"base\n".to_vec());
    let right = objects.put(format, GitObjectKind::Blob, b"source\n".to_vec());
    let tree = objects.put(
        format,
        GitObjectKind::Tree,
        [
            b"40000 ci\0".as_slice(),
            ci.as_bytes(),
            b"100644 left\0",
            left.as_bytes(),
            b"100644 right\0",
            right.as_bytes(),
            b"100644 workflow.yml\0",
            f.workflow.as_bytes(),
        ]
        .concat(),
    );
    let commit = objects.put(
        format,
        GitObjectKind::Commit,
        commit_bytes(tree, &[f.source], "prestart workflow"),
    );
    let mut bundle = header(format);
    bundle.extend_from_slice(
        format!("-{} incoming base\n{commit} refs/heads/topic\n\n", f.source).as_bytes(),
    );
    bundle.extend_from_slice(&objects.pack(format));
    let result = f
        .node()
        .runtime()
        .block_on(f.node().import_incremental_git_bundle_durable_in(
            &f.node().request_context(),
            &session(b"prestart-workflow"),
            &bundle,
            &[(source_ref(), Some(f.source))],
            Default::default(),
        ))
        .unwrap();
    assert!(
        result
            .commands
            .iter()
            .all(|row| matches!(row.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    f.source = commit;
}
pub(super) fn branch(
    f: &Fixture,
    reference: RefName,
    old: Option<GitOid>,
    new: GitOid,
    key: &[u8],
) {
    let mut bundle = header(new.algorithm());
    bundle.extend_from_slice(format!("-{new} visible history\n{new} ").as_bytes());
    bundle.extend_from_slice(reference.as_bytes());
    bundle.extend_from_slice(b"\n\n");
    bundle.extend_from_slice(&Objects(BTreeMap::new()).pack(new.algorithm()));
    let result = f
        .node()
        .runtime()
        .block_on(f.node().import_incremental_git_bundle_durable_in(
            &f.node().request_context(),
            &session(key),
            &bundle,
            &[(reference, old)],
            Default::default(),
        ))
        .unwrap();
    assert!(
        result
            .commands
            .iter()
            .all(|row| matches!(row.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
}
pub(super) fn pull(f: &Fixture, version: ExpectedVersion, key: &[u8]) {
    let command = PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: version,
        action: if version == ExpectedVersion::NewStream {
            PullRequestAction::Open
        } else {
            PullRequestAction::Update
        },
        data: PullRequestData {
            source_ref: source_ref(),
            target_ref: target_ref(),
            source_tip: f.source,
            target_tip: f.target,
            title: "Original candidate".into(),
            body: String::new(),
        },
    };
    let (_, outcome) = f
        .node()
        .runtime()
        .block_on(f.node().admit_pull_request_durable_in(
            &f.node().request_context(),
            &session(key),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
}
pub(super) fn queue(f: &Fixture, version: ExpectedVersion, action: QueueCommandAction, key: &[u8]) {
    let (_, outcome) = f
        .node()
        .runtime()
        .block_on(f.node().admit_queue_durable_in(
            &f.node().request_context(),
            &session(key),
            &QueueCommand {
                number: QueueNumber::FIRST,
                target_ref: target_ref(),
                expected_version: version,
                action,
            },
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
}

pub(super) struct Poll {
    pub(super) state: &'static str,
    pub(super) json: String,
    pub(super) dispatched: bool,
    pub(super) settled: bool,
}
pub(super) fn poll(
    f: &Fixture,
    mode: Mode,
    merge: &PullRequestMergeWatchConfig,
    reads: &[Vec<u8>],
    limits: WorkflowLimits,
    artifacts: Option<&TrustedWorkflowArtifactConfig>,
) -> Result<Poll, TrustedWorkflowFailure> {
    let node = f.node();
    let request = node.request_context();
    let reference = mode.reference();
    let parent = f.parent();
    let observed = node.runtime().block_on(async {
        match mode {
            Mode::PullRequest => {
                node.poll_trusted_pull_request_merge_workflows_in(
                    &request, &reference, 1, b"ci", &parent, reads, limits, artifacts, merge,
                )
                .await
            }
            Mode::Queue => {
                node.poll_trusted_queue_head_merge_workflows_in(
                    &request, &reference, 1, b"ci", &parent, reads, limits, artifacts, merge,
                )
                .await
            }
        }
    })?;
    if let Some(dispatch) = observed.dispatch() {
        assert!(dispatch.succeeded(), "{}", observed.to_json());
    }
    Ok(Poll {
        state: observed.state(),
        json: observed.to_json(),
        dispatched: observed.dispatch().is_some(),
        settled: observed.execution_settled(),
    })
}
pub(super) struct Publication {
    pub(super) pending: usize,
    pub(super) committed: usize,
    pub(super) previous: usize,
    pub(super) error: Option<String>,
    pub(super) lines: Vec<String>,
    pub(super) json: String,
}
pub(super) fn publish(f: &Fixture, mode: Mode) -> Publication {
    let node = f.node();
    let request = node.request_context();
    let reference = mode.reference();
    let parent = f.parent();
    let merge = config();
    let mut lines = Vec::new();
    let observe = |line: &str| {
        lines.push(line.to_owned());
        Ok(())
    };
    let result = node.runtime().block_on(async {
        match mode {
            Mode::PullRequest => {
                node.publish_trusted_pull_request_merge_workflow_checks_in(
                    &request, &reference, 1, b"ci", &parent, OWNER, &merge, observe,
                )
                .await
            }
            Mode::Queue => {
                node.publish_trusted_queue_head_merge_workflow_checks_in(
                    &request, &reference, 1, b"ci", &parent, OWNER, &merge, observe,
                )
                .await
            }
        }
    });
    let json = result.to_json();
    Publication {
        pending: result.pending_execution,
        committed: result.committed,
        previous: result.previously_reported,
        error: result.error,
        lines,
        json,
    }
}

pub(super) struct Pending {
    pub(super) f: Fixture,
    pub(super) mode: Mode,
    pub(super) directory: PathBuf,
    pub(super) candidate: GitOid,
    pub(super) old: Option<GitOid>,
    pub(super) key: Vec<u8>,
    pub(super) event: Vec<u8>,
    pub(super) bundle: Vec<u8>,
    pub(super) intent: Vec<u8>,
}
impl Pending {
    pub(super) fn new(format: GitHashAlgorithm, mode: Mode, existing_ci: bool) -> Self {
        let mut f = Fixture::new(format, WORKFLOW);
        install_workflow(&mut f);
        pull(&f, ExpectedVersion::NewStream, b"prestart-pr");
        if matches!(mode, Mode::Queue) {
            queue(
                &f,
                ExpectedVersion::NewStream,
                QueueCommandAction::Enqueue {
                    pull_request: PullRequestNumber::FIRST,
                    expected_pull_request_version: AggregateVersion::FIRST,
                    source_ref: source_ref(),
                    head_tip: f.source,
                    expected_target_tip: f.target,
                    priority: 0,
                },
                b"prestart-queue",
            );
        }
        let old = existing_ci.then_some(f.source);
        if existing_ci {
            branch(&f, ci_ref(), None, f.source, b"prestart-seed-ci");
        }
        f.node.take().unwrap().shutdown().unwrap();
        let mut node = OneNode::open_existing(f.config.clone()).unwrap();
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        // Explicitly permit native current reads while withholding receive
        // intake. The public watcher creates the real original intent; no
        // successful execution or publication is removed to manufacture it.
        node.transition_cell_state(
            CellState::VerifiedReadOnly,
            CellTransitionCause::Operator,
            head.receipt().generation(),
        )
        .unwrap();
        f.node = Some(node);
        let before = generation(f.node());
        let directory = match poll(&f, mode, &config(), &inputs(), Default::default(), None) {
            Err(TrustedWorkflowFailure::Journal { directory, detail }) => {
                assert!(
                    detail.contains("StateAdmitsNoStaging") && detail.contains("VerifiedReadOnly"),
                    "expected the native read-only receive refusal: {detail}"
                );
                directory
            }
            Err(error) => panic!("prepublication refusal must retain original custody: {error}"),
            Ok(observation) => panic!(
                "read-only node published or dispatched: {}",
                observation.json
            ),
        };
        assert_eq!(generation(f.node()), before);
        let event = fs::read(directory.join("event.json")).unwrap();
        let document = json(&event);
        let selected = field(&document, "merge_candidate");
        let candidate = GitOid::from_hex(format, text_field(selected, "commit")).unwrap();
        let key = unhex(text_field(selected, "publication_key"));
        let recorded_old = match field(selected, "expected_old") {
            Value::Null => None,
            value => Some(GitOid::from_hex(format, value.text().unwrap()).unwrap()),
        };
        assert_eq!(recorded_old, old);
        let bundle = fs::read(directory.join("candidate.bundle")).unwrap();
        let intent = fs::read(directory.join("prestart-intent")).unwrap();
        let pending = Self {
            f,
            mode,
            directory,
            candidate,
            old,
            key,
            event,
            bundle,
            intent,
        };
        pending.assert_unstarted();
        assert!(
            !pending
                .directory
                .join("candidate-publication.json")
                .exists()
        );
        pending
    }
    pub(super) fn activate(&mut self) {
        let node = self.f.node.as_mut().unwrap();
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.transition_cell_state(
            CellState::Serving,
            CellTransitionCause::Operator,
            head.receipt().generation(),
        )
        .unwrap();
    }
    pub(super) fn poll(&self) -> Result<Poll, TrustedWorkflowFailure> {
        poll(
            &self.f,
            self.mode,
            &config(),
            &inputs(),
            Default::default(),
            None,
        )
    }
    pub(super) fn admit_original(&self) -> (String, DecisionOutcome) {
        let node = self.f.node();
        let result = node
            .runtime()
            .block_on(node.import_incremental_git_bundle_durable_in(
                &node.request_context(),
                &session(&self.key),
                &self.bundle,
                &[(ci_ref(), self.old)],
                Default::default(),
            ))
            .unwrap();
        assert_eq!(result.commands.len(), 1);
        let command = &result.commands[0];
        (command.tx_id.to_string(), command.terminal.outcome)
    }
    pub(super) fn outcome(&self) -> fgit_authority::key_recovery::RequestRecovery {
        self.f
            .node()
            .runtime()
            .block_on(
                self.f
                    .node()
                    .recover_transaction_in(&self.f.node().request_context(), &session(&self.key)),
            )
            .unwrap()
    }
    pub(super) fn watch(&self) -> WorkflowWatchConfig {
        self.watch_with_reporting(true)
    }
    pub(super) fn watch_with_reporting(&self, reporting: bool) -> WorkflowWatchConfig {
        let watch = WorkflowWatchConfig::try_new(
            self.f.source.algorithm(),
            self.mode.reference(),
            b"ci".to_vec(),
            self.f.parent(),
            inputs(),
            Duration::from_millis(20),
        )
        .unwrap();
        let watch = match self.mode {
            Mode::PullRequest => watch.with_pull_request(1).unwrap(),
            Mode::Queue => watch.with_merge_queue(1).unwrap(),
        }
        .with_merge_candidate(config())
        .unwrap();
        if reporting {
            watch.with_publisher(OWNER)
        } else {
            watch
        }
    }
    pub(super) fn assert_unstarted(&self) {
        assert!(!self.f.root.join("executed").exists());
        assert!(!self.directory.join("execution-started").exists());
        assert!(!self.directory.join("settled").exists());
        assert!(!self.directory.join("check-sources").exists());
        assert!(
            !fs::read_dir(&self.directory)
                .unwrap()
                .map(Result::unwrap)
                .any(|entry| entry.file_name().to_string_lossy().starts_with("dispatch-"))
        );
    }
    pub(super) fn assert_original_records(&self) {
        assert_eq!(
            fs::read(self.directory.join("event.json")).unwrap(),
            self.event
        );
        assert_eq!(
            fs::read(self.directory.join("candidate.bundle")).unwrap(),
            self.bundle
        );
        assert_eq!(
            fs::read(self.directory.join("prestart-intent")).unwrap(),
            self.intent
        );
    }
    pub(super) fn assert_ci(&self, expected: Option<GitOid>) {
        let state = self
            .f
            .node()
            .runtime()
            .block_on(self.f.node().materialize_admission())
            .unwrap();
        assert_eq!(state.snapshot().refs.get(&ci_ref()).copied(), expected);
        assert_eq!(state.snapshot().refs[&source_ref()], self.f.source);
        assert_eq!(state.snapshot().refs[&target_ref()], self.f.target);
    }
}
