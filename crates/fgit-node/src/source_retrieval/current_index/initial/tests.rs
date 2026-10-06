//! Persisted native repositories, real index generations and metadata changes.
use super::*;
use crate::{LoopbackReceiveSession, NodeConfig};
use crate::source_retrieval::{SymbolPolicy, SymbolUnavailable};
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_forge::preparation::MergeMetadata;
use fgit_forge::source_symbols::{SymbolKind, SymbolMatchMode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    node: Option<OneNode>,
    format: GitHashAlgorithm,
    reference: RefName,
    commit: GitOid,
    lexical: Option<GenerationActivation>,
    symbols: Option<GenerationActivation>,
}
fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x63; 16]), IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}
fn metadata() -> MergeMetadata {
    MergeMetadata { author: "A <a@example.invalid>".into(), committer: "C <c@example.invalid>".into(),
        timestamp: 1, message: b"source retrieval fixture\n".to_vec() }
}
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!("fg-current-initial-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let config = NodeConfig::new(root.join("node"), TenantId::from_bytes([0x61; 16]),
            RepositoryId::from_bytes([0x62; 16])).with_object_format(format).with_worker_threads(2);
        let (mut node, _) = OneNode::init(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let patch = ["src/Thing.rs", "src/Thing-extra.rs", "src/other.rs"].iter().map(|path|
            format!("diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+pub fn Thing() {{}}\n")
        ).collect::<String>();
        let request = node.request_context();
        let (_, plan, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(
            &request, &reference, patch.as_bytes(), &metadata(), Default::default(), None,
        )).unwrap();
        let result = node.runtime().block_on(node.apply_initial_patch_bundle_durable_in(
            &request, &session("seed"), &reference, plan.commit, bundle.bytes(), Default::default(),
        )).unwrap();
        assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        Self { root, node: Some(node), format, reference, commit: plan.commit, lexical: None, symbols: None }
    }
    fn node(&self) -> &OneNode { self.node.as_ref().unwrap() }
    fn head(&self) -> Vec<u8> {
        self.node().runtime().block_on(self.node().authenticate_authority_head()).unwrap().receipt().body().to_vec()
    }
    fn build_lexical(&mut self) -> LexicalSource {
        let node = self.node();
        let request = node.request_context();
        let (source, generation) = node.runtime().block_on(node.build_source_index_local_in(
            &request, &self.reference, None, Some(self.commit),
            self.lexical.as_ref().map(|g| g.generation_id), Default::default(),
        )).unwrap();
        self.lexical = Some(generation);
        source
    }
    fn build_symbols(&mut self) {
        let node = self.node();
        let request = node.request_context();
        let (_, generation) = node.runtime().block_on(node.build_source_symbol_index_local_in(
            &request, &self.reference, None, Some(self.commit),
            self.symbols.as_ref().map(|g| g.generation_id), Default::default(),
        )).unwrap();
        self.symbols = Some(generation);
    }
    fn unrelated(&self, name: &str) {
        let node = self.node();
        let request = node.request_context();
        let result = node.runtime().block_on(node.admit_branch_updates_durable_in(
            &request, &session(name), &[RefCommand {
                name: RefName::try_new(format!("refs/heads/{name}").as_bytes()).unwrap(),
                expected_old: ExpectedOld::Absent, proposed_new: ProposedNew::Update(self.commit), force: false,
            }], Default::default(),
        )).unwrap();
        assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
    }
    fn query(&self, query: &InitialQuery, floors: &Checkpoints, limits: InitialLimits)
        -> Result<RevalidatedInitialReport, RetrievalError>
    {
        let node = self.node();
        node.runtime().block_on(node.search_source_initial_revalidated_local_in(
            &node.request_context(), &self.reference, None, Some(self.commit), floors, query, limits,
        ))
    }
    fn change_code(&mut self) {
        let node = self.node();
        let request = node.request_context();
        let patch = b"diff --git a/src/other.rs b/src/other.rs\n--- a/src/other.rs\n+++ b/src/other.rs\n@@ -1 +1,2 @@\n pub fn Thing() {}\n+// new bytes\n";
        let plan = node.runtime().block_on(node.prepare_trusted_patch_in(
            &request, &self.reference, self.commit, [0x64; 16], patch, &metadata(), Default::default(),
        )).unwrap();
        let result = node.runtime().block_on(node.apply_workspace_bundle_durable_in(
            &request, PrincipalId::from_bytes([0x63; 16]), b"change-code", &self.reference,
            self.commit, plan.candidate_commit, plan.bundle_bytes(),
        )).unwrap();
        assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        self.commit = plan.candidate_commit;
    }
    fn reopen(&mut self) {
        self.node.take().unwrap().shutdown().unwrap();
        let mut node = OneNode::open_existing(NodeConfig::new(self.root.join("node"),
            TenantId::from_bytes([0x61; 16]), RepositoryId::from_bytes([0x62; 16]))
            .with_object_format(self.format).with_worker_threads(2)).unwrap();
        let generation = node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().generation();
        node.bring_into_service(generation).unwrap();
        self.node = Some(node);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(node) = self.node.take() { node.shutdown().unwrap(); }
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn query(policy: Option<SymbolPolicy>) -> InitialQuery {
    let query = InitialQuery::new(&[b"THING".to_vec()], &[b"src".to_vec()]).unwrap();
    match policy {
        None => query,
        Some(policy) => query.with_symbols(b"Thing", SymbolMatchMode::Exact, &[SymbolKind::Function], policy).unwrap(),
    }
}

#[test]
fn differently_dated_indexes_join_to_current_source_without_relabelling_or_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format);
        let indexed = f.build_lexical();
        f.unrelated("between-indexes");
        f.build_symbols();
        f.unrelated("after-indexes");
        let before = f.head();
        let query = query(Some(SymbolPolicy::Required));
        let floors = Checkpoints { lexical: f.lexical.clone(), symbols: f.symbols.clone() };
        let result = f.query(&query, &floors, InitialLimits::default()).unwrap();
        assert_eq!(result.content().source, indexed);
        assert_eq!(result.path().source, indexed);
        assert_ne!(result.current_source().source_head, indexed.source_head);
        assert_eq!(result.current_source().commit, indexed.commit);
        assert_eq!(result.current_source().tree, indexed.tree);
        assert_eq!(result.content().results.hits.len(), 3);
        assert_eq!(result.path().results.hits.len(), 2);
        let SymbolChannel::Available(symbols) = result.symbols() else { panic!("symbols") };
        assert_eq!(symbols.matches.len(), 3);
        assert_ne!(symbols.source.head, indexed.source_head);
        assert_ne!(symbols.source.head, result.current_source().source_head);
        assert_eq!(result.generations().lexical, *f.lexical.as_ref().unwrap());
        assert_eq!(result.generations().symbols, f.symbols);
        assert!(result.complete());
        assert_eq!(f.head(), before);
        // The old exact-source contract has NOT been silently relaxed.
        let node = f.node();
        assert!(node.runtime().block_on(node.search_source_initial_local_in(
            &node.request_context(), &f.reference, None, None, &floors, &query, InitialLimits::default(),
        )).is_err());
        assert!(join_current(result.current_source(), &indexed).is_err());
        f.reopen();
        let reopened = f.query(&query, &floors, InitialLimits::default()).unwrap();
        assert_eq!(reopened.current_source(), result.current_source());
        assert_eq!(reopened.content().results, result.content().results);
        assert_eq!(reopened.generations(), result.generations());
        assert_eq!(f.head(), before);
    }
}

#[test]
fn optional_absence_is_not_a_complete_empty_symbol_answer_or_a_lost_floor() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256);
    f.build_lexical();
    let before = f.head();
    let optional = query(Some(SymbolPolicy::Optional));
    let report = f.query(&optional, &Checkpoints::default(), InitialLimits::default()).unwrap();
    assert!(matches!(report.symbols(), SymbolChannel::Unavailable(SymbolUnavailable::Uninitialized)));
    assert!(!report.complete());
    assert!(f.query(&query(Some(SymbolPolicy::Required)), &Checkpoints::default(), InitialLimits::default()).is_err());
    let floor = Checkpoints { lexical: None, symbols: f.lexical.clone() };
    assert!(f.query(&optional, &floor, InitialLimits::default()).is_err());
    assert!(f.query(&query(None), &floor, InitialLimits::default()).is_err());
    assert_eq!(f.head(), before);
}

#[test]
fn actual_source_changes_require_fresh_lexical_data_and_explicit_optional_symbol_status() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format);
        f.build_lexical();
        f.build_symbols();
        let optional = query(Some(SymbolPolicy::Optional));
        f.change_code();
        assert!(f.query(&optional, &Checkpoints::default(), InitialLimits::default()).is_err());
        f.build_lexical();
        let before = f.head();
        let report = f.query(&optional, &Checkpoints::default(), InitialLimits::default()).unwrap();
        assert!(matches!(report.symbols(), SymbolChannel::Unavailable(SymbolUnavailable::Stale)));
        assert!(!report.complete());
        let floor = Checkpoints { lexical: f.lexical.clone(), symbols: f.symbols.clone() };
        assert!(f.query(&optional, &floor, InitialLimits::default()).is_err());
        f.build_symbols();
        assert!(f.query(&optional, &Checkpoints::default(), InitialLimits::default()).unwrap().complete());
        assert_eq!(f.head(), before);
    }
}

#[test]
fn finite_channel_and_output_budgets_fail_without_partial_success_or_mutation() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256);
    f.build_lexical();
    f.build_symbols();
    let before = f.head();
    let query = query(Some(SymbolPolicy::Required));
    for limits in [
        InitialLimits { max_work: 2, ..Default::default() },
        InitialLimits { max_work: 3, ..Default::default() },
        InitialLimits { max_payload_bytes: 3, ..Default::default() },
        InitialLimits { max_result_bytes: 1, ..Default::default() },
    ] {
        assert!(f.query(&query, &Checkpoints::default(), limits).is_err());
        assert_eq!(f.head(), before);
    }
    let limit = InitialLimits { max_results_per_channel: 1, ..Default::default() };
    let report = f.query(&query, &Checkpoints::default(), limit).unwrap();
    assert!(!report.complete());
    assert!(!report.content().results.complete);
    assert!(!report.path().results.complete);
    assert!(report.completed_work_units() <= limit.max_work);
    assert!(report.completed_payload_bytes_read() <= limit.max_payload_bytes);
    assert!(report.result_bytes() <= limit.max_result_bytes);
    assert!(f.query(&query, &Checkpoints::default(), InitialLimits::default()).unwrap().complete());
    assert_eq!(f.head(), before);
}

#[test]
fn stale_source_pins_cancellation_and_unresolved_generation_floors_never_fallback() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha1);
    let original = f.build_lexical();
    f.unrelated("moved-head");
    let before = f.head();
    let query = query(None);
    let node = f.node();
    assert!(node.runtime().block_on(node.search_source_initial_revalidated_local_in(
        &node.request_context(), &f.reference, Some(original.source_head), Some(f.commit),
        &Checkpoints::default(), &query, InitialLimits::default(),
    )).is_err());
    let request = node.request_context();
    request.authority().cancel();
    assert!(node.runtime().block_on(node.search_source_initial_revalidated_local_in(
        &request, &f.reference, None, None, &Checkpoints::default(), &query, InitialLimits::default(),
    )).is_err());
    let mut unresolved = f.lexical.clone().unwrap();
    unresolved.authority_generation = HeadGeneration::try_new(unresolved.authority_generation.get() + 1).unwrap();
    assert!(f.query(&query, &Checkpoints { lexical: Some(unresolved), symbols: None }, InitialLimits::default()).is_err());
    assert!(f.query(&query, &Checkpoints::default(), InitialLimits::default()).unwrap().complete());
    assert_eq!(f.head(), before);
}
