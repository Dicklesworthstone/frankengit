//! Persisted native symbol tables, reopen and real MCP messages in both Git
//! hash domains. No fake search results, Git subprocess or implicit build.
use super::super::super::super::super::protocol::{ReadTools, Server};
use super::*;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_forge::preparation::MergeMetadata;
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, PrincipalId, TenantId};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0xc3; 16])
}
fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "Symbols <symbols@example.invalid>".into(),
        committer: "Symbols <symbols@example.invalid>".into(),
        timestamp: 1,
        message: b"persisted MCP symbol fixture\n".to_vec(),
    }
}
fn build(node: &OneNode, previous: Option<&GenerationActivation>) -> GenerationActivation {
    node.runtime()
        .block_on(node.build_source_symbol_index_local_in(
            &node.outbox_delivery_context(),
            &reference(),
            None,
            None,
            previous.map(|activation| activation.generation_id),
            Default::default(),
        ))
        .unwrap()
        .1
}
fn seeded(format: GitHashAlgorithm, indexed: bool, partial: bool) -> (Scratch, NodeTools, GitOid) {
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "fg-mcp-indexed-symbols-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    fs::create_dir(&scratch.0).unwrap();
    let tenant = TenantId::from_bytes([0xc1; 16]);
    let repository = RepositoryId::from_bytes([0xc2; 16]);
    let (mut node, _) = OneNode::init(
        NodeConfig::new(scratch.0.join("node"), tenant, repository)
            .with_object_format(format)
            .with_worker_threads(2),
    )
    .unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let mut patch = String::new();
    let mut files = vec![
        (
            "src/a.rs",
            "pub fn alpha() {}\nstruct alphabet;\nfn r#type() {}\n",
        ),
        (
            "src/b.rs",
            "fn alpha_worker() {}\nmacro_rules! make { () => { fn alpha_generated() {} }; }\n",
        ),
        ("src2/c.rs", "fn alpha_other() {}\n"),
        ("notes.txt", "fn alpha() is not Rust here\n"),
    ];
    if partial {
        files.push(("bad.rs", "fn broken(\n"));
    }
    for (path, bytes) in files {
        let lines = bytes.lines().count();
        patch.push_str(&format!("diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{lines} @@\n"));
        for line in bytes.lines() {
            patch.push_str(&format!("+{line}\n"));
        }
    }
    let request = node.request_context();
    let (_, plan, bundle) = node
        .runtime()
        .block_on(node.prepare_trusted_initial_patch_in(
            &request,
            &reference(),
            patch.as_bytes(),
            &metadata(),
            Default::default(),
            None,
        ))
        .unwrap();
    let commit = plan.commit;
    let accepted = node
        .runtime()
        .block_on(node.apply_initial_patch_bundle_durable_in(
            &request,
            &LoopbackReceiveSession::authenticated(
                principal(),
                IdempotencyKey::new(b"indexed-symbols-initial".to_vec()).unwrap(),
            ),
            &reference(),
            commit,
            bundle.bytes(),
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        accepted.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    if indexed {
        build(&node, None);
    }
    let incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    let backend = NodeTools::open(Options {
        storage: scratch.0.join("node"),
        tenant,
        repository,
        format,
        incarnation: Some(incarnation),
        issues: false,
        discussions: false,
        pulls: false,
        source: true,
        writes: Default::default(),
        outcomes: false,
        principal: None,
        queues: Default::default(),
        agent_context: false,
        artifacts: false,
        artifact_root: None,
        agent_token_file: None,
        max_messages: 64,
        index_maintenance: None,
    })
    .unwrap();
    (scratch, backend, commit)
}
fn query(mode: &str) -> Object {
    let Value::Object(args) = object([
        ("reference", text("refs/heads/main")),
        ("name", text("alpha")),
        ("match", text("prefix")),
        ("source_mode", text(mode)),
    ]) else {
        unreachable!()
    };
    args
}
fn rows(value: &Value) -> &[Value] {
    let Value::Array(rows) = value else {
        panic!("expected array")
    };
    rows
}
fn head_bytes(backend: &NodeTools) -> Vec<u8> {
    backend
        .node
        .runtime()
        .block_on(backend.node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .body()
        .to_vec()
}
fn protocol_call(backend: &mut NodeTools, args: Object) -> Value {
    let mut server = Server::new(backend).unwrap();
    server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"persisted-symbol-test","version":"1"}}}"#).unwrap();
    server.receive(
        backend,
        br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    let wire = object([
        ("jsonrpc", text("2.0")),
        ("id", json::number(2)),
        ("method", text("tools/call")),
        (
            "params",
            object([("name", text(NAME)), ("arguments", Value::Object(args))]),
        ),
    ])
    .encode(json::MAX_INPUT)
    .unwrap();
    let response = server.receive(backend, wire.as_bytes()).unwrap();
    let result = response.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(false), "{response:?}");
    result["structuredContent"].clone()
}
fn advance_metadata(backend: &NodeTools, commit: GitOid) {
    let accepted = backend
        .node
        .runtime()
        .block_on(backend.node.admit_branch_updates_durable_in(
            &backend.node.request_context(),
            &LoopbackReceiveSession::authenticated(
                principal(),
                IdempotencyKey::new(b"indexed-symbols-other-ref".to_vec()).unwrap(),
            ),
            &[RefCommand {
                name: RefName::try_new(b"refs/heads/unrelated").unwrap(),
                expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(commit),
                force: false,
            }],
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        accepted.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}
fn advance_source(backend: &NodeTools, commit: GitOid) -> GitOid {
    let node = &backend.node;
    let request = node.request_context();
    let prepared = node.runtime().block_on(node.prepare_trusted_patch_in(
        &request, &reference(), commit, [0xc4; 16],
        b"diff --git a/src/new.rs b/src/new.rs\nnew file mode 100644\n--- /dev/null\n+++ b/src/new.rs\n@@ -0,0 +1 @@\n+fn alpha_new() {}\n",
        &metadata(), Default::default(),
    )).unwrap();
    let accepted = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &request,
            principal(),
            b"indexed-symbols-source-change",
            &reference(),
            commit,
            prepared.candidate_commit,
            prepared.bundle_bytes(),
        ))
        .unwrap();
    assert!(matches!(
        accepted.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    prepared.candidate_commit
}

#[test]
fn persisted_symbol_modes_match_scans_without_source_blob_reads_and_survive_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend, commit) = seeded(format, true, false);
        let before = head_bytes(&backend);
        let mut default = query("scan");
        default.remove("source_mode");
        let scanned = backend.call(NAME, &default).unwrap();
        assert_eq!(backend.call(NAME, &query("scan")).unwrap(), scanned);
        assert_eq!(rows(&scanned.object().unwrap()["matches"]).len(), 4);
        let mut saved = None;
        for mode in ["indexed-exact", "indexed-current"] {
            let result = protocol_call(&mut backend, query(mode));
            let fields = result.object().unwrap();
            assert_eq!(fields["source_mode"].text(), Some(mode));
            assert_eq!(
                fields["source_commit"].text(),
                Some(commit.to_string().as_str())
            );
            assert_eq!(fields["matches"], scanned.object().unwrap()["matches"]);
            assert_eq!(fields["complete"], Value::Bool(true));
            assert_eq!(fields["coverage_complete"], Value::Bool(true));
            assert_eq!(fields["distinct_provenance"], Value::Bool(false));
            assert!(rows(&fields["omissions"]).is_empty());
            for field in ["source_blobs_read", "source_bytes_read"] {
                assert_eq!(fields[field].text(), Some("0"));
            }
            for field in [
                "repository_changed",
                "index_changed",
                "transaction_created",
                "published",
                "pagination_supported",
            ] {
                assert_eq!(fields[field], Value::Bool(false), "{field}");
            }
            let mut limited = query(mode);
            limited.insert("max_matches".into(), json::number(2));
            let limited = backend.call(NAME, &limited).unwrap();
            let limited = limited.object().unwrap();
            assert_eq!(limited["complete"], Value::Bool(false));
            assert_eq!(limited["truncated_reason"].text(), Some("match_limit"));
            assert_eq!(limited["match_count"].text(), Some("2"));
            assert_eq!(limited["coverage_complete"], Value::Bool(true));
            let mut scoped = query(mode);
            scoped.insert(
                "path_prefixes_hex".into(),
                Value::Array(vec![text(hex(b"src"))]),
            );
            scoped.insert("kinds".into(), Value::Array(vec![text("function")]));
            let scoped = backend.call(NAME, &scoped).unwrap();
            assert_eq!(scoped.object().unwrap()["match_count"].text(), Some("2"));
            let mut exact = query(mode);
            exact.insert("match".into(), text("exact"));
            assert_eq!(
                backend.call(NAME, &exact).unwrap().object().unwrap()["match_count"].text(),
                Some("1")
            );
            exact.insert("name".into(), text("type"));
            let raw = backend.call(NAME, &exact).unwrap();
            assert_eq!(
                rows(&raw.object().unwrap()["matches"])[0].object().unwrap()["raw_identifier"],
                Value::Bool(true)
            );
            exact.insert("name".into(), text("does_not_exist"));
            let empty = backend.call(NAME, &exact).unwrap();
            assert!(rows(&empty.object().unwrap()["matches"]).is_empty());
            assert_eq!(empty.object().unwrap()["complete"], Value::Bool(true));
            saved = Some(result);
        }
        assert_eq!(head_bytes(&backend), before);
        let options = backend.options.clone();
        backend.close().unwrap();
        let mut backend = NodeTools::open(options).unwrap();
        assert_eq!(
            backend.call(NAME, &query("indexed-current")).unwrap(),
            saved.unwrap()
        );
        assert_eq!(head_bytes(&backend), before);
        backend.close().unwrap();
    }
}

#[test]
fn current_mode_revalidates_metadata_but_refuses_changed_source_until_explicit_native_refresh() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend, commit) = seeded(format, true, false);
        let first = backend.call(NAME, &query("indexed-current")).unwrap();
        let first = first.object().unwrap();
        let mut floor = query("indexed-current");
        floor.insert("minimum_index_token".into(), first["index_token"].clone());
        floor.insert("minimum_index_number".into(), first["index_number"].clone());
        let activation = input::parse(&floor, format).unwrap().minimum.unwrap();
        advance_metadata(&backend, commit);
        let before = head_bytes(&backend);
        assert_eq!(
            backend
                .call(NAME, &query("indexed-exact"))
                .unwrap_err()
                .code,
            "symbol_index_stale"
        );
        let current = backend.call(NAME, &floor).unwrap();
        let current = current.object().unwrap();
        for field in [
            "source_commit",
            "source_tree",
            "index_token",
            "index_number",
            "matches",
        ] {
            assert_eq!(current[field], first[field]);
        }
        assert_ne!(current["snapshot_token"], first["snapshot_token"]);
        assert_eq!(current["distinct_provenance"], Value::Bool(true));
        assert_eq!(
            current["indexed_source"].object().unwrap()["snapshot_token"],
            first["snapshot_token"]
        );
        assert_eq!(
            current["current_source"].object().unwrap()["snapshot_token"],
            current["snapshot_token"]
        );
        let mut pinned = floor.clone();
        pinned.insert("expected_head".into(), first["snapshot_token"].clone());
        assert!(backend.call(NAME, &pinned).is_err());
        pinned.insert("expected_head".into(), current["snapshot_token"].clone());
        pinned.insert("expected_commit".into(), current["source_commit"].clone());
        assert!(backend.call(NAME, &pinned).is_ok());
        assert_eq!(head_bytes(&backend), before);
        let changed = advance_source(&backend, commit);
        let before = head_bytes(&backend);
        for mode in ["indexed-exact", "indexed-current"] {
            assert_eq!(
                backend.call(NAME, &query(mode)).unwrap_err().code,
                "symbol_index_stale"
            );
        }
        assert_eq!(head_bytes(&backend), before);
        let next = build(&backend.node, Some(&activation));
        assert!(next.authority_generation.get() > activation.authority_generation.get());
        let refreshed = backend.call(NAME, &floor).unwrap();
        let refreshed = refreshed.object().unwrap();
        assert_eq!(
            refreshed["source_commit"].text(),
            Some(changed.to_string().as_str())
        );
        assert_eq!(refreshed["match_count"].text(), Some("5"));
        assert_ne!(refreshed["index_token"], first["index_token"]);
        assert_eq!(refreshed["minimum_index_token"], first["index_token"]);
        assert_eq!(head_bytes(&backend), before);
        backend.close().unwrap();
    }
}

#[test]
fn partial_coverage_is_explicit_even_for_a_complete_narrowed_query() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend, _) = seeded(format, true, true);
        assert_eq!(
            backend.call(NAME, &query("scan")).unwrap_err().code,
            "unsupported_rust_source"
        );
        let before = head_bytes(&backend);
        let mut args = query("indexed-current");
        args.insert(
            "path_prefixes_hex".into(),
            Value::Array(vec![text(hex(b"src"))]),
        );
        let result = protocol_call(&mut backend, args);
        let result = result.object().unwrap();
        assert_eq!(result["complete"], Value::Bool(true));
        assert_eq!(result["coverage_complete"], Value::Bool(false));
        assert_eq!(result["match_count"].text(), Some("3"));
        assert_eq!(result["omitted_files"].text(), Some("1"));
        assert_eq!(
            result["index_profile"].text(),
            Some(data::OMISSION_INDEX_PROFILE)
        );
        let omission = rows(&result["omissions"])[0].object().unwrap();
        assert_eq!(omission["path_hex"].text(), Some(hex(b"bad.rs").as_str()));
        assert_eq!(omission["reason"].text(), Some("unbalanced_delimiter"));
        assert_eq!(omission["source_bytes"].text(), Some("11"));
        assert_eq!(head_bytes(&backend), before);
        backend.close().unwrap();
    }
}

#[test]
fn absent_indexes_floors_and_read_limits_refuse_without_fallback_or_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend, _) = seeded(format, false, false);
        let before = head_bytes(&backend);
        for _ in 0..2 {
            assert_eq!(
                backend
                    .call(NAME, &query("indexed-current"))
                    .unwrap_err()
                    .code,
                "symbol_index_uninitialized"
            );
        }
        assert_eq!(head_bytes(&backend), before);
        assert!(backend.call(NAME, &query("scan")).is_ok());
        let activation = build(&backend.node, None);
        let result = backend.call(NAME, &query("indexed-current")).unwrap();
        let result = result.object().unwrap();
        let mut floor = query("indexed-current");
        floor.insert("minimum_index_token".into(), result["index_token"].clone());
        floor.insert(
            "minimum_index_number".into(),
            result["index_number"].clone(),
        );
        assert!(backend.call(NAME, &floor).is_ok());
        floor.insert(
            "minimum_index_number".into(),
            text((activation.authority_generation.get() + 1).to_string()),
        );
        assert_eq!(
            backend.call(NAME, &floor).unwrap_err().code,
            "symbol_index_generation_unavailable"
        );
        floor.insert(
            "minimum_index_number".into(),
            result["index_number"].clone(),
        );
        floor.insert(
            "minimum_index_token".into(),
            text(format!("alg:2:{}", "a".repeat(64))),
        );
        assert_eq!(
            backend.call(NAME, &floor).unwrap_err().code,
            "symbol_index_generation_unavailable"
        );
        let before = head_bytes(&backend);
        for field in [
            "max_payload_bytes",
            "max_work",
            "max_file_bytes",
            "max_total_bytes",
            "max_files",
        ] {
            let mut tiny = query("indexed-current");
            tiny.insert(field.into(), json::number(1));
            assert_eq!(
                backend.call(NAME, &tiny).unwrap_err().code,
                "resource_limit",
                "{field}"
            );
        }
        let mut wrong = query("indexed-current");
        wrong.insert(
            "expected_commit".into(),
            text("ab".repeat(format.digest_len())),
        );
        assert!(backend.call(NAME, &wrong).is_err());
        wrong = query("indexed-current");
        wrong.insert("reference".into(), text("refs/heads/missing"));
        assert!(backend.call(NAME, &wrong).is_err());
        assert_eq!(head_bytes(&backend), before);
        assert!(backend.call(NAME, &query("indexed-current")).is_ok());
        backend.close().unwrap();
    }
}

#[test]
fn source_writes_or_sponsored_profiles_do_not_grant_the_trusted_local_index_modes() {
    let (_scratch, mut backend, _) = seeded(GitHashAlgorithm::Sha1, true, false);
    let before = head_bytes(&backend);
    backend.options.source = false;
    backend.options.writes.source = true;
    assert_eq!(
        super::call(&backend, &Object::new()).unwrap_err().code,
        "tool_not_granted"
    );
    assert_eq!(
        super::super::call(&backend, &query("indexed-current"))
            .unwrap_err()
            .code,
        "tool_not_granted"
    );
    backend.options.source = true;
    backend.options.agent_token_file = Some(PathBuf::from("must-not-open"));
    assert_eq!(
        super::call(&backend, &Object::new()).unwrap_err().code,
        "tool_not_granted"
    );
    for mode in ["indexed-current", "indexed-exact"] {
        assert_eq!(
            super::super::call(&backend, &query(mode)).unwrap_err().code,
            "tool_not_granted"
        );
    }
    backend.options.agent_token_file = None;
    backend.options.writes.source = false;
    assert_eq!(head_bytes(&backend), before);
    assert!(backend.call(NAME, &query("indexed-current")).is_ok());
    backend.close().unwrap();
}
