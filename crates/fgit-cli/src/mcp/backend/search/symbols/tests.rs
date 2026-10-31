//! Argument contract plus one persisted node per hash domain. No index, no
//! compiler, no Git subprocess.
use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::preparation::MergeMetadata;
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, TenantId};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

fn args<const N: usize>(values: [(&str, Value); N]) -> Object {
    let Value::Object(value) = object(values) else {
        unreachable!()
    };
    value
}
fn base() -> Object {
    args([
        ("reference", text("refs/heads/main")),
        ("name", text("alpha")),
    ])
}
fn code(args: &Object) -> &'static str {
    parse(args, GitHashAlgorithm::Sha1)
        .err()
        .expect("the arguments must be refused")
        .code
}

#[test]
fn names_modes_and_kinds_are_closed_with_permitted_twins() {
    let (_, query) = parse(&base(), GitHashAlgorithm::Sha1).unwrap();
    assert_eq!(query.name(), b"alpha");
    assert_eq!(query.mode(), SymbolMatchMode::Exact);
    assert!(query.kinds().is_empty());
    assert_eq!(query.maximum_work(), MAX_SYMBOL_WORK);
    let mut prefix = base();
    prefix.insert("match".into(), text("prefix"));
    prefix.insert(
        "kinds".into(),
        Value::Array(vec![text("struct"), text("function")]),
    );
    let (_, query) = parse(&prefix, GitHashAlgorithm::Sha1).unwrap();
    assert_eq!(query.mode(), SymbolMatchMode::Prefix);
    assert_eq!(query.kinds().len(), 2);
    for bad in ["1alpha", "al-pha", "r#alpha", "", "αlpha"] {
        let mut name = base();
        name.insert("name".into(), text(bad));
        assert_eq!(code(&name), "invalid_symbol_query", "{bad:?}");
    }
    let mut mode = base();
    mode.insert("match".into(), text("regex"));
    assert_eq!(code(&mode), "invalid_match_mode");
    for kinds in [
        Value::Array(vec![text("impl")]),
        Value::Array(vec![json::number(1)]),
        text("function"),
        Value::Array(vec![text("function"); 9]),
    ] {
        let mut bad = base();
        bad.insert("kinds".into(), kinds);
        assert_eq!(code(&bad), "invalid_symbol_kinds");
    }
    let mut missing = base();
    missing.remove("name");
    assert_eq!(code(&missing), "name_required");
}

#[test]
fn literal_only_and_unknown_arguments_are_refused() {
    for field in ["needle_hex", "ignore_ascii_case", "operation", "pattern"] {
        let mut bad = base();
        bad.insert(field.into(), text("x"));
        assert_eq!(code(&bad), "unknown_argument", "{field}");
    }
    for (field, value) in [
        ("max_work", 0),
        ("max_work", MAX_SYMBOL_WORK + 1),
        ("max_matches", 0),
        ("max_matches", 101),
    ] {
        let mut bad = base();
        bad.insert(field.into(), json::number(value));
        assert_eq!(code(&bad), "invalid_limit", "{field}={value}");
    }
    let mut work = base();
    work.insert("max_work".into(), json::number(1));
    assert_eq!(
        parse(&work, GitHashAlgorithm::Sha1)
            .unwrap()
            .1
            .maximum_work(),
        1
    );
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn seeded(format: GitHashAlgorithm, patch: &[u8]) -> (Scratch, NodeTools) {
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "fg-mcp-symbols-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    fs::create_dir(&scratch.0).unwrap();
    let tenant = TenantId::from_bytes([0xb1; 16]);
    let repository = RepositoryId::from_bytes([0xb2; 16]);
    let (mut node, _) = OneNode::init(
        NodeConfig::new(scratch.0.join("node"), tenant, repository)
            .with_object_format(format)
            .with_worker_threads(2),
    )
    .unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let metadata = MergeMetadata {
        author: "A <a@example.invalid>".into(),
        committer: "C <c@example.invalid>".into(),
        timestamp: 1,
        message: b"symbols\n".to_vec(),
    };
    let request = node.request_context();
    let (_, plan, bundle) = node
        .runtime()
        .block_on(node.prepare_trusted_initial_patch_in(
            &request,
            &reference,
            patch,
            &metadata,
            Default::default(),
            None,
        ))
        .unwrap();
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xb3; 16]),
        IdempotencyKey::new(b"symbols-initial".to_vec()).unwrap(),
    );
    let accepted = node
        .runtime()
        .block_on(node.apply_initial_patch_bundle_durable_in(
            &request,
            &session,
            &reference,
            plan.commit,
            bundle.bytes(),
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        accepted.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    let backend = NodeTools::open(Options {
        storage: scratch.0.join("node"),
        tenant,
        repository,
        format,
        incarnation: Some(incarnation),
        issues: false,
        pulls: false,
        source: true,
        writes: Default::default(),
        outcomes: false,
        principal: None,
        queues: Default::default(),
        agent_context: false,
        artifacts: false,
        artifact_root: None,
        max_messages: 16,
    })
    .unwrap();
    (scratch, backend)
}

const PATCH: &[u8] = b"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,5 @@
+pub fn alpha() {}
+struct AlphaBeta;
+enum Gamma {}
+#[cfg(test)]
+fn alpha_test() { alpha(); }
diff --git a/notes.txt b/notes.txt
new file mode 100644
--- /dev/null
+++ b/notes.txt
@@ -0,0 +1 @@
+fn alpha() is mentioned here but this is not Rust
";

fn names(value: &Value) -> Vec<(String, String)> {
    let Value::Array(rows) = &value.object().unwrap()["matches"] else {
        panic!("matches must be an array")
    };
    rows.iter()
        .map(|row| {
            let row = row.object().unwrap();
            (
                row["name"].text().unwrap().to_owned(),
                row["kind"].text().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn persisted_sha1_and_sha256_declarations_are_pinned_exact_and_read_only() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend) = seeded(format, PATCH);
        assert!(!backend.is_mutation(NAME));
        assert!(backend.tools().iter().any(|tool| tool.name == NAME));
        let exact = backend.call(NAME, &base()).unwrap();
        // Only the .rs declaration; the text file's "fn alpha" is not Rust.
        assert_eq!(names(&exact), vec![("alpha".into(), "function".into())]);
        let page = exact.object().unwrap();
        assert_eq!(page["complete"], Value::Bool(true));
        assert_eq!(page["read_only"], Value::Bool(true));
        assert_eq!(page["repository_changed"], Value::Bool(false));
        assert_eq!(page["unsupported_language_files"].text(), Some("1"));
        let Value::Array(rows) = &page["matches"] else {
            unreachable!()
        };
        let row = rows[0].object().unwrap();
        assert_eq!(row["path_hex"].text(), Some(hex(b"src/lib.rs").as_str()));
        assert_eq!(row["line"].text(), Some("1"));

        // Prefix mode finds every declaration whose name starts with alpha;
        // the kind filter narrows it without changing the snapshot.
        let mut prefix = base();
        prefix.insert("match".into(), text("prefix"));
        prefix.insert("expected_head".into(), page["snapshot_token"].clone());
        prefix.insert("expected_commit".into(), page["source_commit"].clone());
        let all = backend.call(NAME, &prefix).unwrap();
        assert_eq!(
            names(&all),
            vec![
                ("alpha".into(), "function".into()),
                ("alpha_test".into(), "function".into())
            ]
        );
        let mut capital = prefix.clone();
        capital.insert("name".into(), text("Alpha"));
        capital.insert("kinds".into(), Value::Array(vec![text("struct")]));
        assert_eq!(
            names(&backend.call(NAME, &capital).unwrap()),
            vec![("AlphaBeta".into(), "struct".into())]
        );

        // A match ceiling is an explicitly incomplete prefix, not an answer.
        let mut limited = prefix.clone();
        limited.insert("max_matches".into(), json::number(1));
        let truncated = backend.call(NAME, &limited).unwrap();
        assert_eq!(truncated.object().unwrap()["complete"], Value::Bool(false));
        assert_eq!(
            truncated.object().unwrap()["truncated_reason"].text(),
            Some("match_limit")
        );

        // Path scope narrows reads; an absent name is a complete empty answer.
        let mut elsewhere = prefix.clone();
        elsewhere.insert(
            "path_prefixes_hex".into(),
            Value::Array(vec![text(hex(b"tests"))]),
        );
        assert!(names(&backend.call(NAME, &elsewhere).unwrap()).is_empty());
        let mut absent = base();
        absent.insert("name".into(), text("delta"));
        let none = backend.call(NAME, &absent).unwrap();
        assert!(names(&none).is_empty());
        assert_eq!(none.object().unwrap()["complete"], Value::Bool(true));

        // A pin to a different commit refuses rather than answering elsewhere.
        let mut wrong = base();
        let other = if format == GitHashAlgorithm::Sha1 {
            "11".repeat(20)
        } else {
            "11".repeat(32)
        };
        wrong.insert("expected_commit".into(), text(other));
        assert!(backend.call(NAME, &wrong).is_err());
    }
}

#[test]
fn malformed_rust_refuses_instead_of_answering_empty() {
    let broken: &[u8] = b"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1 @@
+pub fn alpha( {
";
    let (_scratch, mut backend) = seeded(GitHashAlgorithm::Sha1, broken);
    assert_eq!(
        backend.call(NAME, &base()).unwrap_err().code,
        "unsupported_rust_source"
    );
}
