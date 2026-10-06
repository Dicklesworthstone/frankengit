//! Real fg processes over persisted native fixtures. No external Git or regex oracle.
use fgit_authority::IdempotencyKey;
use fgit_forge::preparation::MergeMetadata;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId, TenantId};
use std::{fs, path::PathBuf, process::{Command, Output}, sync::atomic::{AtomicU64, Ordering}};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture { root: PathBuf, format: GitHashAlgorithm, commit: GitOid }
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!("fg-regex-cli-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let (mut node, _) = OneNode::init(NodeConfig::new(root.join("node"), TenantId::from_bytes([1;16]), RepositoryId::from_bytes([2;16]))
            .with_object_format(format).with_worker_threads(2)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let patch = format!("diff --git a/text b/text\nnew file mode 100644\n--- /dev/null\n+++ b/text\n@@ -0,0 +1,4 @@\n+abbb ab\n+AB\r\n+\n+last\n\\ No newline at end of file\ndiff --git a/long b/long\nnew file mode 100644\n--- /dev/null\n+++ b/long\n@@ -0,0 +1 @@\n+{}\n", "x".repeat(1000));
        let metadata = MergeMetadata { author: "A <a@example.invalid>".into(), committer: "C <c@example.invalid>".into(), timestamp: 1, message: b"seed\n".to_vec() };
        let request = node.request_context();
        let (_, plan, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(
            &request, &reference, patch.as_bytes(), &metadata, Default::default(), None,
        )).unwrap();
        let session = LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([3;16]), IdempotencyKey::new(b"regex-cli-seed".to_vec()).unwrap());
        let outcome = node.runtime().block_on(node.apply_initial_patch_bundle_durable_in(
            &request, &session, &reference, plan.commit, bundle.bytes(), Default::default(),
        )).unwrap();
        assert!(matches!(outcome.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        node.shutdown().unwrap();
        Self { root, format, commit: plan.commit }
    }
    fn search(&self, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_fg")).args(["--timeout-secs", "120", "search", "--regex"])
            .arg(self.root.join("node")).args(["01".repeat(16), "02".repeat(16), "refs/heads/main".into()])
            .args(["--trusted-local", "--object-format", self.format.as_str()]).args(extra).output().unwrap()
    }
}
impl Drop for Fixture { fn drop(&mut self) { fs::remove_dir_all(&self.root).unwrap(); } }
fn text(output: &Output, code: i32) -> String {
    assert_eq!(output.status.code(), Some(code), "{}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn actual_cli_selects_regex_and_preserves_bytes_across_fresh_processes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format);
        let first = f.search(&["--pattern", "ab+", "--ignore-ascii-case"]);
        let result = text(&first, 0);
        assert!(result.contains("\"match_count\":2"));
        assert!(result.contains("\"match_bytes_hex\":\"61626262\""));
        assert!(result.contains("\"excerpt_hex\":\"41420d\""));
        assert!(result.contains("\"node_closed\":true"));
        assert_eq!(first.stdout, f.search(&["--pattern", "ab+", "--ignore-ascii-case"]).stdout);
        let zero = text(&f.search(&["--pattern", "^$"]), 0);
        assert!(zero.contains("\"match_count\":1"));
        assert!(zero.contains("\"match_length\":0"));
        assert!(zero.contains("\"match_bytes_hex\":\"\""));
        let last = text(&f.search(&["--pattern", "last$", "--expected-commit", &f.commit.to_string()]), 0);
        assert!(last.contains("\"line\":4"));
        let long = text(&f.search(&["--pattern", "^x+$"]), 0);
        assert!(long.contains("\"match_length\":1000"));
        assert!(long.contains("\"match_fully_in_excerpt\":false,\"match_bytes_hex\":null"));
    }
}
#[test]
fn actual_cli_distinguishes_prefixes_zero_hits_invalid_queries_and_work_exhaustion() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format);
        let prefix = text(&f.search(&["--pattern", ".*", "--max-matches", "1"]), 3);
        assert!(prefix.contains("\"complete\":false"));
        let empty = text(&f.search(&["--pattern", "no_such_text"]), 0);
        assert!(empty.contains("\"complete\":true")); assert!(empty.contains("\"match_count\":0"));
        for extra in [vec!["--pattern", "(?=x)"], vec!["--pattern", "x", "--max-regex-steps", "1"],
            vec!["--pattern", "x", "--expected-head", "alg:1:00"], vec!["--pattern", "x", "--literal", "x"]] {
            let result = f.search(&extra);
            assert_eq!(result.status.code(), Some(2));
            assert!(result.stdout.is_empty());
        }
    }
}
