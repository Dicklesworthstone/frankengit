//! Kill a process owning the real node and progress, without either shutdown
//! or progress release. The ordinary operator must recover the exact candidate.
use super::*;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};
use fgit_node::NodeConfig;
use fgit_types::{RepositoryId, TenantId};

const CHILD_ROOT: &str = "FGIT_SYMBOL_CRASH_TEST_ROOT";
struct Process(Child);
impl Process {
    fn start(root: &Scratch, format: GitHashAlgorithm, phase: &str) -> Self {
        let mut child = Self(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash::native_owner_child", "--nocapture", "--test-threads=1"])
            .env(CHILD_ROOT, &root.0).env("FGIT_SYMBOL_CRASH_TEST_FORMAT", format.as_str())
            .env("FGIT_SYMBOL_CRASH_TEST_PHASE", phase).spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(90);
        while !root.0.join("owner-ready").exists() {
            assert!(child.0.try_wait().unwrap().is_none(), "native child exited before its durable boundary");
            assert!(Instant::now() < deadline, "native child did not reach the selected boundary");
            std::thread::sleep(Duration::from_millis(10));
        }
        child
    }
    fn kill(&mut self) {
        self.0.kill().unwrap();
        assert!(!self.0.wait().unwrap().success());
    }
}
impl Drop for Process {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}
fn binding(node: &OneNode, format: GitHashAlgorithm) -> State {
    State::new(format!("31313131313131313131313131313131 32323232323232323232323232323232 {} {} symbols1",
        node.repository_incarnation_id(), format.as_str()), &[REF.to_vec()]).unwrap()
}
fn checkpoint(root: &Path) -> Vec<u8> { fs::read(root.join("symbols/checkpoint")).unwrap() }

#[test]
fn native_owner_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else { return; };
    let root = PathBuf::from(root);
    let format = match std::env::var("FGIT_SYMBOL_CRASH_TEST_FORMAT").unwrap().as_str() {
        "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256,
        _ => panic!("invalid native child format"),
    };
    let config = NodeConfig::new(root.join("node"), TenantId::from_bytes([0x31; 16]),
        RepositoryId::from_bytes([0x32; 16])).with_object_format(format).with_worker_threads(2);
    let node = reopen(&config);
    let mut file = ProgressFile::open(&root.join("symbols"), true, binding(&node, format)).unwrap();
    file.state.begin_preparation(REF).unwrap(); file.save().unwrap();
    let phase = std::env::var("FGIT_SYMBOL_CRASH_TEST_PHASE").unwrap();
    if phase != "preparing" {
        assert!(phase == "published" || phase == "unpublished");
        let result = node.runtime().block_on(node.reconcile_source_symbol_index_guarded_local_in(
            &node.outbox_delivery_context(), &RefName::try_new(REF).unwrap(), None, None,
            Default::default(), Default::default(), &mut |candidate| {
                file.arm(REF, digest(candidate)).unwrap();
                if phase == "published" { Ok(()) } else { Err(NodeWorkspaceRefusal::WorkspaceCapacity) }
            }));
        match phase.as_str() {
            "published" => { assert!(result.is_ok()); drop(result); }, // Lose the activation acknowledgement.
            "unpublished" => assert!(matches!(result, Err(AccessError::Source(NodeWorkspaceRefusal::WorkspaceCapacity)))),
            _ => unreachable!(),
        }
        assert!(file.state.rows[REF].pending.is_some());
    }
    fs::write(root.join("owner-ready"), b"durable boundary reached").unwrap();
    // Keep BOTH native runtime/storage and progress alive until abrupt death.
    loop { std::thread::sleep(Duration::from_secs(1)); }
}

#[test]
fn killed_effect_free_preparation_resumes_and_builds_without_operator_file_edits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, base) = fixture(&root, format); let commit = add_source(&node, base);
        let canonical = generation(&node); let expected = binding(&node, format);
        node.shutdown().unwrap(); directory(&root, "symbols");
        let mut child = Process::start(&root, format, "preparing");
        assert!(State::decode(&checkpoint(&root.0), &expected).unwrap().rows[REF].preparing);
        child.kill();
        assert!(root.0.join("symbols/run.lock").is_file());
        let output = successful(worker(&root, format, "symbols", "resume", true));
        assert!(output.contains("\"state\":\"preparation_recovered\""));
        assert!(output.contains("\"state\":\"observed_current\""));
        let node = reopen(&config); let report = selected(&node).unwrap();
        assert_eq!(report.source.commit, commit); assert_eq!(report.matches.len(), 1);
        assert_eq!(report.generation_number, 1); assert_eq!(generation(&node), canonical);
        assert_no_lexical_index(&node); node.shutdown().unwrap();
        let saved = checkpoint(&root.0);
        successful(worker(&root, format, "symbols", "resume", true));
        assert_eq!(checkpoint(&root.0), saved);
    }
}

#[test]
fn killed_native_publications_recover_original_identity_and_unpublished_candidates_stay_pending() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for phase in ["published", "unpublished"] {
            let root = Scratch::new(); let config = root.config(format);
            let (node, base) = fixture(&root, format); let commit = add_source(&node, base);
            let canonical = generation(&node); let expected = binding(&node, format);
            node.shutdown().unwrap(); directory(&root, "symbols");
            let mut child = Process::start(&root, format, phase);
            let before = checkpoint(&root.0);
            let pending = State::decode(&before, &expected).unwrap().rows[REF].pending.unwrap();
            let marker = fs::read(root.0.join("symbols/run.lock")).unwrap();
            child.kill();
            assert_eq!(fs::read(root.0.join("symbols/run.lock")).unwrap(), marker);
            let output = worker(&root, format, "symbols", "resume", true);
            assert_eq!(output.status.success(), phase == "published", "{}", String::from_utf8_lossy(&output.stderr));
            let body = String::from_utf8(output.stdout).unwrap();
            assert!(!body.contains("observed_current"));
            let node = reopen(&config);
            if phase == "published" {
                assert!(body.contains("\"state\":\"recovered\""));
                let report = selected(&node).unwrap();
                assert_eq!(report.generation.digest().as_bytes(), pending.as_slice());
                assert_eq!(report.generation_number, 1); assert_eq!(report.source.commit, commit);
                assert_eq!(report.matches.len(), 1);
                let state = State::decode(&checkpoint(&root.0), &expected).unwrap();
                assert_eq!(state.rows[REF].floor.as_ref().unwrap().digest, pending);
                assert!(state.rows[REF].pending.is_none());
            } else {
                assert!(body.contains("\"state\":\"pending\""));
                assert!(matches!(selected(&node), Err(AccessError::Uninitialized)));
                assert_eq!(checkpoint(&root.0), before);
            }
            assert_eq!(generation(&node), canonical); assert_no_lexical_index(&node); node.shutdown().unwrap();
            let saved = checkpoint(&root.0);
            let again = worker(&root, format, "symbols", "resume", true);
            assert_eq!(again.status.success(), phase == "published");
            assert_eq!(checkpoint(&root.0), saved);
            assert!(!root.0.join("symbols/run.lock").exists());
            assert!(root.0.join("symbols/owner.lock").is_file());
        }
    }
}
