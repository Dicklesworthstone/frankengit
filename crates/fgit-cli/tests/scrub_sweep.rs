#![forbid(unsafe_code)]
//! Execute the real native fg against independently encoded five-object bundles.
//! No Git, Node, stand-in node, or alternate authority exists on these paths.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
const PRINCIPAL: &str = "33333333333333333333333333333333";
struct Fixture { root: PathBuf, format: &'static str, genesis: String }
impl Fixture {
    fn new(format: &'static str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!("fg-sweep-process-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let mut fixture = Self { root, format, genesis: String::new() };
        checked(fixture.run(&["init", "node", TENANT, REPOSITORY, format]), 0);
        let genesis = checked(fixture.scrub(&[]), 0);
        fixture.genesis = text(&genesis, "snapshot_token").to_owned();
        let hex = if format == "sha1" {
            include_str!("../../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex")
        } else {
            include_str!("../../../tests/fixtures/native_bundle_recovery/sha256.bundle.hex")
        };
        let bytes = hex.trim().as_bytes().chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect::<Vec<_>>();
        fs::write(fixture.root.join("input.bundle"), bytes).unwrap();
        checked(fixture.run(&["bundle", "import", "node", TENANT, REPOSITORY, "input.bundle", "--trusted-local", "--principal", PRINCIPAL,
            "--idempotency-key", "sweep-fixture", "--object-format", format]), 0);
        fixture
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_fg")).args(args).current_dir(&self.root)
            .env("PATH", self.root.join("no-executables")).env("HOME", &self.root).output().unwrap()
    }
    fn scrub(&self, extra: &[&str]) -> Output {
        let mut args = vec!["scrub", "node", TENANT, REPOSITORY, "--trusted-local", "--object-format", self.format];
        args.extend_from_slice(extra);
        self.run(&args)
    }
    fn bodies(&self) -> Vec<PathBuf> {
        let mut pending = vec![self.root.join("node")];
        let mut bodies = Vec::new();
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let kind = entry.file_type().unwrap();
                if kind.is_dir() { pending.push(entry.path()); }
                else if kind.is_file() && fs::read(entry.path()).unwrap().starts_with(b"FGOB") { bodies.push(entry.path()); }
            }
        }
        bodies.sort_by_key(|path| path.file_name().unwrap().to_owned());
        assert_eq!(bodies.len(), 5);
        bodies
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); }
}
fn checked(output: Output, code: i32) -> String {
    assert_eq!(output.status.code(), Some(code), "stdout: {}\nstderr: {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}
fn number(json: &str, key: &str) -> u64 {
    json.split_once(&format!("\"{key}\":")).unwrap().1.chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap()
}
fn text<'a>(json: &'a str, key: &str) -> &'a str {
    json.split_once(&format!("\"{key}\":\"")).unwrap().1.split_once('"').unwrap().0
}
fn pages_and_summary(output: &str, pages: usize) -> Vec<&str> {
    let lines = output.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), pages + 1, "{output}");
    for page in &lines[..pages] {
        assert_eq!(text(page, "type"), "repository_scrub_sweep_page");
        for key in ["page_complete", "complete", "all_selected_object_bytes_verified", "node_closed"] {
            assert!(page.contains(&format!("\"{key}\":false")), "premature success: {page}");
        }
    }
    let summary = lines[pages];
    assert_eq!(text(summary, "type"), "repository_scrub_sweep");
    assert_eq!(number(summary, "pages"), pages as u64);
    assert!(summary.contains("\"complete\":true"));
    assert!(summary.contains("\"node_closed\":true"));
    for page in &lines[..pages] { assert_eq!(text(page, "snapshot_token"), text(summary, "snapshot_token")); }
    lines
}

#[test]
fn full_scrub_sweep_covers_both_git_formats_once_and_preserves_single_page_behavior() {
    for format in ["sha1", "sha256"] {
        let fixture = Fixture::new(format);
        let before = checked(fixture.scrub(&[]), 0);
        assert_eq!(number(&before, "objects_checked"), 5);
        let output = checked(fixture.scrub(&["--all", "--max-page-objects", "1"]), 0);
        let lines = pages_and_summary(&output, 5);
        let summary = lines[5];
        for key in ["objects_checked", "objects_verified", "selected_objects"] { assert_eq!(number(summary, key), 5); }
        assert_eq!(number(summary, "finding_count"), 0);
        assert_eq!(number(summary, "payload_bytes_accounted"), number(&before, "payload_bytes_accounted"));
        assert_eq!(text(summary, "snapshot_token"), text(&before, "snapshot_token"));
        assert!(summary.contains("\"all_selected_object_bytes_verified\":true"));
        assert_eq!(checked(fixture.scrub(&["--all", "--max-page-objects", "1"]), 0), output);
        assert_eq!(checked(fixture.scrub(&[]), 0), before);
        let page = checked(fixture.scrub(&["--max-page-objects", "1"]), 4);
        assert_eq!(text(&page, "type"), "repository_scrub_page");
        assert!(page.contains("\"node_closed\":true"));
    }
}

#[test]
fn earlier_corruption_and_missing_objects_survive_a_clean_final_sweep_page() {
    for format in ["sha1", "sha256"] {
        let fixture = Fixture::new(format);
        let before = checked(fixture.scrub(&[]), 0);
        let bodies = fixture.bodies();
        fs::remove_file(&bodies[0]).unwrap();
        fs::write(&bodies[1], b"planted damaged native body").unwrap();
        let output = checked(fixture.scrub(&["--all", "--max-page-objects", "1", "--max-findings", "1"]), 3);
        let lines = pages_and_summary(&output, 5);
        assert_eq!(number(lines[4], "objects_verified"), 1, "last page deliberately healthy");
        assert_eq!(number(lines[5], "objects_checked"), 5);
        assert_eq!(number(lines[5], "objects_verified"), 3);
        assert_eq!(number(lines[5], "finding_count"), 2);
        assert!(lines[5].contains("\"all_selected_object_bytes_verified\":false"));
        assert_eq!(text(lines[5], "snapshot_token"), text(&before, "snapshot_token"));
        assert!(!bodies[0].exists());
        assert_eq!(fs::read(&bodies[1]).unwrap(), b"planted damaged native body");
    }
}

#[test]
fn sweep_page_and_cumulative_byte_limits_never_reset_or_emit_a_certificate() {
    let fixture = Fixture::new("sha256");
    let before = checked(fixture.scrub(&[]), 0);
    let total = number(&before, "payload_bytes_accounted").to_string();
    let output = checked(fixture.scrub(&["--all", "--max-page-objects", "1", "--max-sweep-bytes", &total]), 0);
    pages_and_summary(&output, 5);
    let capped = checked(fixture.scrub(&["--all", "--max-page-objects", "1", "--max-pages", "2"]), 2);
    assert_eq!(capped.lines().count(), 2);
    assert!(!capped.contains("\"type\":\"repository_scrub_sweep\""));
    assert!(!capped.contains("\"complete\":true"));
    let under = (number(&before, "payload_bytes_accounted") - 1).to_string();
    let refused = checked(fixture.scrub(&["--all", "--max-page-objects", "1", "--max-sweep-bytes", &under]), 2);
    assert!(!refused.contains("\"type\":\"repository_scrub_sweep\""));
    assert!(!refused.contains("\"complete\":true"));
    assert_eq!(checked(fixture.scrub(&[]), 0), before);
}

#[test]
fn sweep_rejects_stale_authority_and_caller_cursor_completeness_claims() {
    let fixture = Fixture::new("sha1");
    let old = checked(fixture.scrub(&["--all", "--expected-head", &fixture.genesis]), 2);
    assert!(old.is_empty());
    let page = checked(fixture.scrub(&["--max-page-objects", "1"]), 4);
    let head = text(&page, "snapshot_token");
    let cursor = text(&page, "after");
    let resumed = checked(fixture.scrub(&["--all", "--expected-head", head, "--resume-after", cursor]), 2);
    assert!(resumed.is_empty());
    let stable = checked(fixture.scrub(&["--all", "--expected-head", head]), 0);
    pages_and_summary(&stable, 1);
}
