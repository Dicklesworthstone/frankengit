//! Fixed Git bundle bytes generated independently with Python hashlib/zlib.
//! These tests exercise native verification, not the JavaScript utility.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

const SHA1_BUNDLE: &str = "23207632206769742062756e646c650a6365303133363235303330626138646261393036663735363936376639653963613339343436346120726566732f746167732f626c6f620a0a5041434b000000020000000136789ccb48cdc9c9e70200084b021fde0412401f4a9e5f05411f44eaf9c86d46096746";
const SHA1_SHA256: &str = "91008ee6b6e00b1a5eef830ba34830f89b2b39035987ec5ad1b34853ceb66a31";
const SHA256_BUNDLE: &str = "23207633206769742062756e646c650a406f626a6563742d666f726d61743d7368613235360a3263663864383364396565323935343362333461383737323734323166646563623765336633613138336433333736333930323564653537366462396562623420726566732f746167732f626c6f620a0a5041434b000000020000000136789ccb48cdc9c9e70200084b021fa3c5e2a560d25012da705ae0890a05c5c36957d4274db457f92b31bf33510557";
const SHA256_SHA256: &str = "8eda61a4ebb15dfab43ec950171b01bfef424fad6782a1d63a1f84ae40874d03";

fn bytes(encoded: &str) -> Vec<u8> {
    encoded.as_bytes().chunks_exact(2).map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}
fn args(values: &[&str]) -> Vec<String> { values.iter().map(|value| (*value).to_owned()).collect() }
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!("fg-native-bundle-{}-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&root).unwrap(); Self(root)
    }
    fn input(&self, data: &[u8]) -> PathBuf {
        let path = self.0.join("source.bundle"); std::fs::write(&path, data).unwrap(); path
    }
}
impl Drop for Directory { fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); } }

#[test]
fn independently_generated_sha1_and_sha256_bundles_reach_the_native_cli_report() {
    for (encoded, digest, format) in [(SHA1_BUNDLE, SHA1_SHA256, "sha1"), (SHA256_BUNDLE, SHA256_SHA256, "sha256")] {
        let directory = Directory::new(); let data = bytes(encoded); let path = directory.input(&data);
        let options = parse(&[path.to_str().unwrap().to_owned()]).unwrap();
        let report = execute(&options, &mut || true).unwrap();
        assert!(report.contains(&format!("\"artifact_sha256\":\"{digest}\"")));
        assert!(report.contains(&format!("\"object_format\":\"{format}\"")));
        assert!(report.contains("\"object_count\":1"));
        assert!(report.contains("\"object_graph_verified\":true"));
        assert!(report.contains("\"repository_opened\":false"));
        assert!(report.contains("\"repository_changed\":false"));
        assert!(report.contains("\"origin_authenticated\":false"));
        assert_eq!(std::fs::read(&path).unwrap(), data);
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    }
}
#[test]
fn no_storage_tenant_credentials_or_retry_keys_are_accepted_by_the_offline_command() {
    assert!(parse(&args(&["file.bundle"])).is_ok());
    for flag in ["--principal", "--key-stdin", "--idempotency-key", "--force", "--trusted-local"] {
        assert!(parse(&args(&["nonexistent.bundle", flag, "x"])).is_err());
    }
    assert!(parse(&args(&["storage", "tenant", "repository", "file.bundle"])).is_err());
}
#[test]
fn malformed_limits_fail_before_any_input_can_be_opened() {
    for value in ["0", "01", "-1", "1.5", "1e2", "9999999999999999999999999"] {
        for flag in ["--max-input-mib", "--max-expanded-mib", "--max-objects", "--max-refs", "--timeout-secs"] {
            assert!(parse(&args(&["missing.bundle", flag, value])).is_err());
        }
    }
    assert!(parse(&args(&["missing.bundle", "--max-input-mib", "129"])).is_err());
    assert!(parse(&args(&["missing.bundle", "--max-input-mib", "1", "--max-input-mib", "1"])).is_err());
    assert!(parse(&args(&["--max-refs"])).is_err());
}
#[test]
fn explicit_limits_control_both_native_pack_and_graph_work() {
    let options = parse(&args(&["file.bundle", "--max-input-mib", "2", "--max-expanded-mib", "3", "--max-objects", "4", "--max-refs", "5", "--timeout-secs", "6"])).unwrap();
    assert_eq!(options.limits.envelope.max_bundle_bytes, 2 * 1024 * 1024);
    assert_eq!(options.limits.pack.max_input_bytes, 2 * 1024 * 1024);
    assert_eq!(options.limits.pack.max_total_expanded_bytes, 3 * 1024 * 1024);
    assert_eq!(options.limits.graph.max_payload_bytes, 3 * 1024 * 1024);
    assert_eq!(options.limits.graph.max_objects, 4);
    assert_eq!(options.limits.envelope.max_references, 5);
    assert_eq!(options.timeout, Duration::from_secs(6));
}
#[test]
fn literal_dash_paths_are_not_reinterpreted_as_options() {
    let options = parse(&args(&["--", "--not-a-flag.bundle"])).unwrap();
    assert_eq!(options.path, PathBuf::from("--not-a-flag.bundle"));
    assert!(parse(&args(&["--"])).is_err());
    assert!(parse(&args(&[""])).is_err());
}
#[test]
fn oversized_empty_and_nonregular_files_are_refused_without_a_report() {
    let directory = Directory::new(); let path = directory.input(&[1, 2, 3]);
    assert!(read_input(&path, 2, &mut || true).is_err());
    assert!(read_input(&directory.0, 100, &mut || true).is_err());
    std::fs::write(&path, []).unwrap(); assert!(read_input(&path, 100, &mut || true).is_err());
}
#[cfg(unix)]
#[test]
fn symbolic_links_are_not_followed_by_the_offline_reader() {
    let directory = Directory::new(); let path = directory.input(&bytes(SHA1_BUNDLE));
    let link = directory.0.join("input-link"); std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(read_input(&link, 4096, &mut || true).is_err());
    assert!(read_input(&path, 4096, &mut || true).is_ok());
}
#[test]
fn cancelled_reads_and_changed_inputs_cannot_produce_a_success_report() {
    let directory = Directory::new(); let path = directory.input(&bytes(SHA1_BUNDLE));
    assert!(read_input(&path, 4096, &mut || false).is_err());
    let mut calls = 0;
    assert!(read_input(&path, 4096, &mut || {
        calls += 1;
        if calls == 3 { std::fs::write(&path, b"changed").unwrap(); }
        true
    }).is_err());
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
}
#[test]
fn corrupt_native_input_is_not_reported_as_a_verified_empty_repository() {
    let directory = Directory::new(); let mut data = bytes(SHA1_BUNDLE); *data.last_mut().unwrap() ^= 1;
    let path = directory.input(&data); let options = parse(&[path.to_str().unwrap().to_owned()]).unwrap();
    assert!(execute(&options, &mut || true).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), data);
}
