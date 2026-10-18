use super::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

fn options(extra: &[&str]) -> Options {
    let mut args = vec!["unused", "11111111111111111111111111111111", "22222222222222222222222222222222", "--trusted-local", "--all"];
    args.extend_from_slice(extra);
    parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).unwrap()
}
fn empty_node() -> (PathBuf, OneNode) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!("fg-sweep-unit-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    let options = options(&[]);
    let (mut node, _) = OneNode::init(NodeConfig::new(path.clone(), options.tenant, options.repository)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    (path, node)
}

#[test]
fn sweep_options_require_explicit_mode_and_fresh_start() {
    let base = ["unused", "11111111111111111111111111111111", "22222222222222222222222222222222", "--trusted-local"];
    let parse_extra = |extra: &[&str]| parse(&base.into_iter().chain(extra.iter().copied()).map(str::to_owned).collect::<Vec<_>>());
    assert!(parse_extra(&["--max-pages", "1"]).is_err());
    assert!(parse_extra(&["--max-sweep-bytes", "1"]).is_err());
    assert!(parse_extra(&["--all", "--all"]).is_err());
    for bad in ["0", "-1", "18446744073709551616"] {
        assert!(parse_extra(&["--all", "--max-pages", bad]).is_err());
        assert!(parse_extra(&["--all", "--max-sweep-bytes", bad]).is_err());
    }
    assert!(parse_extra(&["--all", "--max-pages", "1000001"]).is_err());
    assert!(parse_extra(&["--all", "--max-sweep-bytes", "17179869185"]).is_err());
    let token = format!("alg:1:{}", "ab".repeat(32));
    let oid = "12".repeat(20);
    assert!(parse_extra(&["--all", "--expected-head", &token, "--resume-after", &oid]).is_err());
    let options = options(&["--max-pages", "7", "--max-sweep-bytes", "123"]);
    assert_eq!(options.sweep.unwrap().pages, 7);
    assert_eq!(options.sweep.unwrap().payload_bytes, 123);
}

#[test]
fn expired_sweep_never_acquires_a_fresh_page_budget() {
    let options = options(&[]);
    let started = Instant::now().checked_sub(options.query.timeout).unwrap();
    let mut bytes = Vec::new();
    let result = drive(&options, &mut bytes, started, |_| panic!("expired sweep must not read a page"));
    assert!(result.unwrap_err().contains("deadline"));
    assert!(bytes.is_empty());
}

#[test]
fn progress_is_provisional_and_shutdown_failure_suppresses_terminal_certificate() {
    let (path, node) = empty_node();
    let options = options(&[]);
    let request = node.request_context();
    let mut bytes = Vec::new();
    let result = drive(&options, &mut bytes, Instant::now(), |query| {
        node.runtime().block_on(node.scrub_selected_objects_local_in(&request, query)).map_err(|error| error.to_string())
    });
    assert_eq!(result.as_ref().unwrap().checked, 0);
    let progress = String::from_utf8(bytes.clone()).unwrap();
    assert!(progress.contains("\"type\":\"repository_scrub_sweep_page\""));
    assert!(progress.contains("\"complete\":false"));
    assert!(progress.contains("\"page_complete\":false"));
    assert!(progress.contains("\"node_closed\":false"));
    assert!(finish(&mut bytes, &options, result, Some("injected shutdown refusal".into())).is_err());
    assert_eq!(String::from_utf8(bytes).unwrap(), progress);
    node.shutdown().unwrap();
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn cancelled_request_and_output_failure_produce_no_terminal_success() {
    struct FailedSink;
    impl Write for FailedSink {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> { Err(std::io::ErrorKind::BrokenPipe.into()) }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    let (path, node) = empty_node();
    let options = options(&[]);
    let request = node.request_context();
    let failed_sink = drive(&options, &mut FailedSink, Instant::now(), |query| {
        node.runtime().block_on(node.scrub_selected_objects_local_in(&request, query)).map_err(|error| error.to_string())
    });
    assert!(failed_sink.unwrap_err().contains("output failed"));
    request.cancel();
    let mut bytes = Vec::new();
    let cancelled = drive(&options, &mut bytes, Instant::now(), |query| {
        node.runtime().block_on(node.scrub_selected_objects_local_in(&request, query)).map_err(|error| error.to_string())
    });
    assert!(cancelled.is_err());
    assert!(bytes.is_empty());
    node.shutdown().unwrap();
    fs::remove_dir_all(path).unwrap();
}
