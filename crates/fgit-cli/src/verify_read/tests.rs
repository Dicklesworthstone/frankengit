use super::*;
use std::net::TcpListener;
use std::thread;
use std::time::Duration;
mod fixture;

struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fg-verify-read-command-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn proof_options(format: fgit_types::GitHashAlgorithm) -> (Options, Vec<u8>) {
    proof_options_with_bytes(format, b"\0\xffexact bytes\r\n")
}

fn proof_options_with_bytes(
    format: fgit_types::GitHashAlgorithm,
    bytes: &[u8],
) -> (Options, Vec<u8>) {
    let envelope = fixture::envelope(format, bytes);
    let mut args = arguments();
    args[3] = head_token(fgit_authority::authority_head_identity(envelope.head()).unwrap());
    args[7] = "file".into();
    (
        options::parse(&args).unwrap(),
        fgit_verified_read::blob::encode_verified_blob_envelope(&envelope).unwrap(),
    )
}

#[test]
fn complete_proofs_emit_exact_bytes_and_create_only_verified_files_in_both_domains() {
    for format in [
        fgit_types::GitHashAlgorithm::Sha1,
        fgit_types::GitHashAlgorithm::Sha256,
    ] {
        let (mut options, proof) = proof_options(format);
        let mut output = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        publish_verified(&options, &proof, deadline, &mut output).unwrap();
        assert_eq!(output, b"\0\xffexact bytes\r\n");
        let scratch = Scratch::new();
        let path = scratch.0.join("verified.bin");
        options.output = Some(path.clone());
        output.clear();
        publish_verified(&options, &proof, deadline, &mut output).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"\0\xffexact bytes\r\n");
        assert!(
            String::from_utf8(output.clone())
                .unwrap()
                .contains("\"verified\":true")
        );
        let failure = publish_verified(&options, &proof, deadline, &mut Vec::new()).unwrap_err();
        assert!(failure.verified);
        assert_eq!(failure.output_state, "not_published");
        assert_eq!(std::fs::read(&path).unwrap(), b"\0\xffexact bytes\r\n");
        options.output = Some(scratch.0.join("tampered.bin"));
        let mut tampered = proof.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let failure = publish_verified(&options, &tampered, deadline, &mut Vec::new()).unwrap_err();
        assert!(!failure.verified);
        assert!(!options.output.unwrap().exists());
    }
}

struct BrokenOutput;
impl Write for BrokenOutput {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct FlushBrokenOutput(Vec<u8>);
impl Write for FlushBrokenOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

#[test]
fn failed_receipt_preserves_verified_and_published_status() {
    let scratch = Scratch::new();
    let (mut options, proof) = proof_options(fgit_types::GitHashAlgorithm::Sha256);
    let path = scratch.0.join("published.bin");
    options.output = Some(path.clone());
    let error = publish_verified(
        &options,
        &proof,
        Instant::now() + Duration::from_secs(5),
        &mut BrokenOutput,
    )
    .unwrap_err();
    assert!(error.verified);
    assert_eq!(error.output_state, "published");
    assert_eq!(std::fs::read(path).unwrap(), b"\0\xffexact bytes\r\n");
    assert!(error_json(&error).contains("\"verified\":true"));
    options.output = None;
    let error = publish_verified(
        &options,
        &proof,
        Instant::now() + Duration::from_secs(5),
        &mut BrokenOutput,
    )
    .unwrap_err();
    assert!(error.verified);
    assert_eq!(error.output_state, "partial_or_unwritten");
}

#[test]
fn receipt_flush_failure_reports_the_already_published_verified_file() {
    let scratch = Scratch::new();
    let (mut options, proof) = proof_options(fgit_types::GitHashAlgorithm::Sha256);
    let path = scratch.0.join("published.bin");
    options.output = Some(path.clone());
    let mut output = FlushBrokenOutput::default();
    let error = publish_verified(
        &options,
        &proof,
        Instant::now() + Duration::from_secs(5),
        &mut output,
    )
    .unwrap_err();
    assert!(error.verified);
    assert_eq!(error.kind, "output_receipt_failed");
    assert_eq!(error.output_state, "published");
    assert_eq!(std::fs::read(path).unwrap(), b"\0\xffexact bytes\r\n");
    assert!(
        String::from_utf8(output.0)
            .unwrap()
            .contains("\"output_state\":\"published\"")
    );
}

#[test]
fn cancelled_staging_never_publishes_and_reaps_only_its_temporary() {
    use std::cell::Cell;
    let scratch = Scratch::new();
    let path = scratch.0.join("complete.bin");
    let bytes = vec![17; 64 * 1024 + 1];
    // Stop before creation, before either write, and just before publication.
    for allowed_polls in 0..4 {
        let polls = Cell::new(0);
        let error = fgit_cli::write_new_export_while(&path, &bytes, &|| {
            let poll = polls.get();
            polls.set(poll + 1);
            poll < allowed_polls
        })
        .unwrap_err();
        assert!(
            matches!(error, fgit_cli::CliRefusal::ExportFile { source, .. }
            if source.kind() == std::io::ErrorKind::TimedOut)
        );
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }
    fgit_cli::write_new_export_while(&path, &bytes, &|| true).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn cancellation_during_stdout_stops_after_verified_bytes_without_claiming_full_output() {
    use std::cell::Cell;
    struct StopAfterWrite<'a> {
        live: &'a Cell<bool>,
        bytes: Vec<u8>,
        flushed: bool,
    }
    impl Write for StopAfterWrite<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            self.live.set(false);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushed = true;
            Ok(())
        }
    }
    let (options, proof) = proof_options_with_bytes(
        fgit_types::GitHashAlgorithm::Sha256,
        &vec![42; 64 * 1024 + 1],
    );
    let live = Cell::new(true);
    let mut output = StopAfterWrite {
        live: &live,
        bytes: Vec::new(),
        flushed: false,
    };
    let error = publish_verified_while(&options, &proof, &|| live.get(), &mut output).unwrap_err();
    assert!(error.verified);
    assert_eq!(error.kind, "deadline_exceeded");
    assert_eq!(error.output_state, "partial_or_unwritten");
    assert_eq!(output.bytes, vec![42; 64 * 1024]);
    assert!(!output.flushed);
}

#[test]
fn cancellation_during_successful_flush_preserves_the_output_outcome() {
    use std::cell::Cell;
    struct StopOnFlush<'a> {
        live: &'a Cell<bool>,
        bytes: Vec<u8>,
    }
    impl Write for StopOnFlush<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.live.set(false);
            Ok(())
        }
    }
    let scratch = Scratch::new();
    let (mut options, proof) = proof_options(fgit_types::GitHashAlgorithm::Sha256);
    for file_output in [false, true] {
        let destination = scratch.0.join("published.bin");
        options.output = file_output.then(|| destination.clone());
        let live = Cell::new(true);
        let mut output = StopOnFlush {
            live: &live,
            bytes: Vec::new(),
        };
        let error =
            publish_verified_while(&options, &proof, &|| live.get(), &mut output).unwrap_err();
        assert!(error.verified);
        assert_eq!(error.kind, "deadline_exceeded");
        if file_output {
            assert_eq!(error.output_state, "published");
            assert_eq!(
                std::fs::read(destination).unwrap(),
                b"\0\xffexact bytes\r\n"
            );
        } else {
            assert_eq!(error.output_state, "partial_or_unwritten");
            assert_eq!(output.bytes, b"\0\xffexact bytes\r\n");
        }
    }
}

#[test]
fn regular_input_bounds_and_deadlines_apply_before_proof_verification() {
    let scratch = Scratch::new();
    let path = scratch.0.join("input");
    std::fs::write(&path, b"abc").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    assert_eq!(
        read_regular(&path, 3, "input", false, deadline).unwrap(),
        b"abc"
    );
    assert!(read_regular(&path, 2, "input", false, deadline).is_err());
    assert_eq!(
        read_regular(&path, 3, "input", false, Instant::now())
            .unwrap_err()
            .kind,
        "deadline_exceeded"
    );
    #[cfg(unix)]
    {
        let link = scratch.0.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_regular(&link, 3, "input", false, deadline).is_err());
    }
}

fn arguments() -> Vec<String> {
    [
        "--input",
        "proof.bin",
        "--trusted-head",
        "alg:1:1111111111111111111111111111111111111111111111111111111111111111",
        "--ref",
        "refs/heads/main",
        "--path",
        "src/lib.rs",
    ]
    .map(str::to_owned)
    .to_vec()
}

#[test]
fn exact_independent_pin_and_literal_byte_query_are_required() {
    let base = arguments();
    let parsed = options::parse(&base).unwrap();
    assert_eq!(parsed.reference.as_bytes(), b"refs/heads/main");
    assert_eq!(parsed.path, b"src/lib.rs");
    assert!(parsed.output.is_none());
    for tail in [
        vec!["--trusted-head", "alg:1:ff"],
        vec!["--ref-hex", "61"],
        vec!["--path-hex", "61"],
        vec!["--token-file", "token"],
        vec!["--principal", "admin"],
    ] {
        let mut args = base.clone();
        args.extend(tail.into_iter().map(str::to_owned));
        assert!(options::parse(&args).is_err());
    }
    let mut missing = base.clone();
    missing.drain(2..4);
    assert_eq!(
        options::parse(&missing).unwrap_err().kind,
        "trusted_head_required"
    );
    for invalid in [
        "/absolute",
        "a/../b",
        "./b",
        "a//b",
        "a/",
        ".",
        "..",
        "a\0b",
    ] {
        let mut args = base.clone();
        args[7] = invalid.into();
        assert_eq!(options::parse(&args).unwrap_err().kind, "invalid_path");
    }
    let mut raw = base;
    raw[6] = "--path-hex".into();
    raw[7] = "7372632fff62696e".into();
    assert_eq!(options::parse(&raw).unwrap().path, b"src/\xffbin");
    raw[7] = "FF".into();
    assert_eq!(options::parse(&raw).unwrap_err().kind, "invalid_hex");
}

#[test]
fn fetch_credentials_are_bound_to_one_explicit_numeric_loopback_url() {
    let mut args = arguments();
    args[0] = "--url".into();
    args[1] = "http://127.0.0.1:8123/repo.git".into();
    args.extend(["--token-file".to_owned(), "token".to_owned()]);
    assert!(options::parse(&args).is_ok());
    for invalid in [
        "https://127.0.0.1:8123/repo.git",
        "http://localhost:8123/repo.git",
        "http://192.0.2.1:8123/repo.git",
        "http://user@127.0.0.1:8123/repo.git",
        "http://127.0.0.1:8123/repo.git?head=mine",
        "http://127.0.0.1:8123/repo.git#secret",
        "http://127.0.0.1:8123/repo.git/../other",
        "http://127.0.0.1:0/repo.git",
    ] {
        args[1] = invalid.into();
        assert_eq!(options::parse(&args).unwrap_err().kind, "invalid_url");
    }
    args[1] = "http://[::1]:8123/repo.git".into();
    assert!(options::parse(&args).is_ok());
}

#[test]
fn valid_native_paths_over_the_http_target_bound_refuse_before_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut args = arguments();
    args[7] = vec!["x".repeat(255); 8].join("/");
    assert!(
        options::parse(&args).is_ok(),
        "file mode retains native path bounds"
    );
    args[0] = "--url".into();
    args[1] = format!("http://{}/repo.git", listener.local_addr().unwrap());
    args.extend(["--token-file".into(), "token".into()]);
    let options = options::parse(&args).unwrap();
    let Input::Http(url) = &options.input else {
        panic!("URL");
    };
    assert_eq!(
        http::fetch(
            url,
            &"a".repeat(64),
            &options,
            Instant::now() + Duration::from_secs(2)
        )
        .unwrap_err()
        .kind,
        "http_target_limit"
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn invalid_or_expired_proof_never_writes_partial_output() {
    let options = options::parse(&arguments()).unwrap();
    let mut output = Vec::new();
    assert!(
        publish_verified(
            &options,
            b"forged",
            Instant::now() + Duration::from_secs(1),
            &mut output
        )
        .is_err()
    );
    assert!(output.is_empty());
    assert_eq!(
        publish_verified(&options, b"forged", Instant::now(), &mut output)
            .unwrap_err()
            .kind,
        "deadline_exceeded"
    );
    assert!(output.is_empty());
}

#[test]
fn actual_http_client_preserves_query_and_credentials_and_rejects_truncation() {
    for complete in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 16384);
            }
            let text = String::from_utf8(request).unwrap();
            assert!(text.starts_with("GET /repo.git/api/v1/source/verified-blob?ref_hex=726566732f68656164732f6d61696e&path_hex=7372632f6c69622e7273&expected_head=alg:1:"));
            assert!(text.contains(&format!("Authorization: Bearer {}\r\n", "a".repeat(64))));
            assert!(!text.contains("Idempotency-Key:"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.frankengit.verified-blob\r\nContent-Length: 3\r\nConnection: close\r\n\r\n").unwrap();
            stream
                .write_all(if complete { b"abc" } else { b"ab" })
                .unwrap();
        });
        let mut args = arguments();
        args[0] = "--url".into();
        args[1] = format!("http://{address}/repo.git");
        args.extend(["--token-file".to_owned(), "token".to_owned()]);
        let options = options::parse(&args).unwrap();
        let Input::Http(url) = &options.input else {
            panic!("URL");
        };
        let result = http::fetch(
            url,
            &"a".repeat(64),
            &options,
            Instant::now() + Duration::from_secs(2),
        );
        worker.join().unwrap();
        if complete {
            assert_eq!(result.unwrap(), b"abc");
        } else {
            assert_eq!(result.unwrap_err().kind, "http_framing");
        }
    }
}
