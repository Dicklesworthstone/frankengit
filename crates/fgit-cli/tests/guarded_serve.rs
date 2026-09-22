#![forbid(unsafe_code)]
//! Launch the actual fg binary: testing a node method alone cannot prove that
//! the default serve command stopped selecting the obsolete admission path.
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{GitHashAlgorithm, RefName, RepositoryId, TenantId};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);
const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
const PRINCIPAL: &str = "33333333333333333333333333333333";
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-serve-binary-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_hex(TENANT).unwrap(),
            RepositoryId::from_hex(REPOSITORY).unwrap(),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn packet(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() + 4 <= 65_520);
    [format!("{:04x}", bytes.len() + 4).as_bytes(), bytes].concat()
}
fn records(socket: &mut TcpStream) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    loop {
        let mut length = [0; 4];
        socket.read_exact(&mut length).unwrap();
        let length = usize::from_str_radix(std::str::from_utf8(&length).unwrap(), 16).unwrap();
        if length == 0 {
            return records;
        }
        assert!((4..=65_520).contains(&length));
        let mut record = vec![0; length - 4];
        socket.read_exact(&mut record).unwrap();
        let fatal = record.starts_with(b"ERR ");
        records.push(record);
        if fatal {
            return records;
        }
        assert!(records.len() < 100);
    }
}

#[test]
fn fg_serve_rejects_a_stale_ref_but_commits_the_later_ref_and_reopens_it() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = scratch.config(format);
        let (node, _) = OneNode::init(config.clone()).unwrap();
        let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes())
            .unwrap()
            .to_owned();
        let before = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation()
            .get();
        node.shutdown().unwrap();
        let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let mut child = Process(
            Command::new(env!("CARGO_BIN_EXE_fg"))
                .arg("serve")
                .arg(scratch.0.join("node"))
                .args([
                    TENANT,
                    REPOSITORY,
                    &address.to_string(),
                    "--receive-principal",
                    PRINCIPAL,
                    "--max-sessions",
                    "1",
                    "--max-in-flight",
                    "1",
                    "--session-timeout-secs",
                    "30",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let start = Instant::now();
        let mut socket = loop {
            match TcpStream::connect(address) {
                Ok(socket) => break socket,
                Err(_) if start.elapsed() < Duration::from_secs(60) => {
                    assert!(
                        child.0.try_wait().unwrap().is_none(),
                        "fg failed before accepting a client"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("fg did not open the requested listener: {error}"),
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        socket
            .write_all(&packet(
                format!("git-receive-pack {route}\0host=localhost\0").as_bytes(),
            ))
            .unwrap();
        let advertisement = records(&mut socket);
        assert!(!advertisement[0].starts_with(b"ERR "));
        let oid = git_object_id(format, GitObjectKind::Blob, b"x");
        let zero = "0".repeat(format.digest_len() * 2);
        let mut request = packet(
            format!(
                "{oid} {oid} refs/tags/stale\0report-status object-format={}",
                format.as_str()
            )
            .as_bytes(),
        );
        request.extend(packet(
            format!("{zero} {oid} refs/tags/accepted").as_bytes(),
        ));
        request.extend_from_slice(b"0000");
        let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
        pack.extend_from_slice(&[
            0x31, 0x78, 0x01, 0x01, 1, 0, 0xfe, 0xff, b'x', 0, 121, 0, 121,
        ]);
        let checksum = match format {
            GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(),
            GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec(),
        };
        pack.extend_from_slice(&checksum);
        request.extend(pack);
        socket.write_all(&request).unwrap();
        let report = records(&mut socket);
        socket.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            report,
            [
                b"unpack ok\n".to_vec(),
                b"ng refs/tags/stale stale info\n".to_vec(),
                b"ok refs/tags/accepted\n".to_vec()
            ]
        );
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "fg did not drain its accepted connection"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut stdout = String::new();
        child
            .0
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        let mut stderr = String::new();
        child
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(status.success(), "{stderr}");
        assert!(
            stdout.contains("accepted=1, completed=1, refused=0"),
            "{stdout}"
        );
        let node = OneNode::open_existing(config).unwrap();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(selected.basis().generation().get(), before + 2);
        assert_eq!(selected.snapshot().refs.len(), 1);
        assert_eq!(
            selected.snapshot().refs[&RefName::try_new(b"refs/tags/accepted").unwrap()],
            oid
        );
        node.shutdown().unwrap();
    }
}
