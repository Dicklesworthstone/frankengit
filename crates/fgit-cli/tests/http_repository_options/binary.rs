//! The actual executable must select catalog mode, bind the announced listener,
//! reload route credentials and drain. Native transport tests cover publication.

use fgit_crypto::sha256_digest;
use fgit_node::{NodeConfig, OneNode};
use fgit_schema::json;
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x22; 16]);
const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0x44; 16]);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-http-catalog-binary-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn private_write(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

struct Repository {
    config: NodeConfig,
    row: String,
    header: String,
    token: String,
    credentials: PathBuf,
}

fn repository(scratch: &Scratch, name: &str, tenant: u8, format: GitHashAlgorithm) -> Repository {
    let tenant = TenantId::from_bytes([tenant; 16]);
    let root = scratch.0.join(name);
    let config = NodeConfig::new(root.clone(), tenant, REPOSITORY)
        .with_object_format(format)
        .with_worker_threads(2);
    let (node, _) = OneNode::init(config.clone()).unwrap();
    let incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    let credentials = scratch.0.join(format!("{name}.credentials"));
    let token = format!("{:02x}", tenant.as_bytes()[0]).repeat(32);
    let digest: String = sha256_digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let header = format!("frankengit-http-credentials-v1 {tenant} {REPOSITORY} {incarnation}\n");
    private_write(
        &credentials,
        format!("{header}{digest} {PRINCIPAL} read,receive\n").as_bytes(),
    );
    let row = format!(
        "/team/{name}.git {} {tenant} {REPOSITORY} {incarnation} {} receive -",
        root.display(),
        credentials.display()
    );
    Repository {
        config,
        row,
        header,
        token,
        credentials,
    }
}

fn command(table: &Path, maximum: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fg"));
    command
        .args([
            "serve-http",
            "127.0.0.1:0",
            "--trusted-local",
            "--repositories-file",
        ])
        .arg(table)
        .args([
            "--max-sessions",
            maximum,
            "--max-in-flight",
            "2",
            "--idle-timeout-secs",
            "5",
            "--session-timeout-secs",
            "30",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn request(address: SocketAddr, path: &str, token: &str) -> String {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(10)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    write!(stream, "GET {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nGit-Protocol: version=2\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = Vec::new();
    stream.take(1 << 20).read_to_end(&mut response).unwrap();
    String::from_utf8(response).unwrap()
}

#[test]
fn binary_catalog_routes_two_hash_formats_keeps_credentials_separate_and_reloads_revocation() {
    let scratch = Scratch::new();
    let first = repository(&scratch, "core", 0x11, GitHashAlgorithm::Sha1);
    let second = repository(&scratch, "models", 0x33, GitHashAlgorithm::Sha256);
    let table = scratch.0.join("repositories");
    private_write(
        &table,
        format!(
            "frankengit-http-repositories-v1\n{}\n{}\n",
            first.row, second.row
        )
        .as_bytes(),
    );
    let mut process = Process(command(&table, "7").spawn().unwrap());
    let stdout = process.0.stdout.take().unwrap();
    let stderr = process.0.stderr.take().unwrap();
    let (ready_send, ready_receive) = std::sync::mpsc::sync_channel(1);
    let output = std::thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            if lines.is_empty() {
                let _ = ready_send.send(line.clone());
            }
            lines.push(line);
        }
        lines
    });
    let errors = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.take(64 * 1024).read_to_end(&mut bytes).unwrap();
        bytes
    });
    let ready = ready_receive
        .recv_timeout(Duration::from_secs(60))
        .expect("catalog never announced readiness");
    let ready = json::parse(ready.as_bytes()).unwrap();
    let fields = ready.object().unwrap();
    assert_eq!(fields["type"].text(), Some("smart_http_listening"));
    assert_eq!(fields["routing"].text(), Some("explicit-v1"));
    assert_eq!(fields["repositories"].unsigned(), Some(2));
    let address: SocketAddr = fields["address"].text().unwrap().parse().unwrap();
    let discovery = "/info/refs?service=git-upload-pack";
    let first_reply = request(address, &format!("/team/core.git{discovery}"), &first.token);
    assert!(first_reply.starts_with("HTTP/1.1 200"), "{first_reply}");
    assert!(first_reply.contains("object-format=sha1"), "{first_reply}");
    let second_reply = request(
        address,
        &format!("/team/models.git{discovery}"),
        &second.token,
    );
    assert!(second_reply.starts_with("HTTP/1.1 200"), "{second_reply}");
    assert!(
        second_reply.contains("object-format=sha256"),
        "{second_reply}"
    );
    let wrong = request(
        address,
        &format!("/team/core.git{discovery}"),
        &second.token,
    );
    assert!(wrong.starts_with("HTTP/1.1 401"), "{wrong}");
    let absent = request(
        address,
        &format!("/team/missing.git{discovery}"),
        &first.token,
    );
    assert_eq!(
        wrong, absent,
        "a missing route must not disclose route existence"
    );
    // Both catalog rows and credentials permit receive. The omitted global
    // --allow-receive still prevents discovery and publication.
    let disabled = request(
        address,
        "/team/core.git/info/refs?service=git-receive-pack",
        &first.token,
    );
    assert!(disabled.starts_with("HTTP/1.1 403"), "{disabled}");
    let replacement = scratch.0.join("revoked.credentials");
    private_write(&replacement, first.header.as_bytes());
    fs::rename(&replacement, &first.credentials).unwrap();
    let revoked = request(address, &format!("/team/core.git{discovery}"), &first.token);
    assert!(revoked.starts_with("HTTP/1.1 401"), "{revoked}");
    assert!(
        request(
            address,
            &format!("/team/models.git{discovery}"),
            &second.token
        )
        .starts_with("HTTP/1.1 200")
    );
    let started = Instant::now();
    let status = loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "HTTP catalog did not drain"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = output.join().unwrap();
    let errors = errors.join().unwrap();
    assert!(
        status.success(),
        "{output:?}\n{}",
        String::from_utf8_lossy(&errors)
    );
    let drained = json::parse(output.last().unwrap().as_bytes()).unwrap();
    let drained = drained.object().unwrap();
    assert_eq!(drained["type"].text(), Some("smart_http_drained"));
    assert_eq!(drained["accepted"].unsigned(), Some(7));
    assert_eq!(
        drained["completed_transports"].unsigned().unwrap()
            + drained["refused_transports"].unsigned().unwrap(),
        7
    );
    for repository in [first, second] {
        let node = OneNode::open_existing(repository.config).unwrap();
        node.runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.shutdown().unwrap();
    }
}

#[test]
fn a_later_invalid_route_never_reports_readiness_and_releases_prepared_nodes() {
    let scratch = Scratch::new();
    let first = repository(&scratch, "core", 0x11, GitHashAlgorithm::Sha1);
    let second = repository(&scratch, "models", 0x33, GitHashAlgorithm::Sha256);
    fs::write(&second.credentials, "invalid final credential table\n").unwrap();
    let table = scratch.0.join("repositories");
    private_write(
        &table,
        format!(
            "frankengit-http-repositories-v1\n{}\n{}\n",
            first.row, second.row
        )
        .as_bytes(),
    );
    let output = command(&table, "1").output().unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("smart_http_listening"));
    assert!(
        !output.stderr.is_empty(),
        "startup refusal must be diagnosable"
    );
    for repository in [first, second] {
        let node = OneNode::open_existing(repository.config).unwrap();
        node.runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.shutdown().unwrap();
    }
}
