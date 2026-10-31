//! Real persisted-node Git and SSH upload preparation, including raw clients.
//! SSH uses its production command adapter here; encrypted-window cleanup is
//! independently exercised by `upload_deadline_tests`.

use super::*;
use crate::{NodeConfig, NodePackMaterializationRefusal};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_pack::{
    NativeChecksumVerifier, PackError, PackLimits, PackWriteError, read_verified_pack,
};
use fgit_runtime::{BudgetClass, BudgetPolicy, ClassLimits};
use fgit_types::{GitHashAlgorithm, GitOid, HeadGeneration, TenantId};
use fgit_wire::{Packet, PktLineDecoder, encode_packets};
use std::collections::BTreeSet;
use std::fs;
use std::io::Cursor;
use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::time::Instant;

static NEXT_SCRATCH: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fgit-upload-preparation-{}-{}",
            std::process::id(),
            NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_object(
    root: &Path,
    format: GitHashAlgorithm,
    kind: GitObjectKind,
    label: &str,
    body: &[u8],
) -> GitOid {
    let id = git_object_id(format, kind, body);
    let framed = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(framed.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes());
    encoded.extend((!length).to_le_bytes());
    encoded.extend(&framed);
    let (low, high) = framed.iter().fold((1_u32, 0_u32), |(low, high), byte| {
        let low = (low + u32::from(*byte)) % 65521;
        (low, (high + low) % 65521)
    });
    encoded.extend(((high << 16) | low).to_be_bytes());
    let hex = id.to_string();
    let directory = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&hex[2..]), encoded).unwrap();
    id
}

fn seeded(format: GitHashAlgorithm) -> (Scratch, NodeConfig, GitOid, BTreeSet<Vec<u8>>) {
    let scratch = Scratch::new();
    let source = scratch.0.join("source");
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(
        source.join("config"),
        match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => {
                "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
            }
        },
    )
    .unwrap();
    let blob_body = vec![b'x'; 4096];
    let blob = write_object(&source, format, GitObjectKind::Blob, "blob", &blob_body);
    let mut tree_body = b"100644 data.txt\0".to_vec();
    tree_body.extend_from_slice(blob.as_bytes());
    let tree = write_object(&source, format, GitObjectKind::Tree, "tree", &tree_body);
    let commit_body = format!(
        "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nfixture\n"
    )
    .into_bytes();
    let commit = write_object(
        &source,
        format,
        GitObjectKind::Commit,
        "commit",
        &commit_body,
    );
    fs::write(source.join("refs/heads/main"), format!("{commit}\n")).unwrap();
    let budgets = BudgetPolicy::finite_defaults()
        .with_class_limits(
            BudgetClass::Database,
            ClassLimits::finite(Duration::from_secs(60), 10_000_000, 100_000_000),
        )
        .unwrap();
    let config = NodeConfig::new(
        scratch.0.join("node"),
        TenantId::from_bytes([0x71; 16]),
        RepositoryId::from_bytes([0x72; 16]),
    )
    .with_object_format(format)
    .with_worker_threads(1)
    .with_runtime_budgets(budgets);
    let (mut node, _) = OneNode::init(config.clone()).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node.runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.request_context(),
            &source,
            PrincipalId::from_bytes([0x73; 16]),
            b"upload-preparation-fixture",
        ))
        .unwrap();
    node.shutdown().unwrap();
    (
        scratch,
        config,
        commit,
        [blob_body, tree_body, commit_body].into_iter().collect(),
    )
}

fn reopen(config: NodeConfig) -> OneNode {
    let mut node = OneNode::open_existing(config).unwrap();
    let selected = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(selected.receipt().generation())
        .unwrap();
    node
}

fn generation(node: &OneNode) -> HeadGeneration {
    node.runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation()
}

fn request(commit: GitOid, version: u8, sideband: bool) -> Vec<u8> {
    let format = commit.algorithm().as_str();
    let packets = if version == 2 {
        vec![
            Packet::Data(b"command=fetch\n".to_vec()),
            Packet::Data(format!("object-format={format}\n").into_bytes()),
            Packet::Delimiter,
            Packet::Data(format!("want {commit}\n").into_bytes()),
            Packet::Data(b"no-progress\n".to_vec()),
            Packet::Data(b"done\n".to_vec()),
            Packet::Flush,
        ]
    } else {
        let sideband = if sideband { " side-band-64k" } else { "" };
        vec![
            Packet::Data(format!("want {commit} object-format={format}{sideband}\n").into_bytes()),
            Packet::Flush,
            Packet::Data(b"done\n".to_vec()),
        ]
    };
    encode_packets(&packets, &WireLimits::default()).unwrap()
}

fn after_advertisement(mut bytes: &[u8]) -> &[u8] {
    loop {
        let length = usize::from_str_radix(std::str::from_utf8(&bytes[..4]).unwrap(), 16).unwrap();
        if length == 0 {
            return &bytes[4..];
        }
        assert!(length >= 4);
        bytes = &bytes[length..];
    }
}

fn decoded(bytes: &[u8]) -> Vec<Packet> {
    let mut decoder = PktLineDecoder::new(WireLimits::default()).unwrap();
    let packets = decoder.push(bytes).unwrap();
    decoder.finish().unwrap();
    packets
}

fn assert_error(bytes: &[u8], flag: &str) {
    let packets = decoded(after_advertisement(bytes));
    let [Packet::Data(message)] = packets.as_slice() else {
        panic!("a refused preparation must withhold every negotiation/pack prefix: {packets:?}");
    };
    let message = std::str::from_utf8(message).unwrap();
    assert!(message.starts_with("ERR "), "{message}");
    assert!(message.contains(flag), "{message}");
    assert!(message.ends_with('\n'));
    assert!(message.len() <= 517);
}

fn assert_pack(
    bytes: &[u8],
    format: GitHashAlgorithm,
    sideband: bool,
    expected: &BTreeSet<Vec<u8>>,
) {
    let body = after_advertisement(bytes);
    let pack = if sideband {
        decoded(body)
            .into_iter()
            .filter_map(|packet| match packet {
                Packet::Data(bytes) if bytes.first() == Some(&1) => Some(bytes[1..].to_vec()),
                _ => None,
            })
            .flatten()
            .collect::<Vec<_>>()
    } else {
        assert!(body.starts_with(b"0008NAK\nPACK"));
        body[8..].to_vec()
    };
    let verified = read_verified_pack(
        &pack,
        format,
        &PackLimits::default(),
        &mut || true,
        &NativeChecksumVerifier,
    )
    .expect("the permitted twin remains a complete native pack");
    let actual: BTreeSet<_> = verified
        .entries()
        .iter()
        .map(|entry| entry.inflated.clone())
        .collect();
    assert_eq!(&actual, expected);
}

fn raw(
    node: OneNode,
    commit: GitOid,
    version: u8,
    sideband: bool,
) -> (
    OneNode,
    Result<GitDaemonSessionOutcome, NodeGitDaemonServeRefusal>,
    Vec<u8>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut greeting = b"git-upload-pack ".to_vec();
    greeting.extend_from_slice(node.git_daemon_repository_path().as_bytes());
    greeting.extend_from_slice(b"\0host=loopback\0");
    if version != 0 {
        greeting.extend_from_slice(format!("\0version={version}\0").as_bytes());
    }
    let mut input = encode_packets(&[Packet::Data(greeting)], &WireLimits::default()).unwrap();
    input.extend(request(commit, version, sideband));
    let server = std::thread::spawn(move || {
        let outcome = node.serve_git_daemon_once_with_limits(&listener, WireLimits::default());
        (node, outcome)
    });
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    client.write_all(&input).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut output = Vec::new();
    client.read_to_end(&mut output).unwrap();
    let (node, outcome) = server.join().unwrap();
    (node, outcome, output)
}

fn protocol(version: u8) -> Vec<u8> {
    if version == 0 {
        Vec::new()
    } else {
        format!("version={version}").into_bytes()
    }
}

#[test]
fn git_and_ssh_prepare_or_report_resource_limits_before_any_pack_prefix() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, base, commit, bodies) = seeded(format);
        for (config, flag) in [
            (
                base.clone().with_selected_pack_byte_envelope(1024),
                Some("--pack-max-expanded-mib"),
            ),
            (
                base.clone().with_selected_pack_blob_limit(1024),
                Some("ObjectSizeLimit"),
            ),
            (base.clone().with_selected_pack_byte_envelope(8192), None),
        ] {
            let mut node = reopen(config);
            let before = generation(&node);
            for (version, sideband) in [(0, false), (0, true), (1, false), (1, true), (2, true)] {
                let (returned, result, bytes) = raw(node, commit, version, sideband);
                node = returned;
                if let Some(flag) = flag {
                    assert!(
                        matches!(result, Err(NodeGitDaemonServeRefusal::Pack(ref error))
                        if matches!(error.as_ref(), NodePackMaterializationRefusal::Pack(inner)
                            if matches!(inner.as_ref(), PackWriteError::Pack(PackError::TotalExpandedLimit { .. } | PackError::ObjectSizeLimit { .. }))))
                    );
                    assert_error(&bytes, flag);
                } else {
                    assert!(
                        matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),
                        "{result:?}"
                    );
                    assert_pack(&bytes, format, sideband, &bodies);
                }

                let deadline = GitDaemonSessionDeadline::new(
                    GitDaemonSessionTimeout::DEFAULT,
                    GitDaemonSessionWorkScaling::FLAT,
                );
                let mut output = Vec::new();
                let result = node.serve_ssh_upload_pack(
                    &mut Cursor::new(request(commit, version, sideband)),
                    &mut output,
                    &protocol(version),
                    &|| true,
                    &deadline,
                );
                if let Some(flag) = flag {
                    assert!(
                        matches!(result, Err(NodeGitDaemonServeRefusal::Pack(_))),
                        "{result:?}"
                    );
                    assert_error(&output, flag);
                } else {
                    assert!(
                        matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),
                        "{result:?}"
                    );
                    assert_pack(&output, format, sideband, &bodies);
                }
                assert_eq!(
                    generation(&node),
                    before,
                    "fetch refusals and success never publish state"
                );
            }
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn ssh_work_expiry_uses_one_bounded_err_without_reopening_work() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, config, commit, _) = seeded(format);
        let node = reopen(config);
        let before = generation(&node);
        for (version, sideband) in [(0, false), (0, true), (1, false), (1, true), (2, true)] {
            let mut deadline = GitDaemonSessionDeadline::new(
                GitDaemonSessionTimeout::try_new(Duration::from_secs(1)).unwrap(),
                GitDaemonSessionWorkScaling::DEFAULT,
            );
            deadline.started = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
            deadline.note_admitted(1 << 30);
            assert!(!deadline.expired());
            let mut output = Vec::new();
            // Remove the earned allowance at the first actual pack-work peer
            // checkpoint. This deterministically expires the production work
            // path without sleeping or changing its selected content.
            let result = node.serve_ssh_upload_pack(
                &mut Cursor::new(request(commit, version, sideband)),
                &mut output,
                &protocol(version),
                &|| {
                    deadline.shared.admitted_bytes.store(0, Ordering::Relaxed);
                    true
                },
                &deadline,
            );
            assert!(
                matches!(result, Err(NodeGitDaemonServeRefusal::Transport(ref error))
                if matches!(error.as_ref(), GitDaemonTransportRefusal::SessionDeadlineExceeded { .. }))
            );
            assert_error(&output, "--session-timeout-secs");
            assert!(deadline.expired());
            assert!(deadline.shared.terminal_response.get().is_some());
            assert!(!deadline.note_selected_upload_work(usize::MAX));
            assert_eq!(generation(&node), before);
        }
        node.shutdown().unwrap();
    }
}
