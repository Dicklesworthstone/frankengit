//! Operator catalog boundaries and real repository preparation. Encrypted
//! multi-repository dispatch is exercised by the node's SSH transport tests.

#![cfg(unix)]

use super::*;
use fgit_ssh::{SigningKey, SshCommandAuthorizer, SshGitService};
use fgit_types::{CellState, GitHashAlgorithm, PrincipalId};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt, PermissionsExt, symlink};
#[cfg(not(target_os = "linux"))]
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);

const TENANT: TenantId = TenantId::from_bytes([0x11; 16]);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x22; 16]);
const INCARNATION: RepositoryIncarnationId = RepositoryIncarnationId::from_bytes([0x33; 16]);
const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0x44; 16]);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        for _ in 0..128 {
            let root = std::env::temp_dir().join(format!(
                "fg-ssh-catalog-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::DirBuilder::new().mode(0o700).create(&root) {
                Ok(()) => return Self(root),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create SSH catalog fixture: {error}"),
            }
        }
        panic!("SSH catalog fixture collision budget exhausted")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
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

fn fields() -> [String; 8] {
    [
        "team/repository.git".into(),
        "/srv/frankengit/repository".into(),
        TENANT.to_string(),
        REPOSITORY.to_string(),
        INCARNATION.to_string(),
        "/operator/deploy-keys".into(),
        "read-only".into(),
        "-".into(),
    ]
}

fn table(rows: &[String]) -> Vec<u8> {
    format!("{HEADER}\n{}\n", rows.join("\n")).into_bytes()
}

fn record() -> Record {
    records(&table(&[fields().join(" ")]))
        .unwrap()
        .pop()
        .unwrap()
}

fn arguments(extra: &[&str]) -> Vec<String> {
    [
        "serve-ssh",
        "127.0.0.1:0",
        "--repositories-file",
        "/operator/repositories",
        "--host-key-file",
        "/operator/host-key",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(str::to_owned)
    .collect()
}

fn padded_table(bytes: usize) -> Vec<u8> {
    let mut result = table(&[fields().join(" ")]);
    assert!(result.len() <= bytes);
    while result.len() < bytes {
        let width = (bytes - result.len()).min(MAX_LINE_BYTES + 1);
        if width == 1 {
            result.push(b'\n');
        } else {
            result.push(b'#');
            result.resize(result.len() + width - 2, b'x');
            result.push(b'\n');
        }
    }
    result
}

#[test]
fn versioned_eight_field_catalog_is_complete_before_any_record_is_used() {
    let row = fields().join("\t");
    let bytes = format!("# operator comment\r\n\r\n  {HEADER}\r\n{row}\r\n");
    let parsed = records(bytes.as_bytes()).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].route, "team/repository.git");
    assert_eq!(parsed[0].tenant, TENANT);
    assert_eq!(parsed[0].repository, REPOSITORY);
    assert_eq!(parsed[0].incarnation, INCARNATION);
    assert!(!parsed[0].receive);
    assert!(parsed[0].lfs.is_none());

    for invalid in [
        Vec::new(),
        b"# only comments\n".to_vec(),
        format!("{HEADER}\n").into_bytes(),
        format!("frankengit-ssh-repositories-v2\n{row}\n").into_bytes(),
        format!("{row}\n").into_bytes(),
        format!("{HEADER}\n{row}\n{HEADER}\n").into_bytes(),
        table(&[fields()[..7].join(" ")]),
        table(&[format!("{row} unexpected")]),
        table(&[row.clone(), "malformed final record".into()]),
        [table(&[row]), vec![0xff]].concat(),
    ] {
        assert!(records(&invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn route_spelling_ids_modes_and_absolute_paths_are_strict() {
    for path in ["Team-2/repo_3", "a/b", "a/.hidden.git"] {
        let mut row = fields();
        row[0] = path.into();
        assert_eq!(records(&table(&[row.join(" ")])).unwrap()[0].route, path);
    }
    let boundary = format!("a/{}", "b".repeat(510));
    assert_eq!(boundary.len(), 512);
    let mut row = fields();
    row[0] = boundary.clone();
    assert!(records(&table(&[row.join(" ")])).is_ok());

    for path in [
        "repo.git".to_owned(),
        "/team/repo.git".into(),
        "team//repo.git".into(),
        "team/repo.git/".into(),
        "team/nested/repo.git".into(),
        "../repo.git".into(),
        "team/..".into(),
        "./repo.git".into(),
        "-team/repo.git".into(),
        "team/-repo.git".into(),
        "team/repo name".into(),
        "team/repo;name".into(),
        "team/repo'".into(),
        "team/repo\\name".into(),
        "team/répo".into(),
        boundary + "b",
    ] {
        let mut row = fields();
        row[0] = path;
        assert!(records(&table(&[row.join(" ")])).is_err(), "{row:?}");
    }

    for index in [2, 3, 4] {
        for id in [
            "0".repeat(31),
            "a".repeat(33),
            "AA".repeat(16),
            "é".repeat(16),
        ] {
            let mut row = fields();
            row[index] = id;
            assert!(records(&table(&[row.join(" ")])).is_err(), "{row:?}");
        }
    }
    for mode in ["write", "read", "READ-WRITE", "read,write", "all"] {
        let mut row = fields();
        row[6] = mode.into();
        assert!(records(&table(&[row.join(" ")])).is_err(), "{mode}");
    }
    for index in [1, 5, 7] {
        for path in [
            "relative".into(),
            "/bad\0path".into(),
            format!("/{}", "x".repeat(4096)),
        ] {
            let mut row = fields();
            row[index] = path;
            assert!(records(&table(&[row.join(" ")])).is_err(), "field {index}");
        }
        let mut row = fields();
        row[index] = format!("/{}", "x".repeat(4095));
        assert!(records(&table(&[row.join(" ")])).is_ok(), "field {index}");
    }
}

#[test]
fn duplicate_paths_and_identities_refuse_but_distinct_tenants_do_not_alias() {
    let first = fields();
    let mut second = first.clone();
    second[2] = TenantId::from_bytes([0x55; 16]).to_string();
    assert!(
        records(&table(&[first.join(" "), second.join(" ")]))
            .unwrap_err()
            .contains("duplicate SSH route path")
    );
    second = first.clone();
    second[0] = "other/repository.git".into();
    assert!(
        records(&table(&[first.join(" "), second.join(" ")]))
            .unwrap_err()
            .contains("duplicate SSH repository identity")
    );
    second[2] = TenantId::from_bytes([0x55; 16]).to_string();
    let parsed = records(&table(&[first.join(" "), second.join(" ")])).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].repository, parsed[1].repository);
    assert_eq!(parsed[0].incarnation, parsed[1].incarnation);
    assert_ne!(parsed[0].tenant, parsed[1].tenant);
}

#[test]
fn exact_table_line_and_route_limits_have_one_byte_or_record_refused_twins() {
    let exact = padded_table(MAX_TABLE_BYTES);
    assert_eq!(exact.len(), MAX_TABLE_BYTES);
    assert_eq!(records(&exact).unwrap().len(), 1);
    let mut too_large = exact;
    too_large.push(b'\n');
    assert!(records(&too_large).unwrap_err().contains("256 KiB"));

    let mut line = table(&[fields().join(" ")]);
    line.push(b'#');
    line.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES - 1));
    assert!(records(&line).is_ok());
    line.push(b'x');
    assert!(records(&line).unwrap_err().contains("16 KiB"));

    let rows: Vec<_> = (0..=MAX_SSH_REPOSITORY_ROUTES)
        .map(|index| {
            let mut row = fields();
            row[0] = format!("team/repo-{index}.git");
            row[3] = RepositoryId::from_bytes([u8::try_from(index).unwrap(); 16]).to_string();
            row.join(" ")
        })
        .collect();
    assert_eq!(
        records(&table(&rows[..MAX_SSH_REPOSITORY_ROUTES]))
            .unwrap()
            .len(),
        MAX_SSH_REPOSITORY_ROUTES,
    );
    assert!(records(&table(&rows)).unwrap_err().contains("64 routes"));
}

#[test]
fn listener_options_keep_write_enablement_and_route_lfs_policy_explicit() {
    let defaults = arguments(&[]);
    let parsed = parse(&defaults).unwrap();
    assert_eq!(parsed.listen, "127.0.0.1:0");
    assert_eq!(parsed.table, Path::new("/operator/repositories"));
    assert_eq!(parsed.host, Path::new("/operator/host-key"));
    assert_eq!(parsed.limits, SshServerLimits::DEFAULT);
    assert!(!parsed.receive);
    assert!(parsed.stop.is_none());

    let enabled = arguments(&[
        "--allow-receive",
        "--continuous",
        "--stop-file",
        "ssh.stop",
        "--max-in-flight",
        "2",
    ]);
    let parsed = parse(&enabled).unwrap();
    assert!(parsed.receive);
    assert_eq!(parsed.stop, Some(PathBuf::from("ssh.stop")));
    assert_eq!(parsed.limits.max_in_flight, 2);

    for extra in [
        vec!["--allow-receive", "--allow-receive"],
        vec!["--continuous"],
        vec!["--stop-file", "ssh.stop"],
        vec!["--continuous", "--stop-file", ""],
        vec!["--continuous", "--continuous", "--stop-file", "ssh.stop"],
        vec![
            "--continuous",
            "--stop-file",
            "ssh.stop",
            "--max-sessions",
            "1",
        ],
        vec!["--expected-incarnation", "33333333333333333333333333333333"],
        vec!["--require-lfs-payloads", "/global-lfs"],
        vec!["--deploy-keys-file", "/global-keys"],
        vec!["--principal", "44444444444444444444444444444444"],
        vec!["--scopes", "read,write"],
        vec!["--unknown", "value"],
    ] {
        assert!(parse(&arguments(&extra)).is_err(), "{extra:?}");
    }
    let mut row = fields();
    row[6] = "read-write".into();
    row[7] = "/operator/lfs-custody".into();
    let record = records(&table(&[row.join(" ")])).unwrap().pop().unwrap();
    let config = configuration(&record, &parse(&defaults).unwrap(), 1).unwrap();
    assert!(record.receive);
    assert_eq!(
        config.receive_lfs_root(),
        Some(Path::new("/operator/lfs-custody"))
    );
    assert!(
        config.http_lfs_root().is_none(),
        "custody grants no HTTP LFS endpoint"
    );
    assert!(
        !parse(&defaults).unwrap().receive,
        "a writable row does not enable the listener"
    );
}

#[test]
fn listener_argument_bounds_limits_and_duplicate_values_refuse() {
    for extra in [
        vec!["--max-sessions", "0"],
        vec!["--max-sessions", "1000001"],
        vec!["--max-sessions", "18446744073709551615"],
        vec!["--max-sessions", "+1"],
        vec!["--max-sessions", "1.5"],
        vec!["--max-in-flight", "0"],
        vec!["--max-in-flight", "17"],
        vec!["--max-in-flight", "-1"],
        vec!["--max-in-flight"],
        vec!["--max-in-flight", "--allow-receive"],
        vec!["--max-in-flight", "1", "--max-in-flight", "2"],
        vec!["--repositories-file", "/other"],
        vec!["--host-key-file", "/other"],
        vec!["extra-positional"],
    ] {
        assert!(parse(&arguments(&extra)).is_err(), "{extra:?}");
    }
    assert!(
        parse(&arguments(&[
            "--max-sessions",
            "1000000",
            "--max-in-flight",
            "16"
        ]))
        .is_ok()
    );
    let mut relative = arguments(&[]);
    relative[3] = "relative-catalog".into();
    assert!(parse(&relative).is_err());
    for index in [1, 3, 5] {
        let mut oversized = arguments(&[]);
        oversized[index] = "x".repeat(4097);
        assert!(parse(&oversized).is_err(), "argument {index}");
    }
    let mut excessive = arguments(&[]);
    excessive.resize(65, "extra".into());
    assert!(parse(&excessive).is_err());
    assert!(parse(&[]).is_err());
}

#[test]
fn envelope_validation_precedes_open_and_cache_budgets_are_listener_totals() {
    let record = record();
    let defaults = arguments(&[]);
    let options = parse(&defaults).unwrap();
    let whole = configuration(&record, &options, 1).unwrap();
    for count in [1, 3, MAX_SSH_REPOSITORY_ROUTES] {
        let config = configuration(&record, &options, count).unwrap();
        for capacity in [
            NodeConfig::pack_cache_bytes as fn(&NodeConfig) -> usize,
            NodeConfig::received_pack_cache_bytes,
            NodeConfig::ancestry_metadata_cache_bytes,
        ] {
            assert_eq!(capacity(&config), capacity(&whole) / count);
            assert!(capacity(&config) * count <= capacity(&whole));
        }
    }
    let selected = arguments(&[
        "--pack-cache-mib",
        "7",
        "--received-pack-cache-mib",
        "11",
        "--pack-max-blob-mib",
        "96",
    ]);
    let config = configuration(&record, &parse(&selected).unwrap(), 3).unwrap();
    assert_eq!(config.pack_cache_bytes(), (7 << 20) / 3);
    assert_eq!(config.received_pack_cache_bytes(), (11 << 20) / 3);
    assert_eq!(config.selected_pack_blob_limit(), Some(96 << 20));
    let disabled = arguments(&["--pack-cache-mib", "0", "--received-pack-cache-mib", "0"]);
    let config = configuration(
        &record,
        &parse(&disabled).unwrap(),
        MAX_SSH_REPOSITORY_ROUTES,
    )
    .unwrap();
    assert_eq!(config.pack_cache_bytes(), 0);
    assert_eq!(config.received_pack_cache_bytes(), 0);

    for extra in [
        ["--pack-cache-mib", "65537"],
        ["--received-pack-cache-mib", "65537"],
        ["--session-timeout-secs", "0"],
        ["--receive-max-input-mib", "0"],
        ["--receive-max-expanded-mib", "0"],
        ["--pack-max-expanded-mib", "0"],
        ["--pack-max-blob-mib", "0"],
    ] {
        let arguments = arguments(&extra);
        let options = parse(&arguments).unwrap();
        assert!(configuration(&record, &options, 1).is_err(), "{extra:?}");
    }
}

#[test]
fn table_reads_require_private_unlinked_regular_files_and_validate_every_row() {
    let scratch = Scratch::new();
    let path = scratch.0.join("repositories");
    let valid = table(&[fields().join(" ")]);
    assert!(read_table(&path).is_err());
    private_write(&path, &valid);
    assert_eq!(read_table(&path).unwrap().len(), 1);
    for mode in [0o640, 0o604, 0o666] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(read_table(&path).is_err(), "mode {mode:o}");
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_table(&path).is_ok());
    let alias = scratch.0.join("linked");
    fs::hard_link(&path, &alias).unwrap();
    assert!(read_table(&path).is_err());
    fs::remove_file(&alias).unwrap();
    assert!(read_table(&path).is_ok());
    symlink(&path, &alias).unwrap();
    assert!(read_table(&alias).is_err());
    assert!(read_table(&scratch.0).is_err());
    let socket = scratch.0.join("socket");
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{CWD, FileType, Mode};

        // File-type rejection needs a genuine socket inode, not a listener.
        rustix::fs::mknodat(CWD, &socket, FileType::Socket, Mode::RUSR | Mode::WUSR, 0).unwrap();
    }
    #[cfg(not(target_os = "linux"))]
    let listener = UnixListener::bind(&socket).unwrap();
    assert!(
        fs::symlink_metadata(&socket)
            .unwrap()
            .file_type()
            .is_socket()
    );
    assert!(read_table(&socket).is_err());
    #[cfg(not(target_os = "linux"))]
    drop(listener);

    fs::write(&path, padded_table(MAX_TABLE_BYTES)).unwrap();
    assert!(read_table(&path).is_ok());
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    assert!(read_table(&path).is_err());
    fs::write(&path, table(&[fields().join(" "), "bad final row".into()])).unwrap();
    assert!(
        read_table(&path).is_err(),
        "a valid prefix cannot salvage an invalid table"
    );
    fs::write(&path, valid).unwrap();
    assert!(read_table(&path).is_ok());
}

#[test]
fn a_repository_table_fifo_refuses_without_waiting_for_a_writer() {
    use rustix::fs::{Mode, OFlags};

    let scratch = Scratch::new();
    let path = scratch.0.join("repositories");
    rustix::fs::mkfifoat(rustix::fs::CWD, &path, Mode::RUSR | Mode::WUSR).unwrap();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let child_path = path.clone();
    let child = std::thread::spawn(move || {
        let _ = send.send(read_table(&child_path));
    });
    let result = receive.recv_timeout(Duration::from_secs(2));
    if matches!(result, Err(std::sync::mpsc::RecvTimeoutError::Timeout)) {
        // Let a regressed blocking open return EOF before joining its worker.
        // The successful path has no writer for the entire observation.
        let rescue = rustix::fs::open(
            &path,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .unwrap();
        drop(rescue);
    }
    child.join().unwrap();
    assert!(
        result
            .expect("repository table open waited for a FIFO writer")
            .is_err()
    );
}

#[test]
fn root_resolution_rejects_canonical_aliases_and_ancestor_overlap_in_both_orders() {
    let scratch = Scratch::new();
    let first = scratch.0.join("repository");
    let sibling = scratch.0.join("repository-sibling");
    let nested = first.join("nested");
    fs::create_dir_all(&nested).unwrap();
    fs::create_dir(&sibling).unwrap();
    let with_roots = |roots: &[PathBuf]| -> Vec<Record> {
        roots
            .iter()
            .map(|root| {
                let mut record = record();
                record.root = root.clone();
                record
            })
            .collect()
    };
    let mut disjoint = with_roots(&[first.clone(), sibling.clone()]);
    resolve_roots(&mut disjoint).unwrap();
    assert_eq!(disjoint[0].root, first.canonicalize().unwrap());
    assert_eq!(disjoint[1].root, sibling.canonicalize().unwrap());
    let alias = scratch.0.join("alias");
    symlink(&first, &alias).unwrap();
    let mut single_alias = with_roots(std::slice::from_ref(&alias));
    resolve_roots(&mut single_alias).unwrap();
    assert_eq!(single_alias[0].root, first.canonicalize().unwrap());
    for roots in [
        vec![first.clone(), alias],
        vec![first.clone(), first.clone()],
        vec![first.clone(), nested.clone()],
        vec![nested, first],
    ] {
        assert!(resolve_roots(&mut with_roots(&roots)).is_err());
    }
    let regular = scratch.0.join("regular");
    private_write(&regular, b"not a repository directory");
    for root in [regular, scratch.0.join("absent")] {
        assert!(resolve_roots(&mut with_roots(&[root])).is_err());
    }
}

fn deploy_keys() -> String {
    let key = SigningKey::from_bytes(&[0x61; 32])
        .verifying_key()
        .to_bytes();
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "frankengit-ssh-deploy-keys-v2\n{hex} {PRINCIPAL} read,write exact:726566732f68656164732f6d61696e\n"
    )
}

fn repository(format: GitHashAlgorithm) -> (Scratch, Record) {
    let scratch = Scratch::new();
    let mut record = record();
    record.root = scratch.0.join("repository");
    record.keys = scratch.0.join("deploy-keys");
    private_write(&record.keys, deploy_keys().as_bytes());
    let (node, _) = OneNode::init(
        NodeConfig::new(record.root.clone(), record.tenant, record.repository)
            .with_object_format(format),
    )
    .unwrap();
    record.incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    (scratch, record)
}

#[test]
fn real_route_open_preserves_native_format_identity_and_requires_both_write_switches() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut record) = repository(format);
        let args = arguments(&[]);
        let options = parse(&args).unwrap();
        for (global, per_route) in [(false, false), (false, true), (true, false), (true, true)] {
            record.receive = per_route;
            let config = configuration(&record, &options, 2).unwrap();
            let (node, route) = open_route(&record, config, global).unwrap();
            assert_eq!(node.cell_state(), CellState::Serving);
            assert_eq!(node.tenant_id(), record.tenant);
            assert_eq!(node.repository_id(), record.repository);
            assert_eq!(node.repository_incarnation_id(), record.incarnation);
            assert_eq!(node.object_format(), format);
            let generation = node
                .runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap()
                .receipt()
                .generation();
            let report = node.runtime().block_on(node.doctor(None)).unwrap();
            assert_eq!(report.repository_incarnation_id(), record.incarnation);
            assert_eq!(report.object_format(), format);
            assert_eq!(report.authority_head().receipt().generation(), generation);
            // The route's public diagnostic exposes its selected switch. The
            // node tests independently prove this switch refuses SSH receive.
            let description = format!("{route:?}");
            assert!(description.contains(&format!("allow_receive: {}", global && per_route)));
            assert!(!description.contains(record.keys.to_str().unwrap()));
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn canonical_incarnation_mismatch_refuses_and_a_matching_reopen_remains_usable() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, record) = repository(format);
        let args = arguments(&[]);
        let options = parse(&args).unwrap();
        let config = configuration(&record, &options, 1).unwrap();
        let (node, _) = open_route(&record, config.clone(), false).unwrap();
        let before = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation();
        node.shutdown().unwrap();
        let mut stale = record.clone();
        let mut bytes = *stale.incarnation.as_bytes();
        bytes[0] ^= 1;
        stale.incarnation = RepositoryIncarnationId::from_bytes(bytes);
        let refused = open_route(&stale, configuration(&stale, &options, 1).unwrap(), true)
            .err()
            .expect("stale repository incarnation was accepted");
        assert!(refused.contains("incarnation"), "{refused}");
        let (node, _) = open_route(&record, config, false).unwrap();
        assert_eq!(
            node.runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap()
                .receipt()
                .generation(),
            before
        );
        assert_eq!(node.repository_incarnation_id(), record.incarnation);
        node.shutdown().unwrap();
    }
}

#[test]
fn private_scoped_keys_are_required_before_repository_open() {
    let scratch = Scratch::new();
    let mut record = record();
    record.root = scratch.0.join("must-not-be-created");
    record.keys = scratch.0.join("deploy-keys");
    let args = arguments(&[]);
    let options = parse(&args).unwrap();
    private_write(&record.keys, deploy_keys().as_bytes());
    let source =
        FileDeployKeyAuthorizer::try_new(record.keys.clone(), REPOSITORY, REPOSITORY).unwrap();
    let key = SigningKey::from_bytes(&[0x61; 32])
        .verifying_key()
        .to_bytes();
    let grant = source
        .authorize_command_grant(&key, REPOSITORY, SshGitService::ReceivePack)
        .unwrap();
    assert_eq!(grant.principal(), PRINCIPAL);
    assert!(grant.ref_write_scope().is_some());
    assert!(
        grant
            .principal_without_scope(SshGitService::ReceivePack)
            .is_err()
    );

    for malformed in [
        b"bad first row\n".to_vec(),
        format!("{}bad final row\n", deploy_keys()).into_bytes(),
    ] {
        fs::write(&record.keys, malformed).unwrap();
        let error = open_route(&record, configuration(&record, &options, 1).unwrap(), true)
            .err()
            .expect("malformed credential source was accepted");
        assert!(error.contains("invalid route deploy keys"), "{error}");
        assert!(
            !record.root.exists(),
            "credential failure opened repository state"
        );
    }
    fs::write(&record.keys, deploy_keys()).unwrap();
    fs::set_permissions(&record.keys, fs::Permissions::from_mode(0o644)).unwrap();
    let error = open_route(&record, configuration(&record, &options, 1).unwrap(), true)
        .err()
        .unwrap();
    assert!(error.contains("invalid route deploy keys"));
    assert!(!record.root.exists());
}

#[test]
fn lfs_startup_refusal_closes_the_open_node_and_private_custody_allows_reopen() {
    let (scratch, mut record) = repository(GitHashAlgorithm::Sha256);
    let args = arguments(&[]);
    let options = parse(&args).unwrap();
    let lfs = scratch.0.join("lfs");
    record.lfs = Some(lfs.clone());
    let config = configuration(&record, &options, 1).unwrap();
    assert_eq!(config.clone().receive_lfs_root(), Some(lfs.as_path()));
    let error = open_route(&record, config.clone(), false).err().unwrap();
    assert!(
        error.contains("cannot open required LFS custody"),
        "{error}"
    );
    assert!(
        !lfs.exists(),
        "custody validation must not create its operator root"
    );
    fs::DirBuilder::new().mode(0o700).create(&lfs).unwrap();
    fs::set_permissions(&lfs, fs::Permissions::from_mode(0o755)).unwrap();
    let error = open_route(&record, config.clone(), false).err().unwrap();
    assert!(
        error.contains("cannot open required LFS custody"),
        "{error}"
    );
    fs::set_permissions(&lfs, fs::Permissions::from_mode(0o700)).unwrap();
    let (node, _) = open_route(&record, config, false).unwrap();
    assert_eq!(node.cell_state(), CellState::Serving);
    assert_eq!(node.repository_incarnation_id(), record.incarnation);
    node.validate_receive_lfs_storage().unwrap();
    node.shutdown().unwrap();
    assert_eq!(
        fs::read_dir(&lfs).unwrap().count(),
        0,
        "opening custody creates no payload namespace"
    );
}
