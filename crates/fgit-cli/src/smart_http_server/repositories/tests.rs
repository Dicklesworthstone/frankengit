//! Deployment-boundary tests use actual private files and canonical nodes.

#![cfg(unix)]

use super::*;
use fgit_crypto::sha256_digest;
use fgit_types::{CellState, GitHashAlgorithm, PrincipalId};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const TENANT: TenantId = TenantId::from_bytes([0x11; 16]);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x22; 16]);
const INCARNATION: RepositoryIncarnationId = RepositoryIncarnationId::from_bytes([0x33; 16]);
const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0x44; 16]);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        for _ in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "fg-http-catalog-options-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create HTTP catalog fixture: {error}"),
            }
        }
        panic!("HTTP catalog fixture collision budget exhausted")
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
        "/team/core.git".into(),
        "/srv/frankengit/core".into(),
        TENANT.to_string(),
        REPOSITORY.to_string(),
        INCARNATION.to_string(),
        "/operator/core.credentials".into(),
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
        "127.0.0.1:0",
        "--trusted-local",
        "--repositories-file",
        "/operator/repositories",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(str::to_owned)
    .collect()
}
fn padded_table(bytes: usize) -> Vec<u8> {
    let mut result = table(&[fields().join(" ")]);
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
fn catalog_requires_one_complete_versioned_table_before_use() {
    let row = fields().join("\t");
    let valid = format!("# operator note\r\n\r\n {HEADER}\r\n{row}\r\n");
    let parsed = records(valid.as_bytes()).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].route, "/team/core.git");
    assert_eq!(parsed[0].tenant, TENANT);
    assert_eq!(parsed[0].repository, REPOSITORY);
    assert_eq!(parsed[0].incarnation, INCARNATION);
    assert_eq!(parsed[0].services, HttpRepositoryServices::default());
    for invalid in [
        Vec::new(),
        b"# only comments\n".to_vec(),
        format!("{HEADER}\n").into_bytes(),
        format!("frankengit-http-repositories-v2\n{row}\n").into_bytes(),
        row.as_bytes().to_vec(),
        table(&[fields()[..7].join(" ")]),
        table(&[format!("{row} extra")]),
        table(&[row.clone(), "bad final row".into()]),
        [table(&[row]), vec![0xff]].concat(),
    ] {
        assert!(records(&invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn paths_ids_and_service_sets_have_exact_bounded_spellings() {
    for path in ["/Team-2/repo_3", "/a/b", "/a/.hidden.git"] {
        let mut row = fields();
        row[0] = path.into();
        assert_eq!(records(&table(&[row.join(" ")])).unwrap()[0].route, path);
    }
    let boundary = format!("/a/{}", "b".repeat(509));
    let mut row = fields();
    row[0] = boundary.clone();
    assert_eq!(row[0].len(), 512);
    assert!(records(&table(&[row.join(" ")])).is_ok());
    for path in [
        "a/b".into(),
        "/repo.git".into(),
        "/team//repo".into(),
        "/team/repo/".into(),
        "/team/nested/repo".into(),
        "/../repo".into(),
        "/team/..".into(),
        "/./repo".into(),
        "/-team/repo".into(),
        "/team/-repo".into(),
        "/team/repo%2fchild".into(),
        "/team/repo?key".into(),
        "/team/répo".into(),
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
    for index in [1, 5, 7] {
        for path in [
            "relative".into(),
            "/bad\0path".into(),
            format!("/{}", "x".repeat(4096)),
        ] {
            let mut row = fields();
            row[index] = path;
            assert!(records(&table(&[row.join(" ")])).is_err(), "{row:?}");
        }
    }
    for invalid in [
        "",
        "write",
        "read",
        "read-write",
        "all",
        "read-only,receive",
        "source,issues",
        "receive,receive",
        "receive,",
        ",source",
        "RECEIVE",
    ] {
        assert!(services(invalid).is_err(), "{invalid}");
    }
    let all = services("receive,issues,outcomes,pulls,source").unwrap();
    assert!(all.receive && all.issues && all.outcomes && all.pulls && all.source);
    let source = services("source").unwrap();
    assert_eq!(
        source,
        HttpRepositoryServices {
            source: true,
            ..Default::default()
        }
    );
}

#[test]
fn duplicate_routes_and_identity_triples_refuse_without_cross_tenant_aliases() {
    let first = fields();
    let mut second = first.clone();
    second[2] = TenantId::from_bytes([0x55; 16]).to_string();
    assert!(
        records(&table(&[first.join(" "), second.join(" ")]))
            .unwrap_err()
            .contains("duplicate HTTP route")
    );
    second = first.clone();
    second[0] = "/other/core.git".into();
    assert!(
        records(&table(&[first.join(" "), second.join(" ")]))
            .unwrap_err()
            .contains("duplicate HTTP repository identity")
    );
    second[2] = TenantId::from_bytes([0x55; 16]).to_string();
    let parsed = records(&table(&[first.join(" "), second.join(" ")])).unwrap();
    assert_ne!(parsed[0].tenant, parsed[1].tenant);
    assert_eq!(parsed[0].repository, parsed[1].repository);
}

#[test]
fn exact_table_line_and_route_limits_have_refused_neighbors() {
    let mut exact = padded_table(MAX_TABLE_BYTES);
    assert!(records(&exact).is_ok());
    exact.push(b'\n');
    assert!(records(&exact).unwrap_err().contains("256 KiB"));
    let mut line = table(&[fields().join(" ")]);
    line.push(b'#');
    line.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES - 1));
    assert!(records(&line).is_ok());
    line.push(b'x');
    assert!(records(&line).unwrap_err().contains("16 KiB"));
    let rows: Vec<_> = (0..=MAX_HTTP_REPOSITORY_ROUTES)
        .map(|index| {
            let mut row = fields();
            row[0] = format!("/team/repo-{index}");
            row[3] = RepositoryId::from_bytes([u8::try_from(index).unwrap(); 16]).to_string();
            row.join(" ")
        })
        .collect();
    assert_eq!(
        records(&table(&rows[..MAX_HTTP_REPOSITORY_ROUTES]))
            .unwrap()
            .len(),
        MAX_HTTP_REPOSITORY_ROUTES
    );
    assert!(records(&table(&rows)).unwrap_err().contains("64 routes"));
}

#[test]
fn service_enablement_requires_both_listener_and_route_and_never_implies_a_peer() {
    let names = ["receive", "issues", "outcomes", "pulls", "source"];
    let all = services(&names.join(",")).unwrap();
    let none = HttpRepositoryServices::default();
    for name in names {
        let one = services(name).unwrap();
        assert_eq!(intersect(one, none), none);
        assert_eq!(intersect(none, one), none);
        assert_eq!(intersect(one, all), one);
        assert_eq!(intersect(all, one), one);
        for other in names.into_iter().filter(|other| *other != name) {
            assert_eq!(intersect(one, services(other).unwrap()), none);
        }
    }
}

#[test]
fn explicit_local_options_keep_existing_http_defaults_and_lifetime_bounds() {
    let defaults = arguments(&[]);
    let parsed = parse(&defaults).unwrap();
    assert_eq!(parsed.listen, "127.0.0.1:0".parse().unwrap());
    assert_eq!(parsed.limits.max_sessions(), 1024);
    assert_eq!(parsed.limits.max_in_flight(), 4);
    assert_eq!(parsed.idle_timeout, Duration::from_secs(300));
    assert_eq!(parsed.services, Default::default());
    assert!(parsed.stop.is_none());
    let flags = arguments(&[
        "--allow-receive",
        "--allow-issues",
        "--allow-outcomes",
        "--allow-pulls",
        "--allow-source",
        "--continuous",
        "--stop-file",
        "http.stop",
        "--max-in-flight",
        "16",
    ]);
    let parsed = parse(&flags).unwrap();
    assert_eq!(
        parsed.services,
        services("receive,issues,outcomes,pulls,source").unwrap()
    );
    assert_eq!(parsed.stop, Some(PathBuf::from("http.stop")));
    for address in [
        "0.0.0.0:8080",
        "[::]:8080",
        "192.0.2.1:8080",
        "localhost:8080",
        "127.0.0.1",
    ] {
        let mut args = arguments(&[]);
        args[0] = address.into();
        assert!(parse(&args).is_err(), "{address}");
    }
    let mut ipv6 = arguments(&[]);
    ipv6[0] = "[::1]:0".into();
    assert!(parse(&ipv6).is_ok());
    let mut untrusted = arguments(&[]);
    untrusted.remove(1);
    assert!(parse(&untrusted).is_err());
    for extra in [
        vec!["--continuous"],
        vec!["--stop-file", "http.stop"],
        vec![
            "--continuous",
            "--stop-file",
            "http.stop",
            "--max-sessions",
            "1",
        ],
        vec![
            "--continuous",
            "--stop-file",
            "http.stop",
            "--idle-timeout-secs",
            "1",
        ],
        vec!["--allow-source", "--allow-source"],
        vec!["--repositories-file", "/other"],
        vec!["--credentials-file", "/global-credentials"],
        vec!["--token-file", "/token"],
        vec!["--expected-incarnation", "33333333333333333333333333333333"],
        vec!["--require-lfs-payloads", "/global-lfs"],
        vec!["--lfs-root", "/lfs"],
        vec!["--artifact-root", "/artifacts"],
        vec!["--allow-discussions"],
        vec!["--allow-protection"],
        vec!["--allow-queues"],
        vec!["--allow-queue-landings"],
        vec!["--index-state", "init"],
        vec!["--workflow-trusted-local"],
        vec!["--session-secs-per-mib", "1"],
        vec!["--unknown", "value"],
    ] {
        assert!(parse(&arguments(&extra)).is_err(), "{extra:?}");
    }
}

#[test]
fn argument_and_numeric_limits_refuse_before_open() {
    for extra in [
        ["--max-sessions", "0"],
        ["--max-sessions", "1000001"],
        ["--max-in-flight", "17"],
        ["--max-in-flight", "+1"],
        ["--max-in-flight", "01"],
        ["--max-in-flight", "18446744073709551615"],
        ["--idle-timeout-secs", "86401"],
        ["--max-sessions", "--allow-receive"],
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
    let mut huge = arguments(&[]);
    huge[3] = format!("/{}", "x".repeat(4096));
    assert!(parse(&huge).is_err());
    let mut too_many = arguments(&[]);
    too_many.resize(65, "extra".into());
    assert!(parse(&too_many).is_err());
    let mut nul = arguments(&[]);
    nul[3].push('\0');
    assert!(parse(&nul).is_err());
    assert!(parse(&[]).is_err());
}

#[test]
fn cache_retention_is_divided_without_weakening_selected_transfer_profiles() {
    let record = record();
    let args = arguments(&[]);
    let options = parse(&args).unwrap();
    let whole = configuration(&record, &options, 1).unwrap();
    for count in [1, 3, MAX_HTTP_REPOSITORY_ROUTES] {
        let config = configuration(&record, &options, count).unwrap();
        for capacity in [
            NodeConfig::pack_cache_bytes as fn(&NodeConfig) -> usize,
            NodeConfig::received_pack_cache_bytes,
            NodeConfig::ancestry_metadata_cache_bytes,
        ] {
            assert_eq!(capacity(&config), capacity(&whole) / count);
        }
    }
    let args = arguments(&[
        "--pack-cache-mib",
        "7",
        "--received-pack-cache-mib",
        "11",
        "--pack-max-blob-mib",
        "96",
        "--processing-timeout-secs",
        "45",
        "--trusted-origin",
        "https://forge.example.invalid",
    ]);
    let config = configuration(&record, &parse(&args).unwrap(), 3).unwrap();
    assert_eq!(config.pack_cache_bytes(), (7 << 20) / 3);
    assert_eq!(config.received_pack_cache_bytes(), (11 << 20) / 3);
    assert_eq!(config.selected_pack_blob_limit(), Some(96 << 20));
    assert_eq!(
        config.git_daemon_receive_processing_timeout().duration(),
        Duration::from_secs(45)
    );
    for extra in [
        ["--pack-cache-mib", "65537"],
        ["--received-pack-cache-mib", "65537"],
        ["--session-timeout-secs", "3601"],
        ["--processing-timeout-secs", "0"],
        ["--receive-max-input-mib", "1025"],
        ["--receive-max-expanded-mib", "65537"],
        ["--pack-max-expanded-mib", "65537"],
        ["--pack-max-blob-mib", "0"],
        ["--trusted-origin", "not-an-origin"],
    ] {
        let args = arguments(&extra);
        assert!(
            configuration(&record, &parse(&args).unwrap(), 1).is_err(),
            "{extra:?}"
        );
    }
    assert!(configuration(&record, &options, 0).is_err());
    let args = arguments(&["--pack-cache-mib", "0", "--received-pack-cache-mib", "0"]);
    let config = configuration(&record, &parse(&args).unwrap(), 64).unwrap();
    assert_eq!(config.pack_cache_bytes(), 0);
    assert_eq!(config.received_pack_cache_bytes(), 0);
}

#[test]
fn catalog_files_require_private_unaliased_regular_custody() {
    let scratch = Scratch::new();
    let path = scratch.0.join("repositories");
    let bytes = table(&[fields().join(" ")]);
    assert!(read_table(&path).is_err());
    private_write(&path, &bytes);
    assert_eq!(read_table(&path).unwrap().len(), 1);
    for mode in [0o640, 0o604, 0o666] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(read_table(&path).is_err());
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = scratch.0.join("alias");
    fs::hard_link(&path, &alias).unwrap();
    assert!(read_table(&path).is_err());
    fs::remove_file(&alias).unwrap();
    assert!(read_table(&path).is_ok());
    symlink(&path, &alias).unwrap();
    assert!(read_table(&alias).is_err());
    assert!(read_table(&scratch.0).is_err());
    fs::write(&path, padded_table(MAX_TABLE_BYTES)).unwrap();
    assert!(read_table(&path).is_ok());
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    assert!(read_table(&path).is_err());
    fs::write(&path, table(&[fields().join(" "), "bad last row".into()])).unwrap();
    assert!(read_table(&path).is_err());
}

#[test]
fn fifo_catalog_refuses_without_waiting_for_a_writer() {
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
            .expect("catalog read waited for a FIFO writer")
            .is_err()
    );
}

#[test]
fn roots_are_canonical_disjoint_directories_before_opening_any_node() {
    let scratch = Scratch::new();
    let first = scratch.0.join("core");
    let second = scratch.0.join("core-other");
    let nested = first.join("nested");
    fs::create_dir_all(&nested).unwrap();
    fs::create_dir(&second).unwrap();
    let make = |paths: &[PathBuf]| {
        paths
            .iter()
            .map(|path| {
                let mut row = record();
                row.root = path.clone();
                row
            })
            .collect::<Vec<_>>()
    };
    let mut disjoint = make(&[first.clone(), second.clone()]);
    resolve_roots(&mut disjoint).unwrap();
    assert_eq!(disjoint[0].root, first.canonicalize().unwrap());
    let alias = scratch.0.join("alias");
    symlink(&first, &alias).unwrap();
    for paths in [
        vec![first.clone(), first.clone()],
        vec![first.clone(), alias],
        vec![first.clone(), nested.clone()],
        vec![nested, first],
        vec![second, scratch.0.join("absent")],
    ] {
        assert!(resolve_roots(&mut make(&paths)).is_err());
    }
}

fn credentials(row: &Record) -> Vec<u8> {
    let digest: String = sha256_digest("ab".repeat(32).as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("frankengit-http-credentials-v2 {} {} {}\n{digest} {PRINCIPAL} read,receive exact:726566732f68656164732f6d61696e\n", row.tenant, row.repository, row.incarnation).into_bytes()
}
fn repository(format: GitHashAlgorithm) -> (Scratch, Record) {
    let scratch = Scratch::new();
    let mut row = record();
    row.root = scratch.0.join("repository");
    row.credentials = scratch.0.join("credentials");
    let (node, _) = OneNode::init(
        NodeConfig::new(row.root.clone(), row.tenant, row.repository)
            .with_object_format(format)
            .with_worker_threads(2),
    )
    .unwrap();
    row.incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    private_write(&row.credentials, &credentials(&row));
    (scratch, row)
}

#[test]
fn canonical_repository_and_scoped_credentials_are_required_for_route_preparation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, row) = repository(format);
        let args = arguments(&[]);
        let options = parse(&args).unwrap();
        let config = configuration(&row, &options, 2).unwrap();
        let (node, route) = open_route(&row, config.clone(), Default::default()).unwrap();
        assert_eq!(node.cell_state(), CellState::Serving);
        assert_eq!(node.tenant_id(), row.tenant);
        assert_eq!(node.repository_id(), row.repository);
        assert_eq!(node.repository_incarnation_id(), row.incarnation);
        assert_eq!(node.object_format(), format);
        HttpRepositoryRoute::validate_catalog(&[route]).unwrap();
        node.shutdown().unwrap();
        let mut stale = row.clone();
        let mut id = *stale.incarnation.as_bytes();
        id[0] ^= 1;
        stale.incarnation = RepositoryIncarnationId::from_bytes(id);
        assert!(
            open_route(
                &stale,
                configuration(&stale, &options, 1).unwrap(),
                Default::default()
            )
            .is_err()
        );
        for body in [b"invalid table\n".to_vec(), credentials(&stale)] {
            fs::write(&row.credentials, body).unwrap();
            assert!(open_route(&row, config.clone(), Default::default()).is_err());
        }
        fs::write(&row.credentials, credentials(&row)).unwrap();
        let (node, _) = open_route(&row, config, Default::default()).unwrap();
        node.shutdown().unwrap();
    }
}

#[test]
fn route_lfs_custody_is_required_before_readiness_and_grants_no_transfer_endpoint() {
    let (scratch, mut row) = repository(GitHashAlgorithm::Sha256);
    row.lfs = Some(scratch.0.join("lfs"));
    let args = arguments(&[]);
    let options = parse(&args).unwrap();
    let config = configuration(&row, &options, 1).unwrap();
    assert_eq!(config.receive_lfs_root(), row.lfs.as_deref());
    assert!(config.http_lfs_root().is_none());
    assert!(open_route(&row, config.clone(), Default::default()).is_err());
    assert!(!row.lfs.as_ref().unwrap().exists());
    fs::DirBuilder::new()
        .mode(0o700)
        .create(row.lfs.as_ref().unwrap())
        .unwrap();
    let (node, _) = open_route(&row, config, Default::default()).unwrap();
    node.shutdown().unwrap();
    assert_eq!(fs::read_dir(row.lfs.unwrap()).unwrap().count(), 0);
}
