//! Explicit multi-repository HTTP deployment. The catalog is an immutable
//! routing hint; each entry authenticates an existing canonical incarnation
//! and keeps its own live credential source and publication boundaries.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fgit_node::smart_http::server::{
    HttpRepositoryRoute, HttpRepositoryServices, MAX_HTTP_REPOSITORY_ROUTES,
};
use fgit_node::{
    GitDaemonReceiveProcessingTimeout, GitDaemonServerLimits, GitDaemonServerReceipt,
    GitDaemonSessionTimeout, HttpTrustedOrigin, NodeConfig, OneNode,
};
use fgit_types::{RepositoryId, RepositoryIncarnationId, TenantId};

const HEADER: &str = "frankengit-http-repositories-v1";
const MAX_TABLE_BYTES: usize = 256 * 1024;
const MAX_LINE_BYTES: usize = 16 * 1024;

pub(super) const USAGE: &str = "usage: fg serve-http <numeric-loopback-address>
  --trusted-local --repositories-file <absolute-private-file>
  [--allow-receive] [--allow-issues] [--allow-outcomes] [--allow-pulls] [--allow-source]
  [--max-sessions <1..1000000>] [--max-in-flight <1..16>]
  [--idle-timeout-secs <1..86400>] [--session-timeout-secs <1..3600>]
  [--processing-timeout-secs <1..3600>] [--continuous --stop-file <absent-path>]
  [--receive-max-input-mib <1..1024>] [--receive-max-expanded-mib <1..65536>]
  [--pack-max-expanded-mib <1..65536>] [--pack-max-blob-mib <non-zero>]
  [--pack-cache-mib <0..65536>] [--received-pack-cache-mib <0..65536>]
  [--trusted-origin <origin>]

The private table begins with frankengit-http-repositories-v1 and has eight fields:
  </tenant/repository.git> <absolute-storage-root> <tenant-id> <repository-id>
  <expected-incarnation> <absolute-credentials-file> <services> <required-lfs-root|->
Services are read-only (Git reads only), or a comma-separated subset in this order:
receive,issues,outcomes,pulls,source. Every selected service also requires its
--allow-* listener flag and the requesting token's independent credential scope.
No service implies another. Git reads always require the selected route's read
credential. At most 64 disjoint existing repositories are accepted. Catalog
paths are exact, fixed until restart, and never filesystem lookup paths. Live
credential tables reload at each request. The last field enables receive LFS
payload custody only; it grants no LFS transfer endpoint or credential scope.
No global credential, principal, incarnation, LFS, artifact, index or workflow
options are accepted in catalog mode. Continuous mode requires a stop file and
excludes --max-sessions and --idle-timeout-secs. The listener remains loopback-only.
See docs/MULTI_REPOSITORY_HTTP.md.";

#[derive(Clone, Debug)]
struct Record {
    route: String,
    root: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    credentials: PathBuf,
    services: HttpRepositoryServices,
    lfs: Option<PathBuf>,
}

struct Options<'a> {
    listen: SocketAddr,
    table: PathBuf,
    services: HttpRepositoryServices,
    limits: GitDaemonServerLimits,
    idle_timeout: Duration,
    stop: Option<PathBuf>,
    flags: BTreeMap<&'a str, &'a str>,
}

fn absolute_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty()
        || value.len() > 4096
        || !Path::new(value).is_absolute()
        || value.as_bytes().contains(&0)
    {
        return Err(
            "repository table paths must be absolute, non-NUL and at most 4096 bytes".into(),
        );
    }
    Ok(PathBuf::from(value))
}

fn services(value: &str) -> Result<HttpRepositoryServices, String> {
    let mut result = HttpRepositoryServices::default();
    if value == "read-only" {
        return Ok(result);
    }
    let mut previous = 0;
    for name in value.split(',') {
        let (order, enabled) = match name {
            "receive" => (1, &mut result.receive),
            "issues" => (2, &mut result.issues),
            "outcomes" => (3, &mut result.outcomes),
            "pulls" => (4, &mut result.pulls),
            "source" => (5, &mut result.source),
            _ => return Err("unknown HTTP repository service".into()),
        };
        if order <= previous {
            return Err("HTTP repository services must be unique and in canonical order".into());
        }
        *enabled = true;
        previous = order;
    }
    Ok(result)
}

fn intersect(
    row: HttpRepositoryServices,
    listener: HttpRepositoryServices,
) -> HttpRepositoryServices {
    HttpRepositoryServices {
        receive: row.receive && listener.receive,
        issues: row.issues && listener.issues,
        outcomes: row.outcomes && listener.outcomes,
        pulls: row.pulls && listener.pulls,
        source: row.source && listener.source,
    }
}

fn records(bytes: &[u8]) -> Result<Vec<Record>, String> {
    if bytes.len() > MAX_TABLE_BYTES {
        return Err("HTTP repository table exceeds 256 KiB".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "HTTP repository table must be UTF-8")?;
    let mut header = false;
    let mut result = Vec::new();
    let mut paths = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for line in text.lines() {
        if line.len() > MAX_LINE_BYTES {
            return Err("HTTP repository table line exceeds 16 KiB".into());
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !header {
            if line != HEADER {
                return Err("HTTP repository table requires its v1 header".into());
            }
            header = true;
            continue;
        }
        if result.len() >= MAX_HTTP_REPOSITORY_ROUTES {
            return Err("HTTP repository table exceeds 64 routes".into());
        }
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let [
            route,
            root,
            tenant,
            repository,
            incarnation,
            credentials,
            selected,
            lfs,
        ] = fields.as_slice()
        else {
            return Err("HTTP repository table rows require exactly eight fields".into());
        };
        HttpRepositoryRoute::validate_path(route).map_err(|error| error.to_string())?;
        let record = Record {
            route: (*route).to_owned(),
            root: absolute_path(root)?,
            tenant: TenantId::from_hex(tenant).map_err(|_| "invalid route tenant ID")?,
            repository: RepositoryId::from_hex(repository)
                .map_err(|_| "invalid route repository ID")?,
            incarnation: RepositoryIncarnationId::from_hex(incarnation)
                .map_err(|_| "invalid route incarnation ID")?,
            credentials: absolute_path(credentials)?,
            services: services(selected)?,
            lfs: if *lfs == "-" {
                None
            } else {
                Some(absolute_path(lfs)?)
            },
        };
        if !paths.insert(record.route.clone()) {
            return Err("duplicate HTTP route path".into());
        }
        if !identities.insert((record.tenant, record.repository, record.incarnation)) {
            return Err("duplicate HTTP repository identity".into());
        }
        result.push(record);
    }
    if !header || result.is_empty() {
        return Err("HTTP repository table requires 1..64 routes".into());
    }
    Ok(result)
}

fn number(
    flags: &BTreeMap<&str, &str>,
    name: &str,
    default: u64,
    maximum: u64,
) -> Result<u64, String> {
    let Some(value) = flags.get(name) else {
        return Ok(default);
    };
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!("{name} requires a canonical positive decimal"));
    }
    let value = value
        .parse::<u64>()
        .map_err(|_| format!("{name} is out of range"))?;
    if value == 0 || value > maximum {
        return Err(format!("{name} must be in 1..={maximum}"));
    }
    Ok(value)
}

fn parse(arguments: &[String]) -> Result<Options<'_>, String> {
    if arguments.is_empty()
        || arguments.len() > 64
        || arguments
            .iter()
            .any(|arg| arg.len() > 4096 || arg.as_bytes().contains(&0))
        || arguments.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err(USAGE.into());
    }
    let listen: SocketAddr = arguments[0]
        .parse()
        .map_err(|_| "expected a numeric loopback socket address")?;
    if !listen.ip().is_loopback() {
        return Err("serve-http refuses non-loopback plaintext listeners".into());
    }
    let mut flags = BTreeMap::new();
    let mut index = 1;
    while index < arguments.len() {
        let name = arguments[index].as_str();
        index += 1;
        let boolean = matches!(
            name,
            "--trusted-local"
                | "--allow-receive"
                | "--allow-issues"
                | "--allow-outcomes"
                | "--allow-pulls"
                | "--allow-source"
                | "--continuous"
        );
        if !boolean
            && !matches!(
                name,
                "--repositories-file"
                    | "--max-sessions"
                    | "--max-in-flight"
                    | "--idle-timeout-secs"
                    | "--session-timeout-secs"
                    | "--processing-timeout-secs"
                    | "--receive-max-input-mib"
                    | "--receive-max-expanded-mib"
                    | "--pack-max-expanded-mib"
                    | "--pack-max-blob-mib"
                    | "--pack-cache-mib"
                    | "--received-pack-cache-mib"
                    | "--trusted-origin"
                    | "--stop-file"
            )
        {
            return Err(format!(
                "unsupported serve-http catalog option {name}\n{USAGE}"
            ));
        }
        let value = if boolean {
            ""
        } else {
            let value = arguments
                .get(index)
                .ok_or_else(|| format!("missing value for {name}"))?;
            index += 1;
            if value.is_empty() || value.starts_with("--") {
                return Err(format!("missing value for {name}"));
            }
            value.as_str()
        };
        if flags.insert(name, value).is_some() {
            return Err(format!("duplicate serve-http catalog option {name}"));
        }
    }
    if !flags.contains_key("--trusted-local") {
        return Err(
            "--trusted-local is required for this operator-owned capability profile".into(),
        );
    }
    let table = absolute_path(
        flags
            .get("--repositories-file")
            .ok_or_else(|| USAGE.to_owned())?,
    )?;
    let stop = match (flags.contains_key("--continuous"), flags.get("--stop-file")) {
        (false, None) => None,
        (true, Some(path))
            if !flags.contains_key("--max-sessions")
                && !flags.contains_key("--idle-timeout-secs") =>
        {
            Some(PathBuf::from(*path))
        }
        _ => return Err(
            "--continuous requires --stop-file and excludes --max-sessions and --idle-timeout-secs"
                .into(),
        ),
    };
    let limits = GitDaemonServerLimits::try_new(
        number(&flags, "--max-sessions", 1024, 1_000_000)? as usize,
        number(&flags, "--max-in-flight", 4, 16)? as usize,
    )
    .map_err(|error| error.to_string())?;
    let idle_timeout = Duration::from_secs(number(&flags, "--idle-timeout-secs", 300, 86400)?);
    Ok(Options {
        listen,
        table,
        services: HttpRepositoryServices {
            receive: flags.contains_key("--allow-receive"),
            issues: flags.contains_key("--allow-issues"),
            outcomes: flags.contains_key("--allow-outcomes"),
            pulls: flags.contains_key("--allow-pulls"),
            source: flags.contains_key("--allow-source"),
        },
        limits,
        idle_timeout,
        stop,
        flags,
    })
}

#[cfg(unix)]
fn read_table(path: &Path) -> Result<Vec<Record>, String> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let private = |meta: &fs::Metadata| {
        meta.is_file()
            && meta.mode() & 0o077 == 0
            && meta.nlink() == 1
            && meta.len() <= MAX_TABLE_BYTES as u64
    };
    let stamp = |meta: &fs::Metadata| {
        (
            meta.dev(),
            meta.ino(),
            meta.len(),
            meta.mode(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
        )
    };
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect HTTP repository table: {error}"))?;
    if !private(&before) {
        return Err("HTTP repository table must be a private regular file, at most 256 KiB".into());
    }
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| format!("cannot open HTTP repository table: {error}"))?;
    let mut file = fs::File::from(fd);
    let opened = file.metadata().map_err(|error| error.to_string())?;
    if !private(&opened) || stamp(&before) != stamp(&opened) {
        return Err("HTTP repository table changed while opening".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_TABLE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read HTTP repository table: {error}"))?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    let named = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !private(&after)
        || !private(&named)
        || stamp(&opened) != stamp(&after)
        || stamp(&opened) != stamp(&named)
        || bytes.len() as u64 != opened.len()
    {
        return Err("HTTP repository table changed while reading".into());
    }
    records(&bytes)
}

#[cfg(not(unix))]
fn read_table(_path: &Path) -> Result<Vec<Record>, String> {
    Err("multi-repository HTTP requires the Unix private-file profile".into())
}

/// Canonicalize every root before opening any node, rejecting aliases and
/// parent/child layouts. Later open_existing still authenticates each head.
fn resolve_roots(records: &mut [Record]) -> Result<(), String> {
    let mut roots = Vec::<PathBuf>::new();
    for record in records {
        let root = record
            .root
            .canonicalize()
            .map_err(|error| format!("cannot resolve repository root: {error}"))?;
        if !root.is_dir()
            || roots
                .iter()
                .any(|previous| root.starts_with(previous) || previous.starts_with(&root))
        {
            return Err("HTTP repository roots must be existing disjoint directories".into());
        }
        record.root = root.clone();
        roots.push(root);
    }
    Ok(())
}

fn configuration(
    record: &Record,
    options: &Options<'_>,
    count: usize,
) -> Result<NodeConfig, String> {
    if !(1..=MAX_HTTP_REPOSITORY_ROUTES).contains(&count) {
        return Err("HTTP repository table requires 1..64 routes".into());
    }
    let flags = &options.flags;
    let timeout = GitDaemonSessionTimeout::try_new(Duration::from_secs(number(
        flags,
        "--session-timeout-secs",
        300,
        3600,
    )?))
    .map_err(|error| error.to_string())?;
    let processing = GitDaemonReceiveProcessingTimeout::try_new(Duration::from_secs(number(
        flags,
        "--processing-timeout-secs",
        300,
        3600,
    )?))
    .map_err(|error| error.to_string())?;
    let bytes = |name, default, maximum| -> Result<usize, String> {
        usize::try_from(number(flags, name, default, maximum)? * 1024 * 1024)
            .map_err(|_| "byte envelope is not supported on this platform".into())
    };
    let mut config = NodeConfig::new(record.root.clone(), record.tenant, record.repository)
        .with_expected_repository_incarnation(record.incarnation)
        .with_git_daemon_session_timeout(timeout)
        .with_git_daemon_receive_processing_timeout(processing)
        .with_git_daemon_receive_byte_envelope(
            Some(bytes("--receive-max-input-mib", 128, 1024)?),
            Some(bytes("--receive-max-expanded-mib", 4096, 65536)?),
        );
    if flags.contains_key("--pack-max-expanded-mib") {
        config =
            config.with_selected_pack_byte_envelope(bytes("--pack-max-expanded-mib", 1, 65536)?);
    }
    if let Some(value) = flags.get("--pack-max-blob-mib") {
        config = config.with_selected_pack_blob_limit(
            fgit_cli::parse_pack_blob_mib(value).map_err(|error| error.to_string())?,
        );
    }
    if let Some(value) = flags.get("--pack-cache-mib") {
        config = config.with_pack_cache_bytes(
            fgit_cli::parse_pack_cache_mib(value).map_err(|error| error.to_string())?,
        );
    }
    if let Some(value) = flags.get("--received-pack-cache-mib") {
        config = config.with_received_pack_cache_bytes(
            fgit_cli::parse_received_pack_cache_mib(value).map_err(|error| error.to_string())?,
        );
    }
    // These are listener-wide retention budgets, divided across independent
    // repository domains. No cache or node pool is keyed only by a path alias.
    let computed = config.pack_cache_bytes() / count;
    let received = config.received_pack_cache_bytes() / count;
    let ancestry = config.ancestry_metadata_cache_bytes() / count;
    config = config
        .with_pack_cache_bytes(computed)
        .with_received_pack_cache_bytes(received)
        .with_ancestry_metadata_cache_bytes(ancestry);
    if let Some(root) = &record.lfs {
        config = config.with_receive_lfs_root(root.clone());
    }
    if let Some(origin) = flags.get("--trusted-origin") {
        config = config.with_http_trusted_origin(
            HttpTrustedOrigin::try_new(origin).map_err(|error| error.to_string())?,
        );
    }
    Ok(config)
}

fn open_route(
    record: &Record,
    config: NodeConfig,
    listener: HttpRepositoryServices,
) -> Result<(OneNode, HttpRepositoryRoute), String> {
    let mut node = OneNode::open_existing(config).map_err(|error| error.to_string())?;
    let prepared = (|| {
        node.validate_smart_http_credentials_file(&record.credentials)
            .map_err(|error| error.to_string())?;
        node.validate_receive_lfs_storage()
            .map_err(|code| format!("cannot open required LFS custody: {code:?}"))?;
        let generation = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|error| error.to_string())?
            .receipt()
            .generation();
        node.bring_into_service(generation)
            .map_err(|error| error.to_string())?;
        HttpRepositoryRoute::try_new(
            record.route.clone(),
            &node,
            &record.credentials,
            intersect(record.services, listener),
        )
        .map_err(|error| error.to_string())
    })();
    match prepared {
        Ok(route) => Ok((node, route)),
        Err(error) => match node.shutdown() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!(
                "HTTP route preparation failed ({error}); shutdown failed ({cleanup})"
            )),
        },
    }
}

pub(super) fn run(arguments: &[String]) -> Result<u8, String> {
    let options = parse(arguments)?;
    let mut records = read_table(&options.table)?;
    resolve_roots(&mut records)?;
    let configurations = records
        .iter()
        .map(|record| configuration(record, &options, records.len()))
        .collect::<Result<Vec<_>, _>>()?;
    let stop = options
        .stop
        .as_ref()
        .map(|path| crate::service_stop::StopFile::arm(path))
        .transpose()
        .map_err(|error| format!("cannot arm HTTP stop control: {error}"))?;
    let mut configurations = configurations.into_iter();
    let first = configurations
        .next()
        .ok_or("HTTP repository table is empty")?;
    let (anchor, first_route) = open_route(&records[0], first, options.services)?;
    let serving: Result<GitDaemonServerReceipt, String> = (|| {
        let mut routes = vec![first_route];
        for (record, config) in records.iter().skip(1).zip(configurations) {
            let (node, route) = open_route(record, config, options.services)?;
            node.shutdown()
                .map_err(|error| format!("route startup shutdown failed: {error}"))?;
            routes.push(route);
        }
        HttpRepositoryRoute::validate_catalog(&routes).map_err(|error| error.to_string())?;
        let control = stop.as_ref().map(crate::service_stop::StopControl::new);
        if let Some(control) = &control
            && control
                .should_stop()
                .map_err(|error| format!("cannot inspect HTTP stop control: {error}"))?
        {
            return Err("HTTP stop requested during catalog startup".into());
        }
        let listener = TcpListener::bind(options.listen)
            .map_err(|error| format!("cannot bind HTTP listener: {error}"))?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let mut output = io::stdout().lock();
        writeln!(output, "{{\"type\":\"smart_http_listening\",\"schema_version\":1,\"address\":\"{address}\",\"routing\":\"explicit-v1\",\"repositories\":{},\"credential_mode\":\"reloadable\",\"lifetime\":\"{}\"}}",
            routes.len(), if control.is_some() { "continuous" } else { "bounded" })
            .and_then(|()| output.flush()).map_err(|error| format!("cannot report HTTP readiness: {error}"))?;
        drop(output);
        if let Some(control) = control {
            anchor.serve_http_repositories_until_stopped(
                &listener,
                options.limits.max_in_flight(),
                routes,
                &|| control.should_stop(),
            )
        } else {
            anchor.serve_http_repositories_bounded(
                &listener,
                options.limits,
                routes,
                options.idle_timeout,
            )
        }
        .map_err(|error| error.to_string())
    })();
    let receipt = match (serving, anchor.shutdown()) {
        (Ok(receipt), Ok(())) => receipt,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => {
            return Err(format!(
                "HTTP service drained but node shutdown failed: {error}"
            ));
        }
        (Err(error), Err(cleanup)) => {
            return Err(format!(
                "HTTP service failed ({error}); node shutdown also failed ({cleanup})"
            ));
        }
    };
    let mut output = io::stdout().lock();
    writeln!(output, "{{\"type\":\"smart_http_drained\",\"schema_version\":1,\"accepted\":{},\"completed_transports\":{},\"refused_transports\":{}}}",
        receipt.accepted_sessions(), receipt.completed_sessions(), receipt.refused_sessions())
        .and_then(|()| output.flush()).map_err(|error| format!("cannot report HTTP drain: {error}"))?;
    Ok(0)
}

#[cfg(test)]
#[path = "repositories/tests.rs"]
mod tests;
