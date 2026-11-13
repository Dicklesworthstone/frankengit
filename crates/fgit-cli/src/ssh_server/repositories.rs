//! Explicit multi-repository SSH deployment. Routing is a static operator
//! configuration; every selected node still authenticates its canonical head
//! and expected incarnation. Per-repository deploy-key files remain live.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fgit_cli::CliOutcome;
use fgit_node::{
    FileDeployKeyAuthorizer, MAX_SSH_REPOSITORY_ROUTES, NodeConfig, OneNode, SshRepositoryRoute,
    SshServerLimits, SshServerReceipt,
};
use fgit_types::{RepositoryId, RepositoryIncarnationId, TenantId};

const HEADER: &str = "frankengit-ssh-repositories-v1";
const MAX_TABLE_BYTES: usize = 256 * 1024;
const MAX_LINE_BYTES: usize = 16 * 1024;

pub(super) const USAGE: &str = "usage: fg serve-ssh <listen-address>
  --repositories-file <absolute-private-file> --host-key-file <path>
  [--allow-receive] [--max-sessions <1..1000000>] [--max-in-flight <1..16>]
  [--continuous --stop-file <absent-path>]
  [--session-timeout-secs <non-zero>] [--session-secs-per-mib <n>] [--session-max-extension-secs <n>]
  [--receive-max-input-mib <non-zero>] [--receive-max-expanded-mib <non-zero>]
  [--pack-max-expanded-mib <non-zero>] [--pack-max-blob-mib <non-zero>]
  [--pack-cache-mib <0..65536>] [--received-pack-cache-mib <0..65536>]

The private table begins with frankengit-ssh-repositories-v1 and has eight fields:
  <tenant/repository.git> <absolute-storage-root> <tenant-id> <repository-id>
  <expected-incarnation> <absolute-deploy-keys-file> <read-only|read-write> <absolute-lfs-root|->
Each record occupies one line. Paths cannot contain whitespace. At most 64
nonoverlapping repositories are accepted; every incarnation is mandatory.
Writes require --allow-receive, read-write in the table, and a key's write grant.
The final field requires LFS payload custody, or '-' leaves that policy disabled.
Routing is fixed until restart; deploy-key files are reloaded at each command.
See docs/MULTI_REPOSITORY_SSH.md.";

#[derive(Clone, Debug)]
struct Record {
    route: String,
    root: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    keys: PathBuf,
    receive: bool,
    lfs: Option<PathBuf>,
}

struct Options<'a> {
    listen: &'a str,
    table: PathBuf,
    host: &'a Path,
    receive: bool,
    limits: SshServerLimits,
    stop: Option<PathBuf>,
    flags: BTreeMap<&'a str, &'a str>,
}

fn absolute_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() || value.len() > 4096 || !Path::new(value).is_absolute() {
        return Err("repository table paths must be absolute and at most 4096 bytes".into());
    }
    if value.as_bytes().contains(&0) {
        return Err("repository table paths cannot contain NUL".into());
    }
    Ok(PathBuf::from(value))
}

fn records(bytes: &[u8]) -> Result<Vec<Record>, String> {
    if bytes.len() > MAX_TABLE_BYTES {
        return Err("SSH repository table exceeds 256 KiB".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "SSH repository table must be UTF-8")?;
    let mut header = false;
    let mut result = Vec::new();
    let mut paths = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for line in text.lines() {
        if line.len() > MAX_LINE_BYTES {
            return Err("SSH repository table line exceeds 16 KiB".into());
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !header {
            if line != HEADER {
                return Err("SSH repository table requires its v1 header".into());
            }
            header = true;
            continue;
        }
        if result.len() >= MAX_SSH_REPOSITORY_ROUTES {
            return Err("SSH repository table exceeds 64 routes".into());
        }
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let [
            route,
            root,
            tenant,
            repository,
            incarnation,
            keys,
            mode,
            lfs,
        ] = fields.as_slice()
        else {
            return Err("SSH repository table rows require exactly eight fields".into());
        };
        SshRepositoryRoute::validate_path(route).map_err(|error| error.to_string())?;
        let record = Record {
            route: (*route).to_owned(),
            root: absolute_path(root)?,
            tenant: TenantId::from_hex(tenant).map_err(|_| "invalid route tenant ID")?,
            repository: RepositoryId::from_hex(repository)
                .map_err(|_| "invalid route repository ID")?,
            incarnation: RepositoryIncarnationId::from_hex(incarnation)
                .map_err(|_| "invalid route incarnation ID")?,
            keys: absolute_path(keys)?,
            receive: match *mode {
                "read-only" => false,
                "read-write" => true,
                _ => return Err("route mode must be read-only or read-write".into()),
            },
            lfs: if *lfs == "-" {
                None
            } else {
                Some(absolute_path(lfs)?)
            },
        };
        if !paths.insert(record.route.clone()) {
            return Err("duplicate SSH route path".into());
        }
        if !identities.insert((record.tenant, record.repository, record.incarnation)) {
            return Err("duplicate SSH repository identity".into());
        }
        result.push(record);
    }
    if !header || result.is_empty() {
        return Err("SSH repository table requires 1..64 routes".into());
    }
    Ok(result)
}

fn parse(arguments: &[String]) -> Result<Options<'_>, String> {
    if arguments.first().map(String::as_str) != Some("serve-ssh") || arguments.len() > 64 {
        return Err(USAGE.into());
    }
    let mut flags = BTreeMap::new();
    let mut positional = Vec::new();
    let mut receive = false;
    let mut continuous = false;
    let mut index = 1;
    while index < arguments.len() {
        let name = arguments[index].as_str();
        if name.len() > 4096 {
            return Err("SSH option exceeds 4096 bytes".into());
        }
        match name {
            "--allow-receive" if !receive => {
                receive = true;
                index += 1;
            }
            "--continuous" if !continuous => {
                continuous = true;
                index += 1;
            }
            "--allow-receive" | "--continuous" => return Err(format!("duplicate {name}")),
            value if value.starts_with("--") => {
                if !matches!(
                    name,
                    "--repositories-file"
                        | "--host-key-file"
                        | "--max-sessions"
                        | "--max-in-flight"
                        | "--stop-file"
                ) && (!crate::guarded_git_server::SESSION_AND_ENVELOPE_FLAGS.contains(&name)
                    || name == "--require-lfs-payloads")
                {
                    return Err(USAGE.into());
                }
                let value = arguments.get(index + 1).ok_or_else(|| USAGE.to_owned())?;
                if value.is_empty() || value.len() > 4096 || value.starts_with("--") {
                    return Err(format!("invalid value for {name}"));
                }
                if flags.insert(name, value.as_str()).is_some() {
                    return Err(format!("duplicate {name}"));
                }
                index += 2;
            }
            value => {
                positional.push(value);
                index += 1;
            }
        }
    }
    let [listen] = positional.as_slice() else {
        return Err(USAGE.into());
    };
    let table = absolute_path(
        flags
            .get("--repositories-file")
            .ok_or_else(|| USAGE.to_owned())?,
    )?;
    let host = Path::new(
        *flags
            .get("--host-key-file")
            .ok_or_else(|| USAGE.to_owned())?,
    );
    let sessions = flags
        .get("--max-sessions")
        .map(|value| super::integer(value, "--max-sessions", false))
        .transpose()?
        .unwrap_or(1000);
    let in_flight = flags
        .get("--max-in-flight")
        .map(|value| super::integer(value, "--max-in-flight", false))
        .transpose()?
        .unwrap_or(16);
    let limits = SshServerLimits::try_new(
        usize::try_from(sessions).map_err(|_| "SSH session limit exceeds platform")?,
        usize::try_from(in_flight).map_err(|_| "SSH in-flight limit exceeds platform")?,
    )
    .map_err(|error| error.to_string())?;
    let stop = match (continuous, flags.get("--stop-file")) {
        (false, None) => None,
        (true, Some(path)) if !flags.contains_key("--max-sessions") => Some(PathBuf::from(*path)),
        _ => return Err("--continuous requires --stop-file and excludes --max-sessions".into()),
    };
    Ok(Options {
        listen,
        table,
        host,
        receive,
        limits,
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
        .map_err(|error| format!("cannot inspect SSH repository table: {error}"))?;
    if !private(&before) {
        return Err("SSH repository table must be a private regular file, at most 256 KiB".into());
    }
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| format!("cannot open SSH repository table: {error}"))?;
    let mut file = fs::File::from(fd);
    let opened = file.metadata().map_err(|error| error.to_string())?;
    if !private(&opened) || stamp(&before) != stamp(&opened) {
        return Err("SSH repository table changed while opening".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_TABLE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read SSH repository table: {error}"))?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    let named = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !private(&after)
        || !private(&named)
        || stamp(&opened) != stamp(&after)
        || stamp(&opened) != stamp(&named)
        || bytes.len() as u64 != opened.len()
    {
        return Err("SSH repository table changed while reading".into());
    }
    records(&bytes)
}

#[cfg(not(unix))]
fn read_table(_path: &Path) -> Result<Vec<Record>, String> {
    Err("multi-repository SSH requires the Unix private-file profile".into())
}

/// Resolve every root before opening any node. This cannot grant access: later
/// open_existing still verifies each exact expected canonical incarnation.
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
            return Err("SSH repository roots must be existing disjoint directories".into());
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
    let mut config = crate::guarded_git_server::apply_session_and_envelope_flags(
        NodeConfig::new(record.root.clone(), record.tenant, record.repository)
            .with_expected_repository_incarnation(record.incarnation),
        &options.flags,
    )?;
    // Cache flags are budgets for the listener, not a multiplier per route.
    // Each route keeps independent content/authorization domains.
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
    Ok(config)
}

fn open_route(
    record: &Record,
    config: NodeConfig,
    receive: bool,
) -> Result<(OneNode, SshRepositoryRoute), String> {
    let authorizer = Arc::new(
        FileDeployKeyAuthorizer::try_new(record.keys.clone(), record.repository, record.repository)
            .map_err(|error| format!("invalid route deploy keys: {error}"))?,
    );
    let mut node = OneNode::open_existing(config).map_err(|error| error.to_string())?;
    let prepared = (|| {
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
        SshRepositoryRoute::try_new(
            record.route.clone(),
            &node,
            authorizer,
            receive && record.receive,
        )
        .map_err(|error| error.to_string())
    })();
    match prepared {
        Ok(route) => Ok((node, route)),
        Err(error) => match node.shutdown() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!(
                "SSH route preparation failed ({error}); shutdown failed ({cleanup})"
            )),
        },
    }
}

pub(super) fn run(arguments: &[String]) -> Result<CliOutcome, String> {
    let options = parse(arguments)?;
    let mut records = read_table(&options.table)?;
    resolve_roots(&mut records)?;
    let configurations = records
        .iter()
        .map(|record| configuration(record, &options, records.len()))
        .collect::<Result<Vec<_>, _>>()?;
    let host = super::read_host_key(options.host)?;
    let stop = options
        .stop
        .as_ref()
        .map(|path| crate::service_stop::StopFile::arm(path))
        .transpose()
        .map_err(|error| format!("cannot arm SSH stop control: {error}"))?;
    let mut configurations = configurations.into_iter();
    let first = configurations
        .next()
        .ok_or_else(|| "SSH route table is empty".to_owned())?;
    let (anchor, first_route) = open_route(&records[0], first, options.receive)?;
    let serving: Result<(std::net::SocketAddr, SshServerReceipt), String> = (|| {
        let mut routes = vec![first_route];
        for (record, config) in records.iter().skip(1).zip(configurations) {
            let (node, route) = open_route(record, config, options.receive)?;
            node.shutdown()
                .map_err(|error| format!("route startup shutdown failed: {error}"))?;
            routes.push(route);
        }
        let listener = TcpListener::bind(options.listen).map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let control = stop.as_ref().map(crate::service_stop::StopControl::new);
        let mut out = io::stdout().lock();
        writeln!(out, "{{\"type\":\"ssh_listening\",\"schema_version\":1,\"address\":\"{address}\",\"routing\":\"explicit-v1\",\"repositories\":{},\"allow_receive\":{},\"lifetime\":\"{}\"}}",
            routes.len(), options.receive, if control.is_some() { "continuous" } else { "bounded" })
            .and_then(|()| out.flush()).map_err(|error| format!("cannot report SSH readiness: {error}"))?;
        drop(out);
        let receipt = if let Some(control) = control {
            anchor.serve_ssh_routes_until_stopped(
                listener,
                options.limits.max_in_flight,
                host,
                routes,
                &|| control.should_stop(),
            )
        } else {
            anchor.serve_ssh_routes_bounded(&listener, options.limits, host, routes)
        }
        .map_err(|error| error.to_string())?;
        Ok((address, receipt))
    })();
    let cleanup = anchor.shutdown();
    let (address, service) = match (serving, cleanup) {
        (Ok(result), Ok(())) => result,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => {
            return Err(format!(
                "SSH service completed but shutdown failed: {error}"
            ));
        }
        (Err(error), Err(cleanup)) => {
            return Err(format!(
                "SSH service failed ({error}); shutdown failed ({cleanup})"
            ));
        }
    };
    if stop.is_some() {
        let mut out = io::stdout().lock();
        writeln!(out, "{{\"type\":\"ssh_drained\",\"schema_version\":1,\"accepted\":{},\"completed_transports\":{},\"refused_transports\":{},\"lifetime\":\"continuous\"}}",
            service.accepted_sessions(), service.completed_sessions(), service.refused_sessions())
            .and_then(|()| out.flush()).map_err(|error| format!("cannot report SSH drain: {error}"))?;
        Ok(CliOutcome::ContinuouslyServed {
            listen_address: address,
            service,
            receive_path: "ssh-routed-admission",
            unauthenticated_network_push: false,
        })
    } else {
        Ok(CliOutcome::Served {
            listen_address: address,
            service,
            receive_path: "ssh-routed-admission",
            unauthenticated_network_push: false,
        })
    }
}

#[cfg(test)]
#[path = "repositories/tests.rs"]
mod tests;
