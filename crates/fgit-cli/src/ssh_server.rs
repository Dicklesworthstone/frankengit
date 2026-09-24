//! Executable `fg serve-ssh` binding for the pure-Rust SSH transport service.
//!
//! Provides bounded SSH listener execution with host key configuration,
//! deploy-key authentication, and typed Git command dispatch (`git-upload-pack`
//! and `git-receive-pack`).

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

use fgit_cli::CliOutcome;
use fgit_crypto::sha256_digest;
use fgit_identity::deploy_key::{DeployKeyBinding, DeployKeyScope};
use fgit_node::{
    NodeConfig, OneNode, RepositoryResolutionInput, SshServerLimits, SshServerReceipt,
};
use fgit_ssh::SigningKey;
use fgit_types::{PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};

const USAGE: &str = "usage: fg serve-ssh <storage-root> <tenant-id> <repository-id> <listen-address>
  --host-key-file <path>
  (--deploy-key <pubkey-hex> --principal <principal-id-hex> --scopes <read|write|read,write> | --deploy-keys-file <path>)
  [--allow-receive]
  [--expected-incarnation <id>]
  [--max-sessions <1..1000000>]
  [--max-in-flight <1..16>]";

struct Prepared {
    configuration: NodeConfig,
    listen: String,
    limits: SshServerLimits,
    host_signing_key: SigningKey,
    deploy_keys: Vec<DeployKeyBinding>,
    allow_receive: bool,
}

fn integer(value: &str, flag: &str, zero: bool) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid {flag}: expected a decimal integer"));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|n| zero || *n != 0)
        .ok_or_else(|| format!("invalid {flag}: integer is zero or out of range"))
}

fn parse_hex_key_32(hex_str: &str, desc: &str) -> Result<[u8; 32], String> {
    let clean = hex_str.trim();
    if clean.len() != 64 {
        return Err(format!(
            "invalid {desc}: expected 64 hex characters (32 bytes), got {}",
            clean.len()
        ));
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let slice = &clean[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(slice, 16)
            .map_err(|_| format!("invalid {desc}: invalid hex byte at position {i}"))?;
    }
    Ok(bytes)
}

fn read_host_key(path: &Path) -> Result<SigningKey, String> {
    let content = fs::read(path).map_err(|e| format!("cannot read host key file: {e}"))?;
    let key_bytes = if content.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&content);
        arr
    } else {
        let text = std::str::from_utf8(&content)
            .map_err(|_| "host key file contains invalid UTF-8 hex")?;
        parse_hex_key_32(text, "host signing key")?
    };
    Ok(SigningKey::from_bytes(&key_bytes))
}

fn parse_scopes(text: &str) -> Result<Vec<DeployKeyScope>, String> {
    let mut scopes = Vec::new();
    for part in text.split(',') {
        match part.trim() {
            "read" => scopes.push(DeployKeyScope::Read),
            "write" => scopes.push(DeployKeyScope::Write),
            other => {
                return Err(format!(
                    "invalid deploy key scope `{other}`; expected `read` or `write`"
                ));
            }
        }
    }
    if scopes.is_empty() {
        return Err("no deploy key scopes specified".into());
    }
    Ok(scopes)
}

fn read_deploy_keys_file(
    path: &Path,
    repo_id: RepositoryId,
    route_repo_id: RepositoryId,
) -> Result<Vec<DeployKeyBinding>, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("cannot read deploy keys file: {e}"))?;
    let mut bindings = Vec::new();
    for (line_no, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(format!(
                "invalid deploy keys file line {}: expected `<pubkey-hex> <principal-hex> <scopes>`",
                line_no + 1
            ));
        }
        let pub_bytes = parse_hex_key_32(parts[0], "deploy public key")?;
        let principal = PrincipalId::from_hex(parts[1])
            .map_err(|e| format!("line {}: invalid principal: {e}", line_no + 1))?;
        let scopes = parse_scopes(parts[2])?;

        let fgit_key = fgit_crypto::VerifyingKey::from_bytes(pub_bytes);
        let b1 = DeployKeyBinding::register(repo_id, principal, fgit_key, &scopes)
            .map_err(|e| format!("line {}: cannot register deploy key: {e}", line_no + 1))?;
        bindings.push(b1);

        if route_repo_id != repo_id {
            let b2 = DeployKeyBinding::register(route_repo_id, principal, fgit_key, &scopes)
                .map_err(|e| format!("line {}: cannot register deploy key: {e}", line_no + 1))?;
            bindings.push(b2);
        }
    }
    Ok(bindings)
}

fn parse(arguments: &[String]) -> Result<Prepared, String> {
    if arguments.first().map(String::as_str) != Some("serve-ssh") {
        return Err(USAGE.into());
    }
    let mut flags = BTreeMap::new();
    let mut positional = Vec::new();
    let mut allow_receive = false;

    let mut index = 1;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if argument == "--allow-receive" {
            allow_receive = true;
            index += 1;
        } else if argument.starts_with("--") {
            if !matches!(
                argument,
                "--host-key-file"
                    | "--deploy-key"
                    | "--principal"
                    | "--scopes"
                    | "--deploy-keys-file"
                    | "--expected-incarnation"
                    | "--max-sessions"
                    | "--max-in-flight"
            ) {
                return Err(USAGE.into());
            }
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| USAGE.to_owned())?
                .as_str();
            if flags.insert(argument, value).is_some() {
                return Err(format!("duplicate {argument}"));
            }
            index += 2;
        } else {
            positional.push(argument);
            index += 1;
        }
    }

    let [root, tenant, repository, listen] = positional.as_slice() else {
        return Err(USAGE.into());
    };

    let sessions = flags
        .get("--max-sessions")
        .map(|v| integer(v, "--max-sessions", false))
        .transpose()?
        .unwrap_or(1000);
    let in_flight = flags
        .get("--max-in-flight")
        .map(|v| integer(v, "--max-in-flight", false))
        .transpose()?
        .unwrap_or(16);

    let limits = SshServerLimits::try_new(sessions as usize, in_flight as usize)
        .map_err(|e| e.to_string())?;

    let tenant = TenantId::from_hex(tenant).map_err(|e| e.to_string())?;
    let repository = RepositoryId::from_hex(repository).map_err(|e| e.to_string())?;

    let host_key_file = flags
        .get("--host-key-file")
        .ok_or_else(|| "--host-key-file is required".to_owned())?;
    let host_signing_key = read_host_key(Path::new(host_key_file))?;

    let route_digest = sha256_digest(format!("{repository}.git").as_bytes());
    let mut route_repo_bytes = [0u8; 16];
    route_repo_bytes.copy_from_slice(&route_digest[..16]);
    let route_repo_id = RepositoryId::from_bytes(route_repo_bytes);

    let mut deploy_keys = Vec::new();
    if let Some(path_str) = flags.get("--deploy-keys-file") {
        deploy_keys.extend(read_deploy_keys_file(
            Path::new(path_str),
            repository,
            route_repo_id,
        )?);
    } else if let Some(key_hex) = flags.get("--deploy-key") {
        let principal_hex = flags
            .get("--principal")
            .ok_or_else(|| "--principal is required when --deploy-key is specified".to_owned())?;
        let scopes_str = flags
            .get("--scopes")
            .ok_or_else(|| "--scopes is required when --deploy-key is specified".to_owned())?;

        let pub_bytes = parse_hex_key_32(key_hex, "deploy key")?;
        let principal = PrincipalId::from_hex(principal_hex).map_err(|e| e.to_string())?;
        let scopes = parse_scopes(scopes_str)?;

        let fgit_key = fgit_crypto::VerifyingKey::from_bytes(pub_bytes);
        let b1 = DeployKeyBinding::register(repository, principal, fgit_key, &scopes)
            .map_err(|e| format!("cannot register deploy key: {e}"))?;
        deploy_keys.push(b1);

        if route_repo_id != repository {
            let b2 = DeployKeyBinding::register(route_repo_id, principal, fgit_key, &scopes)
                .map_err(|e| format!("cannot register deploy key: {e}"))?;
            deploy_keys.push(b2);
        }
    } else {
        return Err("either --deploy-key or --deploy-keys-file must be provided".into());
    }

    let mut configuration = NodeConfig::new(PathBuf::from(*root), tenant, repository);
    if let Some(value) = flags.get("--expected-incarnation") {
        configuration =
            configuration.with_resolution_input(RepositoryResolutionInput::TransportTarget(
                RepositoryIncarnationId::from_hex(value).map_err(|e| e.to_string())?,
            ));
    }

    Ok(Prepared {
        configuration,
        listen: (*listen).to_owned(),
        limits,
        host_signing_key,
        deploy_keys,
        allow_receive,
    })
}

pub fn run(arguments: &[String]) -> Result<CliOutcome, String> {
    let prepared = parse(arguments)?;
    let listener = TcpListener::bind(&prepared.listen).map_err(|e| e.to_string())?;
    let listen_address = listener.local_addr().map_err(|e| e.to_string())?;
    let mut node = OneNode::open_existing(prepared.configuration).map_err(|e| e.to_string())?;

    let serving: Result<SshServerReceipt, String> = (|| {
        let selected = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|e| e.to_string())?;
        node.bring_into_service(selected.receipt().generation())
            .map_err(|e| e.to_string())?;

        let mut out = io::stdout().lock();
        let _ = writeln!(
            out,
            "{{\"type\":\"ssh_listening\",\"schema_version\":1,\"address\":\"{}\",\"allow_receive\":{},\"repository_incarnation\":\"{}\"}}",
            listen_address,
            prepared.allow_receive,
            node.repository_incarnation_id()
        );
        let _ = out.flush();
        drop(out);

        node.serve_ssh_bounded(
            &listener,
            prepared.limits,
            prepared.host_signing_key,
            prepared.deploy_keys,
            prepared.allow_receive,
        )
        .map_err(|e| e.to_string())
    })();

    let cleanup = node.shutdown();
    match (serving, cleanup) {
        (Ok(receipt), Ok(())) => {
            println!(
                "{{\"type\":\"ssh_drained\",\"schema_version\":1,\"accepted\":{},\"completed_transports\":{},\"refused_transports\":{}}}",
                receipt.accepted_sessions(),
                receipt.completed_sessions(),
                receipt.refused_sessions()
            );
            Ok(CliOutcome::Served {
                listen_address,
                service: receipt,
            })
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(format!(
            "SSH service completed but node shutdown failed: {error}"
        )),
        (Err(error), Err(cleanup)) => Err(format!(
            "SSH service failed ({error}); node shutdown also failed ({cleanup})"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scopes() {
        assert_eq!(parse_scopes("read").unwrap(), vec![DeployKeyScope::Read]);
        assert_eq!(parse_scopes("write").unwrap(), vec![DeployKeyScope::Write]);
        assert_eq!(
            parse_scopes("read,write").unwrap(),
            vec![DeployKeyScope::Read, DeployKeyScope::Write]
        );
        assert!(parse_scopes("admin").is_err());
    }
}
