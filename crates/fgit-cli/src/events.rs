//! Resumable canonical forge-event feed for trusted local integrations.
use crate::publication_support::quote;
use fgit_node::{NodeConfig, OneNode};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::{
    CANONICAL_CODEC_VERSION, GitHashAlgorithm, HeadGeneration, RepositoryAuthorityHeadId,
    RepositoryId, TenantId,
};
use std::{collections::BTreeMap, io::Write, path::PathBuf};

const USAGE: &str = "usage: fg events <storage-root> <tenant-id> <repository-id> --trusted-local
  [--object-format sha1|sha256] [--limit <1..100>] [--after <repository-sequence:event-index>]
  [--expected-head <snapshot-token>]

Reads canonical forge events in committed repository order. Cursor values remain
append-stable across later commits; --expected-head optionally pins one exact
snapshot and refuses movement. Each row includes the canonical encoded event
frame in lowercase hex, so integrations need not infer fields from display text.
This command is read-only and does not acknowledge delivery. Exit 0: complete
page; 2: input/read/output failure.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EventCursor {
    repository_sequence: u64,
    event_index: u32,
}
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
    after: Option<EventCursor>,
    limit: u16,
    expected_head: Option<RepositoryAuthorityHeadId>,
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        write_page(&mut std::io::stdout().lock(), USAGE)?;
        return Ok(0);
    }
    let options = parse(args)?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|e| e.to_string())?;
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST)
            .map_err(|e| e.to_string())?;
        let request = node.request_context();
        node.runtime()
            .block_on(
                node.read_forge_events_in(
                    &request,
                    options
                        .after
                        .map(|cursor| (cursor.repository_sequence, cursor.event_index)),
                    options.limit,
                    options.expected_head,
                ),
            )
            .map_err(|e| e.to_string())
    })();
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    match (operation, cleanup) {
        (Ok(page), None) => {
            let rows = page
                .events
                .iter()
                .map(|value| {
                    let frame = fgit_codec::encode_body(&value.event).map_err(|e| e.to_string())?;
                    Ok(format!(
                        "{{\"cursor\":{},\"repository_sequence\":{},\"event_index\":{},\"tx_id\":{},\"policy_epoch\":{},\"aggregate\":{},\"aggregate_version\":{},\"kind\":{},\"event_frame_hex\":{}}}",
                        quote(&cursor(value.cursor.repository_sequence, value.cursor.event_index)),
                        value.cursor.repository_sequence,
                        value.cursor.event_index,
                        quote(&value.tx_id.to_string()),
                        value.policy_epoch.get(),
                        quote(&value.event.aggregate.to_string()),
                        value.event.version.get(),
                        value.event.payload.kind(),
                        quote(&hex(&frame))
                    ))
                })
                .collect::<Result<Vec<String>, String>>()?
                .join(",");
            let next_after = page.next_after.map_or_else(
                || "null".into(),
                |value| quote(&cursor(value.repository_sequence, value.event_index)),
            );
            let receipt = format!(
                "{{\"type\":\"forge_event_page\",\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},\"events\":[{}],\"next_after\":{},\"has_more\":{},\"node_closed\":true}}",
                quote(&options.tenant.to_string()),
                quote(&options.repository.to_string()),
                quote(options.format.as_str()),
                quote(&page.source_head.to_string()),
                quote(&head_token(page.source_head)),
                rows,
                next_after,
                page.next_after.is_some()
            );
            write_page(&mut std::io::stdout().lock(), &receipt)?;
            Ok(0)
        }
        (result, cleanup) => Err(format!(
            "no complete forge event page returned{}{}",
            result
                .err()
                .map_or_else(String::new, |e| format!("; read: {e}")),
            cleanup.map_or_else(String::new, |e| format!("; shutdown: {e}"))
        )),
    }
}
fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4
        || args.len() > 15
        || args.iter().any(|v| v.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err(USAGE.into());
    }
    if args[0].is_empty() || args[0].len() > 4096 {
        return Err("invalid storage path".into());
    }
    let tenant = TenantId::from_hex(&args[1]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[2]).map_err(|_| "invalid repository ID")?;
    let mut flags = BTreeMap::new();
    let mut i = 3;
    while i < args.len() {
        let flag = args[i].as_str();
        i += 1;
        if !matches!(
            flag,
            "--trusted-local" | "--object-format" | "--limit" | "--after" | "--expected-head"
        ) {
            return Err(format!("unknown events option {flag}"));
        }
        let value = if flag == "--trusted-local" {
            ""
        } else {
            let v = args
                .get(i)
                .ok_or_else(|| format!("missing value for {flag}"))?;
            i += 1;
            v.as_str()
        };
        if flags.insert(flag, value).is_some() {
            return Err(format!("duplicate events option {flag}"));
        }
    }
    if !flags.contains_key("--trusted-local") {
        return Err("--trusted-local is required for repository metadata disclosure".into());
    }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".into()),
    };
    let limit = u16::try_from(
        flags
            .get("--limit")
            .map(|v| decimal(v))
            .transpose()?
            .unwrap_or(50),
    )
    .map_err(|_| "event limit overflow")?;
    if !(1..=100).contains(&limit) {
        return Err("event limit must be 1..100".into());
    }
    let after = flags.get("--after").map(|v| parse_cursor(v)).transpose()?;
    let expected_head = flags
        .get("--expected-head")
        .map(|v| parse_head(v))
        .transpose()?;
    Ok(Options {
        storage: args[0].clone().into(),
        tenant,
        repository,
        format,
        after,
        limit,
        expected_head,
    })
}
fn decimal(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("expected canonical unsigned decimal".into());
    }
    value.parse().map_err(|_| "decimal overflow".into())
}
fn parse_cursor(value: &str) -> Result<EventCursor, String> {
    let (sequence, index) = value
        .split_once(':')
        .ok_or("event cursor must be repository-sequence:event-index")?;
    let repository_sequence = decimal(sequence)?;
    if repository_sequence == 0 {
        return Err("event sequence must be nonzero".into());
    }
    let event_index = u32::try_from(decimal(index)?).map_err(|_| "event index overflow")?;
    Ok(EventCursor {
        repository_sequence,
        event_index,
    })
}
fn unhex(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || value.len() > 128
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected bounded lowercase hex digest".into());
    }
    let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| 16 * digit(p[0]) + digit(p[1]))
        .collect())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}
fn parse_head(value: &str) -> Result<RepositoryAuthorityHeadId, String> {
    let (alg, digest) = value
        .strip_prefix("alg:")
        .and_then(|v| v.split_once(':'))
        .ok_or("expected algorithm-qualified snapshot token")?;
    let alg = u16::try_from(decimal(alg)?).map_err(|_| "head algorithm overflow")?;
    let alg = DigestAlgorithmId::try_new(alg).map_err(|_| "invalid head algorithm")?;
    let digest = DigestBytes::try_new(&unhex(digest)?).map_err(|_| "invalid head digest width")?;
    Ok(RepositoryAuthorityHeadId::from_digest(
        alg,
        CANONICAL_CODEC_VERSION,
        digest,
    ))
}
fn cursor(repository_sequence: u64, event_index: u32) -> String {
    format!("{repository_sequence}:{event_index}")
}
fn write_page(output: &mut impl Write, page: &str) -> Result<(), String> {
    writeln!(output, "{page}")
        .and_then(|()| output.flush())
        .map_err(|e| format!("event page output incomplete: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parser_accepts_append_cursor_and_optional_snapshot_pin() {
        let base = vec![
            "store".into(),
            "11".repeat(16),
            "22".repeat(16),
            "--trusted-local".into(),
            "--after".into(),
            "7:3".into(),
            "--limit".into(),
            "100".into(),
        ];
        let parsed = parse(&base).unwrap();
        assert_eq!(
            parsed.after,
            Some(EventCursor {
                repository_sequence: 7,
                event_index: 3
            })
        );
        let mut bad = base.clone();
        *bad.last_mut().unwrap() = "101".into();
        assert!(parse(&bad).is_err());
        let mut zero = base;
        zero[5] = "0:0".into();
        assert!(parse(&zero).is_err());
    }
    #[test]
    fn cursor_parser_is_canonical_and_bounded() {
        assert_eq!(
            parse_cursor("1:0").unwrap(),
            EventCursor {
                repository_sequence: 1,
                event_index: 0
            }
        );
        for bad in ["01:0", "1:00", "0:0", "1", "x:0", "1:4294967296"] {
            assert!(parse_cursor(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn output_failure_is_not_a_complete_page() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("broken"))
            }
        }
        assert!(
            write_page(&mut Broken, "{}")
                .unwrap_err()
                .contains("incomplete")
        );
    }
}
