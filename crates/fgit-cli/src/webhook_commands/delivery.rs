//! Operator reads of canonical delivery state. Local registration and dead-letter
//! files never select event bytes or become an independent source of truth.

use std::{collections::BTreeMap, io::Write, path::PathBuf};

use fgit_node::{NodeConfig, OneNode};
use fgit_types::{
    AsciiSlug, GitHashAlgorithm, HeadGeneration, RepositoryAuthorityHeadId, RepositoryId,
    TenantId,
};

use crate::publication_support::quote;

struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
    expected_head: Option<String>,
    after: Option<AsciiSlug>,
    limit: u16,
    key: Option<AsciiSlug>,
    destination: Option<AsciiSlug>,
}

pub(super) fn run(action: &str, args: &[String]) -> Result<u8, String> {
    let options = parse(action, args)?;
    let output = match action {
        "outbox" => list(&options)?,
        "inspect" => inspect(&options)?,
        _ => return Err("unsupported canonical webhook action".into()),
    };
    writeln!(std::io::stdout().lock(), "{output}")
        .map_err(|error| format!("cannot write canonical webhook result: {error}"))?;
    Ok(0)
}

fn with_node<T>(
    options: &Options,
    operation: impl FnOnce(&OneNode) -> Result<T, String>,
) -> Result<T, String> {
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|error| error.to_string())?;
    let result = node
        .bring_into_service(HeadGeneration::FIRST)
        .map_err(|error| error.to_string())
        .and_then(|_| operation(&node));
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match (result, cleanup) {
        (Ok(value), None) => Ok(value),
        (result, cleanup) => Err(format!(
            "canonical webhook read did not complete{}{}; no delivery was attempted",
            result.err().map_or_else(String::new, |error| format!("; read: {error}")),
            cleanup.map_or_else(String::new, |error| format!("; shutdown: {error}")),
        )),
    }
}

fn list(options: &Options) -> Result<String, String> {
    let page = with_node(options, |node| {
        let request = node.request_context();
        node.runtime()
            .block_on(node.read_forge_outbox_in(&request, options.after, options.limit, None))
            .map_err(|error| error.to_string())
    })?;
    check_head(options, page.source_head)?;
    let entries = page.entries.iter().map(|entry| {
        format!(
            "{{\"delivery_id\":{},\"destination\":{},\"effect_class\":{},\"payload_root\":{},\"effect_state_root\":{}}}",
            quote(entry.delivery_key().as_str()), quote(entry.destination().as_str()),
            quote(entry.effect_class().as_str()), quote(&entry.payload_root().to_string()),
            quote(&entry.effect_state_root().to_string()),
        )
    }).collect::<Vec<_>>().join(",");
    let after = page.next_after.map_or_else(|| "null".into(), |key| quote(key.as_str()));
    Ok(format!(
        "{{\"type\":\"forge_outbox_page\",\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},\"includes_settled\":true,\"entries\":[{}],\"next_after\":{},\"node_closed\":true}}",
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()),
        quote(options.format.as_str()), quote(&page.source_head.to_string()),
        quote(&head_token(page.source_head)), entries, after,
    ))
}

fn inspect(options: &Options) -> Result<String, String> {
    let key = options.key.ok_or("missing --delivery-id")?;
    let destination = options.destination.ok_or("missing --destination")?;
    let selected = with_node(options, |node| {
        let request = node.request_context();
        node.runtime()
            .block_on(node.select_forge_delivery_in(&request, key, destination, None))
            .map_err(|error| error.to_string())
    })?;
    check_head(options, selected.source_head())?;
    let request = selected.as_request();
    let mut output = format!(
        "{{\"type\":\"forge_delivery_payload\",\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},\"source_head\":{},\"snapshot_token\":{},\"delivery_id\":{},\"destination\":{},\"payload_root\":{},\"effect_state_root\":{},\"events_count\":{},\"events\":[",
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()),
        quote(&selected.source_head().to_string()), quote(&head_token(selected.source_head())),
        quote(request.key.as_str()), quote(request.destination.as_str()),
        quote(&request.payload_root.to_string()), quote(&selected.entry().effect_state_root().to_string()),
        request.events.events.len(),
    );
    for (index, event) in request.events.events.iter().enumerate() {
        let frame = fgit_codec::encode_body(event).map_err(|error| error.to_string())?;
        let bytes = frame.len().checked_mul(2).and_then(|value| value.checked_add(128))
            .ok_or("inspection size overflow")?;
        reserve_inspection(&mut output, bytes)?;
        if index != 0 {
            output.push(',');
        }
        output.push_str(&format!(
            "{{\"kind\":{},\"version\":{},\"canonical_frame_hex\":\"",
            event.payload.kind(), event.version.get(),
        ));
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in frame {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 15)]));
        }
        output.push_str("\"}");
    }
    let suffix = "],\"node_closed\":true,\"sent\":false,\"settled\":false}";
    reserve_inspection(&mut output, suffix.len())?;
    output.push_str(suffix);
    Ok(output)
}

fn reserve_inspection(output: &mut String, bytes: usize) -> Result<(), String> {
    const MAX_INSPECTION_BYTES: usize = 64 * 1024 * 1024;
    if output.len().checked_add(bytes).is_none_or(|size| size > MAX_INSPECTION_BYTES) {
        return Err("canonical webhook inspection exceeds 64 MiB".into());
    }
    output.try_reserve(bytes).map_err(|_| "cannot allocate bounded inspection".into())
}

fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let identity = head.as_internal_object_id();
    let hex: String = identity.digest().as_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
    format!("alg:{}:{hex}", identity.algorithm().code_point())
}

fn check_head(options: &Options, head: RepositoryAuthorityHeadId) -> Result<(), String> {
    if options.expected_head.as_ref().is_some_and(|expected| *expected != head_token(head)) {
        return Err("SnapshotMoved: canonical webhook source differs from --expected-head".into());
    }
    Ok(())
}

fn parse(action: &str, args: &[String]) -> Result<Options, String> {
    if !matches!(action, "outbox" | "inspect") || args.len() > 18
        || args.iter().any(|value| value.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err("invalid or oversized canonical webhook command".into());
    }
    let (storage, tenant, repository, mut index) = super::parse_base(args)?;
    if args[0].is_empty() || args[0].len() > 4096 {
        return Err("invalid storage path".into());
    }
    let mut flags = BTreeMap::new();
    while index < args.len() {
        let flag = args[index].as_str();
        let permitted = matches!(flag, "--object-format" | "--expected-head")
            || (action == "outbox" && matches!(flag, "--after" | "--limit"))
            || (action == "inspect" && matches!(flag, "--delivery-id" | "--destination"));
        if !permitted {
            return Err(format!("unknown {action} option {flag}"));
        }
        index += 1;
        let value = args.get(index).ok_or_else(|| format!("missing value for {flag}"))?;
        if value.is_empty() || value.starts_with("--") {
            return Err(format!("missing value for {flag}"));
        }
        if flags.insert(flag, value.as_str()).is_some() {
            return Err(format!("duplicate {action} option {flag}"));
        }
        index += 1;
    }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".into()),
    };
    let slug = |flag: &'static str| -> Result<Option<AsciiSlug>, String> {
        flags.get(flag).map(|value| {
            AsciiSlug::try_new("delivery_parameter", value.as_bytes()).map_err(|error| error.to_string())
        }).transpose()
    };
    let key = slug("--delivery-id")?;
    let destination = slug("--destination")?;
    if action == "inspect" && (key.is_none() || destination.is_none()) {
        return Err("inspect requires --delivery-id and --destination from fg webhook outbox".into());
    }
    let limit = flags.get("--limit").copied().unwrap_or("50");
    if !limit.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("outbox limit must be 1..100".into());
    }
    let limit = limit.parse::<u16>().map_err(|_| "outbox limit must be 1..100")?;
    if !(1..=100).contains(&limit) {
        return Err("outbox limit must be 1..100".into());
    }
    Ok(Options {
        storage, tenant, repository, format,
        expected_head: flags.get("--expected-head").map(|value| (*value).to_owned()),
        after: slug("--after")?, limit, key, destination,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Vec<String> {
        ["data", "11111111111111111111111111111111", "22222222222222222222222222222222", "--trusted-local"]
            .into_iter().chain(extra.iter().copied()).map(str::to_owned).collect()
    }

    #[test]
    fn canonical_reads_require_trusted_local_and_bounded_options() {
        assert!(parse("outbox", &args(&[])).is_ok());
        let mut missing = args(&[]);
        missing.pop();
        assert!(parse("outbox", &missing).is_err());
        for extra in [vec!["--limit", "0"], vec!["--limit", "101"], vec!["--limit", "65536"], vec!["--limit", "-1"], vec!["--unknown", "1"], vec!["--limit"]] {
            assert!(parse("outbox", &args(&extra)).is_err(), "{extra:?}");
        }
        assert!(parse("outbox", &args(&["--limit", "1", "--limit", "2"])).is_err());
    }

    #[test]
    fn inspection_requires_both_original_delivery_parameters() {
        assert!(parse("inspect", &args(&["--delivery-id", "delivery-1"])).is_err());
        let options = parse("inspect", &args(&["--delivery-id", "delivery-1", "--destination", "forge-projection", "--object-format", "sha256"])).unwrap();
        assert_eq!(options.key.unwrap().as_str(), "delivery-1");
        assert_eq!(options.destination.unwrap().as_str(), "forge-projection");
        assert_eq!(options.format, GitHashAlgorithm::Sha256);
        assert!(parse("outbox", &args(&["--delivery-id", "delivery-1"])).is_err());
    }

    #[test]
    fn inspection_budget_refuses_before_reserving_unbounded_memory() {
        let mut output = String::from("{}");
        assert!(reserve_inspection(&mut output, usize::MAX).is_err());
        assert!(reserve_inspection(&mut output, 64 * 1024 * 1024).is_err());
        assert_eq!(output, "{}");
    }
}
