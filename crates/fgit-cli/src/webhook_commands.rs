use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fgit_forge::webhook::{
    SsrfPolicy, WebhookEventFilter, WebhookId, WebhookRegistration, WebhookRetrySchedule,
    WebhookSecret, WebhookSecretRotation,
};
use fgit_node::webhook::{WebhookDeliveryDestination, WebhookStore};
use fgit_types::{AsciiSlug, RepositoryId, TenantId};

use crate::publication_support::quote;

const USAGE: &str =
    "usage: fg webhook register <storage-root> <tenant-id> <repository-id> --trusted-local
         --id <id> --url <url> --secret <hex-secret>
         [--filter <all|event1,event2>] [--permissive-for-tests]
usage: fg webhook list <storage-root> <tenant-id> <repository-id> --trusted-local
usage: fg webhook rotate <storage-root> <tenant-id> <repository-id> --trusted-local
         --id <id> --new-secret <hex-secret> [--window-secs <seconds>]
usage: fg webhook dead-letter list <storage-root> <tenant-id> <repository-id> --trusted-local
usage: fg webhook dead-letter replay <storage-root> <tenant-id> <repository-id> --trusted-local
         --delivery-id <delivery-id>
usage: fg webhook deliver <storage-root> <tenant-id> <repository-id> --trusted-local
         --id <id> --delivery-id <delivery-id> [--attempt <num>]
         [--permissive-for-tests]";

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args.is_empty() || args == ["--help"] {
        println!("{USAGE}");
        return Ok(0);
    }

    match args[0].as_str() {
        "register" => run_register(&args[1..]),
        "list" => run_list(&args[1..]),
        "rotate" => run_rotate(&args[1..]),
        "dead-letter" => run_dead_letter(&args[1..]),
        "deliver" => run_deliver(&args[1..]),
        _ => Err(format!("unknown webhook subcommand: {}", args[0])),
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex secret must have even length".into());
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| format!("invalid hex character in secret at position {i}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn parse_base(args: &[String]) -> Result<(PathBuf, TenantId, RepositoryId, usize), String> {
    if args.len() < 4 {
        return Err(USAGE.into());
    }
    let storage = PathBuf::from(&args[0]);
    let tenant = TenantId::from_hex(&args[1]).map_err(|_| "invalid tenant ID")?;
    let repo = RepositoryId::from_hex(&args[2]).map_err(|_| "invalid repository ID")?;
    if args[3] != "--trusted-local" {
        return Err("missing mandatory --trusted-local flag".into());
    }
    Ok((storage, tenant, repo, 4))
}

fn run_register(args: &[String]) -> Result<u8, String> {
    let (storage, _tenant, _repo, mut idx) = parse_base(args)?;

    let mut id = None;
    let mut url = None;
    let mut secret_hex = None;
    let mut permissive = false;
    let mut filter = WebhookEventFilter::Wildcard;

    while idx < args.len() {
        match args[idx].as_str() {
            "--id" => {
                idx += 1;
                let val = args.get(idx).ok_or("missing argument for --id")?;
                id = Some(val.parse::<u64>().map_err(|_| "invalid webhook id")?);
            }
            "--url" => {
                idx += 1;
                url = Some(args.get(idx).ok_or("missing argument for --url")?.clone());
            }
            "--secret" => {
                idx += 1;
                secret_hex = Some(
                    args.get(idx)
                        .ok_or("missing argument for --secret")?
                        .clone(),
                );
            }
            "--filter" => {
                idx += 1;
                let val = args.get(idx).ok_or("missing argument for --filter")?;
                if val == "all" || val == "*" {
                    filter = WebhookEventFilter::Wildcard;
                } else {
                    let parts: Vec<String> = val.split(',').map(|s| s.trim().to_string()).collect();
                    filter = WebhookEventFilter::Selected(parts);
                }
            }
            "--permissive-for-tests" => {
                permissive = true;
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
        idx += 1;
    }

    let webhook_id = id.ok_or("missing mandatory --id")?;
    let url_str = url.ok_or("missing mandatory --url")?;
    let secret_str = secret_hex.ok_or("missing mandatory --secret")?;

    let secret_bytes = hex_decode(&secret_str)?;
    let secret = WebhookSecret::new(secret_bytes).map_err(|e| e.to_string())?;

    let ssrf_policy = if permissive {
        SsrfPolicy::PERMISSIVE_FOR_TESTS
    } else {
        SsrfPolicy::STRICT
    };

    let validated_url = ssrf_policy
        .validate_url(&url_str)
        .map_err(|e| e.to_string())?;

    let reg = WebhookRegistration {
        id: WebhookId(webhook_id),
        url: validated_url,
        secrets: WebhookSecretRotation::new(secret),
        filter,
        active: true,
        retry_schedule: WebhookRetrySchedule::default(),
    };

    let store = WebhookStore::open(storage.join("webhooks"))?;
    store.register(reg)?;

    println!(
        "{{\"type\":\"webhook_registered\",\"schema_version\":1,\"id\":{},\"url\":{},\"status\":\"active\"}}",
        webhook_id,
        quote(&url_str)
    );
    Ok(0)
}

fn run_list(args: &[String]) -> Result<u8, String> {
    let (storage, _tenant, _repo, _) = parse_base(args)?;
    let store = WebhookStore::open(storage.join("webhooks"))?;
    let list = store.list();

    let items: Vec<String> = list
        .iter()
        .map(|r| {
            format!(
                "{{\"id\":{},\"url\":{},\"active\":{}}}",
                r.id.0,
                quote(r.url.raw()),
                r.active
            )
        })
        .collect();

    println!(
        "{{\"type\":\"webhook_list\",\"schema_version\":1,\"count\":{},\"webhooks\":[{}]}}",
        items.len(),
        items.join(",")
    );
    Ok(0)
}

fn run_rotate(args: &[String]) -> Result<u8, String> {
    let (storage, _tenant, _repo, mut idx) = parse_base(args)?;

    let mut id = None;
    let mut new_secret_hex = None;
    let mut window_secs = 86400u64;

    while idx < args.len() {
        match args[idx].as_str() {
            "--id" => {
                idx += 1;
                let val = args.get(idx).ok_or("missing argument for --id")?;
                id = Some(val.parse::<u64>().map_err(|_| "invalid webhook id")?);
            }
            "--new-secret" => {
                idx += 1;
                new_secret_hex = Some(
                    args.get(idx)
                        .ok_or("missing argument for --new-secret")?
                        .clone(),
                );
            }
            "--window-secs" => {
                idx += 1;
                let val = args.get(idx).ok_or("missing argument for --window-secs")?;
                window_secs = val.parse::<u64>().map_err(|_| "invalid window-secs")?;
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
        idx += 1;
    }

    let webhook_id = id.ok_or("missing mandatory --id")?;
    let secret_str = new_secret_hex.ok_or("missing mandatory --new-secret")?;
    let secret_bytes = hex_decode(&secret_str)?;
    let new_secret = WebhookSecret::new(secret_bytes).map_err(|e| e.to_string())?;

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();

    let store = WebhookStore::open(storage.join("webhooks"))?;
    store.rotate_secret(WebhookId(webhook_id), new_secret, window_secs, now_secs)?;

    println!(
        "{{\"type\":\"webhook_secret_rotated\",\"schema_version\":1,\"id\":{},\"window_secs\":{}}}",
        webhook_id, window_secs
    );
    Ok(0)
}

fn run_dead_letter(args: &[String]) -> Result<u8, String> {
    if args.is_empty() {
        return Err("missing dead-letter action (list|replay)".into());
    }
    match args[0].as_str() {
        "list" => {
            let (storage, _tenant, _repo, _) = parse_base(&args[1..])?;
            let store = WebhookStore::open(storage.join("webhooks"))?;
            let dl = store.list_dead_letters();
            let items: Vec<String> = dl
                .iter()
                .map(|e| {
                    format!(
                        "{{\"delivery_id\":{},\"webhook_id\":{},\"target_url\":{},\"terminal_reason\":{},\"attempts\":{}}}",
                        quote(e.delivery_id.as_str()),
                        e.webhook_id.0,
                        quote(&e.target_url),
                        quote(&e.terminal_reason),
                        e.attempts
                    )
                })
                .collect();
            println!(
                "{{\"type\":\"webhook_dead_letter_list\",\"schema_version\":1,\"count\":{},\"dead_letters\":[{}]}}",
                items.len(),
                items.join(",")
            );
            Ok(0)
        }
        "replay" => {
            let (storage, _tenant, _repo, mut idx) = parse_base(&args[1..])?;
            let mut delivery_id = None;
            while idx < args.len() - 1 {
                if args[idx] == "--delivery-id" {
                    idx += 1;
                    delivery_id = Some(
                        args.get(idx)
                            .ok_or("missing argument for --delivery-id")?
                            .clone(),
                    );
                }
                idx += 1;
            }
            let id_str = delivery_id.ok_or("missing mandatory --delivery-id")?;
            let slug =
                AsciiSlug::try_new("delivery_id", id_str.as_bytes()).map_err(|e| e.to_string())?;

            let store = WebhookStore::open(storage.join("webhooks"))?;
            let replayed = store.replay_dead_letter(slug);

            if let Some(entry) = replayed {
                println!(
                    "{{\"type\":\"webhook_dead_letter_replayed\",\"schema_version\":1,\"delivery_id\":{},\"status\":\"replayed\"}}",
                    quote(entry.delivery_id.as_str())
                );
                Ok(0)
            } else {
                Err(format!(
                    "delivery id {id_str} not found in dead-letter queue"
                ))
            }
        }
        unknown => Err(format!("unknown dead-letter action: {unknown}")),
    }
}

fn run_deliver(args: &[String]) -> Result<u8, String> {
    let (storage, _tenant, _repo, mut idx) = parse_base(args)?;

    let mut id = None;
    let mut delivery_id_str = None;
    let mut attempt = 1u32;
    let mut permissive = false;

    while idx < args.len() {
        match args[idx].as_str() {
            "--id" => {
                idx += 1;
                let val = args.get(idx).ok_or("missing argument for --id")?;
                id = Some(val.parse::<u64>().map_err(|_| "invalid webhook id")?);
            }
            "--delivery-id" => {
                idx += 1;
                delivery_id_str = Some(
                    args.get(idx)
                        .ok_or("missing argument for --delivery-id")?
                        .clone(),
                );
            }
            "--attempt" => {
                idx += 1;
                let val = args.get(idx).ok_or("missing argument for --attempt")?;
                attempt = val.parse::<u32>().map_err(|_| "invalid attempt number")?;
            }
            "--permissive-for-tests" => {
                permissive = true;
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
        idx += 1;
    }

    let webhook_id = id.ok_or("missing mandatory --id")?;
    let del_str = delivery_id_str.ok_or("missing mandatory --delivery-id")?;
    let delivery_slug =
        AsciiSlug::try_new("delivery_id", del_str.as_bytes()).map_err(|e| e.to_string())?;

    let store = WebhookStore::open(storage.join("webhooks"))?;
    let reg = store
        .get(WebhookId(webhook_id))
        .ok_or_else(|| format!("webhook id {webhook_id} not registered"))?;

    let ssrf_policy = if permissive {
        SsrfPolicy::PERMISSIVE_FOR_TESTS
    } else {
        SsrfPolicy::STRICT
    };

    let dest =
        WebhookDeliveryDestination::new(delivery_slug, reg, ssrf_policy, store.dead_letters());

    // Execute HTTP dispatch
    let (verdict_str, response_body) = dest.deliver_simple(delivery_slug, attempt)?;

    let response_text = String::from_utf8_lossy(&response_body);

    println!(
        "{{\"type\":\"webhook_delivered\",\"schema_version\":1,\"delivery_id\":{},\"attempt\":{},\"verdict\":{},\"response_summary\":{}}}",
        quote(&del_str),
        attempt,
        quote(verdict_str),
        quote(&response_text)
    );

    match verdict_str {
        "Accepted" | "DuplicateSuppressed" => Ok(0),
        "TransientFailure" => Ok(1),
        _ => Ok(2),
    }
}
