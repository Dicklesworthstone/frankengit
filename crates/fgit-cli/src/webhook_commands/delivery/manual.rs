//! An explicitly requested, single-attempt operator delivery. Generic HTTP
//! receivers do not acquire strong idempotency by being called from the CLI.

use fgit_forge::webhook::{
    DeadLetterEntry, SsrfPolicy, WebhookId, WebhookRegistration,
};
#[cfg(all(test, unix))]
use fgit_forge::webhook::WebhookEventFilter;
#[cfg(all(test, unix))]
use fgit_forge::{ForgeEvent, ForgeEventPayload};
use fgit_node::webhook::{WebhookDeliveryDestination, WebhookStore};
use fgit_types::{AsciiSlug, Digest};

use super::super::subscription::require_subscription;
use super::{Options, check_head, head_token, with_node};
use crate::publication_support::quote;

mod replay_budget;

pub(super) fn execute(options: &Options, replay: bool) -> Result<(u8, String), String> {
    if !options.at_least_once {
        return Err(
            "manual delivery requires --at-least-once; a repeated send can duplicate an effect"
                .into(),
        );
    }
    let key = options.key.ok_or("missing --delivery-id")?;
    let destination = options.destination.ok_or("missing --destination")?;
    let webhook_id = options.webhook_id.ok_or("missing --id")?;

    // Authentication/selection and runtime shutdown finish BEFORE external I/O.
    // This result owns the exact canonical bytes, not a mutable local preview.
    let selected = with_node(options, |node| {
        let request = fgit_cli::command_request_context(&node);
        node.runtime()
            .block_on(node.select_forge_delivery_in(&request, key, destination, None))
            .map_err(|error| error.to_string())
    })?;
    check_head(options, selected.source_head())?;
    let request = selected.as_request();
    let store = WebhookStore::open(options.storage.join("webhooks"))?;
    let registration = store
        .get(WebhookId(webhook_id))
        .ok_or_else(|| format!("webhook id {webhook_id} not registered"))?;
    if !registration.active {
        return Err("webhook registration is inactive; no delivery attempted".into());
    }
    require_subscription(&registration.filter, &request.events.events)?;

    let previous = if replay {
        let record = store
            .get_dead_letter(key)
            .ok_or("delivery not present in dead letters")?;
        require_replay_binding(&record, &registration, key, request.payload_root)?;
        Some(record)
    } else {
        None
    };
    let automatic_attempt_limit = registration.retry_schedule.max_attempts;
    let budget = replay_budget::plan(
        automatic_attempt_limit,
        previous.as_ref().map(|record| record.attempts),
        options.attempt,
    )?;
    let attempt = budget.ordinal;
    // After canonical selection, binding checks and explicit at-least-once
    // consent, replay gets THIS send beyond an exhausted automatic schedule.
    // Keep the cumulative attempt in HTTP headers; never reset it to one or
    // raise the saved automatic policy. Headers are not covered by the payload
    // HMAC. This owned registration copy is never registered or persisted.
    let mut registration = registration;
    registration.retry_schedule.max_attempts = budget.invocation_limit;

    let policy = if options.permissive {
        SsrfPolicy::PERMISSIVE_FOR_TESTS
    } else {
        SsrfPolicy::STRICT
    };
    let transport =
        WebhookDeliveryDestination::new(destination, registration, policy, store.dead_letters());
    let (verdict, response) = transport.deliver_request(&request, attempt)?;
    // Do not delete a diagnostic and call that a replay. Nor does a 2xx here
    // authorize canonical settlement: that is the strong worker's separate CAS
    // path. Keep the diagnostic, including after a successful manual send.
    let diagnostic_retained = store.get_dead_letter(key).is_some();
    let output = format!(
        "{{\"type\":\"webhook_delivery_observed\",\"schema_version\":1,\"mode\":\"manual-at-least-once\",\"tenant_id\":{},\"repository_id\":{},\"source_head\":{},\"snapshot_token\":{},\"webhook_id\":{},\"delivery_id\":{},\"destination\":{},\"payload_root\":{},\"attempt\":{},\"automatic_attempt_limit\":{},\"invocation_attempt_limit\":{},\"replay\":{},\"verdict\":{},\"outcome_unknown\":{},\"diagnostic_retained\":{},\"canonical_settled\":false,\"automatic_retry\":false,\"node_closed\":true,\"response_summary\":{}}}",
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(&selected.source_head().to_string()),
        quote(&head_token(selected.source_head())),
        webhook_id,
        quote(key.as_str()),
        quote(destination.as_str()),
        quote(&request.payload_root.to_string()),
        attempt,
        automatic_attempt_limit,
        budget.invocation_limit,
        replay,
        quote(verdict),
        verdict == "AmbiguousTimeout",
        diagnostic_retained,
        quote(&String::from_utf8_lossy(&response)),
    );
    Ok((exit_code(verdict), output))
}

fn exit_code(verdict: &str) -> u8 {
    match verdict {
        "Accepted" | "DuplicateSuppressed" => 0,
        "TransientFailure" => 1,
        "AmbiguousTimeout" => 3,
        _ => 2,
    }
}

fn require_replay_binding(
    record: &DeadLetterEntry,
    registration: &WebhookRegistration,
    key: AsciiSlug,
    payload_root: Digest,
) -> Result<(), String> {
    if record.delivery_id != key
        || record.webhook_id != registration.id
        || record.target_url != registration.url.raw()
        || record.payload_root != payload_root
    {
        return Err("dead-letter identity, endpoint, or payload differs from the selected delivery; no replay attempted".into());
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
