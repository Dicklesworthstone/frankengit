//! Deterministic JSON. Human text is data and ref bytes are never lossy strings.

use fgit_authority::TerminalOutcome;
use fgit_forge::aggregate::{AggregateId, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEvent, ForgeEventPayload, NativeMerge};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestData};
use fgit_types::{DecisionOutcome, PrincipalId, RepositoryAuthorityHeadId, TxId};
use crate::publication_support::quote;
use super::options::{Mutation, Options, ReadOptions, Selection, head_token, hex};

const MAX_REPLY_BYTES: usize = 48 * 1024 * 1024;

/// Borrowed rendering inputs only, not a second PR state or admission proof.
/// The node owns the actual read model; this view keeps the CLI coupled to
/// forge event/data types rather than taking a dependency on admission internals.
pub(super) struct Row<'a> {
    pub number: PullRequestNumber,
    pub event: &'a ForgeEvent,
    pub data: Option<&'a PullRequestData>,
    pub opened_by: Option<PrincipalId>,
    pub last_metadata_actor: Option<PrincipalId>,
}

pub(super) fn action_name(action: PullRequestAction) -> &'static str {
    match action { PullRequestAction::Open => "open", PullRequestAction::Update => "update", PullRequestAction::Close => "close" }
}
fn data_json(data: &PullRequestData) -> String {
    format!("{{\"source_reference_hex\":{},\"target_reference_hex\":{},\"source_tip\":{},\"target_tip\":{},\"title\":{},\"body\":{}}}",
        quote(&hex(data.source_ref.as_bytes())), quote(&hex(data.target_ref.as_bytes())),
        quote(&data.source_tip.to_string()), quote(&data.target_tip.to_string()), quote(&data.title), quote(&data.body))
}
fn merge_json(merge: &NativeMerge) -> String {
    format!("{{\"source_reference_hex\":{},\"target_reference_hex\":{},\"source_tip\":{},\"target_tip_before\":{},\"base_tip\":{},\"commit\":{}}}",
        quote(&hex(merge.source_ref.as_bytes())), quote(&hex(merge.target_ref.as_bytes())),
        quote(&merge.source_tip.to_string()), quote(&merge.target_tip_before.to_string()),
        quote(&merge.base_tip.to_string()), quote(&merge.merge_commit.to_string()))
}

pub(super) fn mutation_receipt(
    options: &Options, mutation: &Mutation, tx: TxId, terminal: &TerminalOutcome, cleanup: Option<&str>,
) -> String {
    let (outcome, rcr, code, refusal, committed) = match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } => ("committed", quote(&repository_commit_id.to_string()), "null".to_owned(), "null".to_owned(), true),
        DecisionOutcome::Refused { code, refusal_record_id } => ("refused", "null".to_owned(), quote(&format!("{code:?}")), quote(&refusal_record_id.to_string()), false),
    };
    let version = match mutation.command.expected_version { ExpectedVersion::NewStream => 0, ExpectedVersion::Exactly(value) => value.get() };
    format!(concat!("{{\"type\":\"pull_request_publication\",\"schema_version\":1,\"action\":{},",
        "\"outcome\":{},\"command_committed\":{},\"tx_id\":{},\"decision_sequence\":{},",
        "\"repository_commit_id\":{},\"refusal_code\":{},\"refusal_record_id\":{},",
        "\"tenant_id\":{},\"repository_id\":{},\"principal_id\":{},\"object_format\":{},",
        "\"pull_request\":{},\"expected_version\":{},\"data\":{},\"refs_changed\":false,",
        "\"delivery_acknowledged\":null,\"node_closed\":{},\"cleanup_error\":{}}}"),
        quote(action_name(mutation.command.action)), quote(outcome), committed, quote(&tx.to_string()),
        terminal.decision_sequence.get(), rcr, code, refusal,
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()), quote(&mutation.principal.to_string()),
        quote(options.format.as_str()), mutation.command.number.get(), version, data_json(&mutation.command.data),
        cleanup.is_none(), cleanup.map_or_else(|| "null".to_owned(), quote))
}

pub(super) fn read_receipt(
    options: &Options, read: &ReadOptions, source_head: RepositoryAuthorityHeadId,
    next_after: Option<u64>, rows: &[Row<'_>],
) -> Result<(String, u8), String> {
    // Never disclose a response that contradicts the requested pinned window.
    if read.expected_head.is_some_and(|expected| expected != source_head)
        || rows.len() > usize::from(read.limit())
        || rows.iter().any(|view| view.number.get() <= read.after())
        || !rows.windows(2).all(|pair| pair[0].number < pair[1].number)
        || next_after.is_some_and(|next| rows.last().map(|view| view.number.get()) != Some(next))
    { return Err("PR response does not match its pinned pagination contract".to_owned()); }
    let header = format!(concat!("\"schema_version\":1,\"scope\":\"native_prs_and_merge_receipts\",",
        "\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},\"source_head\":{},",
        "\"snapshot_token\":{},\"node_closed\":true"),
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()), quote(options.format.as_str()),
        quote(&source_head.to_string()), quote(&head_token(source_head)));
    match read.selection {
        Selection::Show(number) => {
            // A next-number result must not turn a hidden/absent exact lookup
            // into an accidental disclosure of a different PR.
            let row = rows.first().filter(|view| view.number == number);
            let body = row.map(render_view).transpose()?.unwrap_or_else(|| "null".to_owned());
            Ok((format!("{{\"type\":\"pull_request\",{header},\"requested_number\":{},\"found\":{},\"pull_request\":{body}}}", number.get(), row.is_some()),
                if row.is_some() { 0 } else { 4 }))
        }
        Selection::List { after, limit } => {
            let mut out = format!("{{\"type\":\"pull_request_page\",{header},\"after\":{after},\"limit\":{limit},\"count\":{},\"has_more\":{},\"next_after\":{},\"pull_requests\":[",
                rows.len(), next_after.is_some(), next_after.map_or_else(|| "null".to_owned(), |value| value.to_string()));
            for (index, view) in rows.iter().enumerate() {
                let row = render_view(view)?;
                if out.len().saturating_add(row.len()).saturating_add(3) > MAX_REPLY_BYTES {
                    return Err("PR page exceeds the output ceiling; request a smaller page".to_owned());
                }
                if index != 0 { out.push(','); }
                out.push_str(&row);
            }
            out.push_str("]}");
            Ok((out, 0))
        }
    }
}

fn render_view(view: &Row<'_>) -> Result<String, String> {
    if view.event.aggregate != AggregateId::PullRequest(view.number) {
        return Err("PR row aggregate binding is invalid".to_owned());
    }
    if let Some(data) = view.data { data.validate().map_err(|_| "PR row metadata is invalid")?; }
    let (state, action, merge) = match &view.event.payload {
        ForgeEventPayload::PullRequestChangedNative(change) => {
            if view.data != Some(&change.data) {
                return Err("PR row metadata disagrees with its selected event".to_owned());
            }
            (if change.action == PullRequestAction::Close { "closed" } else { "open" }, action_name(change.action), "null".to_owned())
        }
        ForgeEventPayload::MergeCommittedNative(merge) => {
            merge.validate().map_err(|_| "PR merge coordinates are invalid")?;
            if view.data.is_some_and(|data| !data.matches_merge(merge)) {
                return Err("PR metadata does not describe its selected merge".to_owned());
            }
            ("merged", "merge", merge_json(merge))
        }
        _ => return Err("unexpected non-native PR event; no lossy legacy conversion is supported".to_owned()),
    };
    Ok(format!(concat!("{{\"number\":{},\"version\":{},\"kind\":{},\"state\":{},\"last_action\":{},",
        "\"data\":{},\"opened_by\":{},\"last_metadata_actor\":{},\"merge\":{}}}"),
        view.number.get(), view.event.version.get(), quote(if view.data.is_some() { "pull_request" } else { "merge_receipt" }),
        quote(state), quote(action), view.data.map_or_else(|| "null".to_owned(), data_json),
        view.opened_by.map_or_else(|| "null".to_owned(), |actor| quote(&actor.to_string())),
        view.last_metadata_actor.map_or_else(|| "null".to_owned(), |actor| quote(&actor.to_string())), merge))
}
