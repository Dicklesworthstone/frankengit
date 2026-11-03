use crate::publication_support::quote;
use fgit_admission::merge::native::agent_credentials::AgentCredentialState;
use fgit_authority::TerminalOutcome;
use fgit_identity::agent::{
    AgentCredentialAction, AgentCredentialCommand, AgentCredentialGrant, AgentCredentialId,
    DISCUSSIONS_READ, DISCUSSIONS_WRITE, ISSUES_READ, ISSUES_WRITE, OUTCOMES_READ, PULLS_READ,
    PULLS_WRITE,
};
use fgit_types::{DecisionOutcome, TxId};

fn grant(value: &AgentCredentialGrant) -> String {
    let operations = [
        (ISSUES_READ, "issues-read"),
        (ISSUES_WRITE, "issues-write"),
        (PULLS_READ, "pulls-read"),
        (PULLS_WRITE, "pulls-write"),
        (DISCUSSIONS_READ, "discussions-read"),
        (DISCUSSIONS_WRITE, "discussions-write"),
        (OUTCOMES_READ, "outcomes-read"),
    ]
    .into_iter()
    .filter(|(bit, _)| value.permits(*bit))
    .map(|(_, name)| quote(name))
    .collect::<Vec<_>>()
    .join(",");
    format!(
        "{{\"agent\":{},\"sponsor\":{},\"sponsor_kind\":{},\"tenant\":{},\"repository\":{},\"incarnation\":{},\"issued_at\":{},\"expires_at\":{},\"operations\":[{}]}}",
        quote(&value.agent.to_string()),
        quote(&value.sponsor.to_string()),
        quote(value.sponsor_kind.name()),
        quote(&value.tenant.to_string()),
        quote(&value.repository.to_string()),
        quote(&value.incarnation.to_string()),
        value.issued_at,
        value.expires_at,
        operations
    )
}

fn state(value: &AgentCredentialState) -> String {
    format!(
        "{{\"credential_id\":{},\"version\":{},\"revoked\":{},\"source_head\":{},\"grant_root\":{},\"grant\":{}}}",
        quote(&value.id.to_string()),
        value.version.get(),
        value.revoked,
        quote(&value.source_head.to_string()),
        quote(&value.grant_root.to_string()),
        grant(&value.grant)
    )
}

pub(super) fn single(id: AgentCredentialId, value: Option<&AgentCredentialState>) -> String {
    format!(
        "{{\"type\":\"agent_credential\",\"schema_version\":1,\"credential_id\":{},\"found\":{},\"credential\":{},\"node_closed\":true}}",
        quote(&id.to_string()),
        value.is_some(),
        value.map_or_else(|| "null".into(), state)
    )
}

pub(super) fn list(values: &[AgentCredentialState]) -> String {
    format!(
        "{{\"type\":\"agent_credentials\",\"schema_version\":1,\"credentials\":[{}],\"node_closed\":true}}",
        values.iter().map(state).collect::<Vec<_>>().join(",")
    )
}

pub(super) fn mutation(
    command: &AgentCredentialCommand,
    tx: TxId,
    terminal: &TerminalOutcome,
    cleanup: Option<&str>,
) -> String {
    let (outcome, committed, commit, refusal, code) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            true,
            quote(&repository_commit_id.to_string()),
            "null".into(),
            "null".into(),
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            "refused",
            false,
            "null".into(),
            quote(&refusal_record_id.to_string()),
            quote(&format!("{code:?}")),
        ),
    };
    let (action, expected) = match command.action {
        AgentCredentialAction::Issue(_) => ("issue", 0),
        AgentCredentialAction::Revoke(_) => ("revoke", 1),
    };
    format!(
        concat!(
            "{{\"type\":\"agent_credential_publication\",\"schema_version\":1,\"tx_id\":{},",
            "\"decision_sequence\":{},\"outcome\":{},\"committed\":{},\"repository_commit_id\":{},",
            "\"refusal_record_id\":{},\"refusal_code\":{},\"action\":{},\"credential_id\":{},",
            "\"expected_version\":{},\"proposed_grant\":{},\"delivery_acknowledged\":null,",
            "\"node_closed\":{},\"cleanup_error\":{}}}"
        ),
        quote(&tx.to_string()),
        terminal.decision_sequence.get(),
        quote(outcome),
        committed,
        commit,
        refusal,
        code,
        quote(action),
        quote(&command.id.to_string()),
        expected,
        grant(command.action.grant()),
        cleanup.is_none(),
        cleanup.map_or_else(|| "null".into(), quote)
    )
}
