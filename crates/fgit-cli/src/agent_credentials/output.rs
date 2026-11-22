use crate::publication_support::quote;
use fgit_admission::merge::native::agent_credentials::AgentCredentialState;
use fgit_authority::TerminalOutcome;
use fgit_identity::agent::{
    AgentCredentialCommand, AgentCredentialGrant, AgentCredentialId, DISCUSSIONS_READ,
    DISCUSSIONS_WRITE, ISSUES_READ, ISSUES_WRITE, MILESTONES_READ, MILESTONES_WRITE, OUTCOMES_READ,
    PULLS_DIFF_READ, PULLS_FEEDBACK_READ, PULLS_READ, PULLS_WRITE, SOURCE_CANDIDATES,
    SOURCE_HISTORY_READ, SOURCE_PUBLISH, SOURCE_READ, SOURCE_VERIFIED_READ, SourcePublicationScope,
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
        (SOURCE_READ, "source-read"),
        (SOURCE_HISTORY_READ, "source-history-read"),
        (SOURCE_CANDIDATES, "source-candidates"),
        (MILESTONES_READ, "milestones-read"),
        (MILESTONES_WRITE, "milestones-write"),
        (SOURCE_PUBLISH, "source-publish"),
        (SOURCE_VERIFIED_READ, "source-verified-read"),
        (PULLS_DIFF_READ, "pulls-diff-read"),
        (PULLS_FEEDBACK_READ, "pulls-feedback-read"),
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

fn source_scope_field(value: Option<&SourcePublicationScope>, field: &str) -> String {
    value.map_or_else(String::new, |scope| {
        let paths = scope
            .path_prefixes()
            .iter()
            .map(|path| {
                let hex: String = path.iter().map(|byte| format!("{byte:02x}")).collect();
                quote(&hex)
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            ",{}:{{\"ref_scope\":{},\"path_prefixes_hex\":[{}]}}",
            quote(field),
            quote(scope.ref_scope()),
            paths
        )
    })
}

fn state(value: &AgentCredentialState) -> String {
    format!(
        "{{\"credential_id\":{},\"version\":{},\"revoked\":{},\"source_head\":{},\"grant_root\":{},\"grant\":{}{}}}",
        quote(&value.id.to_string()),
        value.version.get(),
        value.revoked,
        quote(&value.source_head.to_string()),
        quote(&value.grant_root.to_string()),
        grant(&value.grant),
        source_scope_field(value.source_scope.as_ref(), "source_scope")
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
    let (action, expected) = if command.action.is_issue() {
        ("issue", 0)
    } else {
        ("revoke", 1)
    };
    format!(
        concat!(
            "{{\"type\":\"agent_credential_publication\",\"schema_version\":1,\"tx_id\":{},",
            "\"decision_sequence\":{},\"outcome\":{},\"committed\":{},\"repository_commit_id\":{},",
            "\"refusal_record_id\":{},\"refusal_code\":{},\"action\":{},\"credential_id\":{},",
            "\"expected_version\":{},\"proposed_grant\":{}{},\"delivery_acknowledged\":null,",
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
        source_scope_field(command.action.source_scope(), "proposed_source_scope"),
        cleanup.is_none(),
        cleanup.map_or_else(|| "null".into(), quote)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_identity::agent::SponsorKind;
    use fgit_types::{PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};

    #[test]
    fn source_scope_output_is_lossless_and_absent_for_legacy_credentials() {
        assert_eq!(source_scope_field(None, "source_scope"), "");
        let scope = SourcePublicationScope::new(
            "exact:726566732f68656164732f6167656e74",
            vec![b"src".to_vec(), b"data/\xff".to_vec()],
        )
        .unwrap();
        assert_eq!(
            source_scope_field(Some(&scope), "source_scope"),
            ",\"source_scope\":{\"ref_scope\":\"exact:726566732f68656164732f6167656e74\",\"path_prefixes_hex\":[\"646174612fff\",\"737263\"]}"
        );
        let whole_tree = SourcePublicationScope::new(scope.ref_scope(), vec![Vec::new()]).unwrap();
        assert!(
            source_scope_field(Some(&whole_tree), "source_scope")
                .contains("\"path_prefixes_hex\":[\"\"]")
        );
    }

    #[test]
    fn retained_grant_output_preserves_each_explicit_scope_without_expanding_old_masks() {
        let value = AgentCredentialGrant {
            agent: PrincipalId::from_bytes([1; 16]),
            sponsor: PrincipalId::from_bytes([2; 16]),
            sponsor_kind: SponsorKind::Human,
            tenant: TenantId::from_bytes([3; 16]),
            repository: RepositoryId::from_bytes([4; 16]),
            incarnation: RepositoryIncarnationId::from_bytes([5; 16]),
            issued_at: 100,
            expires_at: 200,
            operations: SOURCE_HISTORY_READ,
        };
        assert!(grant(&value).contains("\"operations\":[\"source-history-read\"]"));
        for (operations, expected) in [
            (SOURCE_PUBLISH, "\"operations\":[\"source-publish\"]"),
            (MILESTONES_READ, "\"operations\":[\"milestones-read\"]"),
            (MILESTONES_WRITE, "\"operations\":[\"milestones-write\"]"),
            (PULLS_FEEDBACK_READ, "\"operations\":[\"pulls-feedback-read\"]"),
            (
                PULLS_DIFF_READ | PULLS_FEEDBACK_READ,
                "\"operations\":[\"pulls-diff-read\",\"pulls-feedback-read\"]",
            ),
            (
                MILESTONES_READ | MILESTONES_WRITE,
                "\"operations\":[\"milestones-read\",\"milestones-write\"]",
            ),
        ] {
            assert!(
                grant(&AgentCredentialGrant {
                    operations,
                    ..value
                })
                .contains(expected)
            );
        }
        assert!(
            !grant(&AgentCredentialGrant {
                operations: 0x7fff,
                ..value
            })
            .contains("pulls-feedback-read")
        );
        assert!(
            !grant(&AgentCredentialGrant {
                operations: 0x0fff,
                ..value
            })
            .contains("source-publish")
        );
        assert!(
            !grant(&AgentCredentialGrant {
                operations: 0x03ff,
                ..value
            })
            .contains("milestones-")
        );
        assert!(
            grant(&AgentCredentialGrant {
                operations: SOURCE_CANDIDATES,
                ..value
            })
            .contains("\"operations\":[\"source-candidates\"]")
        );
        assert!(
            !grant(&AgentCredentialGrant {
                operations: 0x01ff,
                ..value
            })
            .contains("source-candidates")
        );
        assert!(
            grant(&AgentCredentialGrant {
                operations: SOURCE_READ | SOURCE_HISTORY_READ,
                ..value
            })
            .contains("\"operations\":[\"source-read\",\"source-history-read\"]")
        );
        assert!(
            !grant(&AgentCredentialGrant {
                operations: 0x00ff,
                ..value
            })
            .contains("source-history-read")
        );
    }
}
