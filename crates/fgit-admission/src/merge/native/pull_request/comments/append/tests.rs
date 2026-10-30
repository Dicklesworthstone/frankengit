use super::*;
use crate::merge::native::pull_request::comments::proposal;
use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_codec::ForgePositionStateEntry;
use fgit_forge::event::pull_request_comment::{
    PullRequestCommentCommand, SourceCommentAnchor, SourceCommentComparison, SourceCommentSide,
};
use fgit_forge::{ExpectedVersion, PullRequestNumber};
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId};

fn context(format: GitHashAlgorithm) -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"pr-append/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"pr-append-once".to_vec()).unwrap(),
        object_format: format,
    }
}
fn command() -> PullRequestAppendCommentCommand {
    PullRequestAppendCommentCommand {
        number: PullRequestNumber::FIRST,
        body: "Exact additive PR comment é\r\n".into(),
        anchor: None,
    }
}
fn anchor(format: GitHashAlgorithm) -> SourceCommentAnchor {
    let oid = |byte: &str| GitOid::from_hex(format, &byte.repeat(format.digest_len())).unwrap();
    SourceCommentAnchor {
        pull_request_version: AggregateVersion::FIRST,
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: oid("11"),
        target_tip: oid("22"),
        compared_base: oid("22"),
        comparison: SourceCommentComparison::Direct,
        path: b"src/main.rs".to_vec(),
        side: SourceCommentSide::After,
        blob: oid("33"),
        mode: 0o100644,
        byte_start: 0,
        byte_end: 4,
        line_start: 0,
        line_count: 1,
    }
}
// Synthetic canonical frontier exercises the pure planner, not storage durability.
fn positions(context: &AdmissionContext, version: u64) -> CanonicalForgePositionState {
    let entries = if version == 0 {
        Vec::new()
    } else {
        vec![
            ForgePositionStateEntry::try_new(
                AsciiSlug::from_static("conversation/1"),
                version - 1,
                1,
                fgit_codec::harness::digest_of(9),
            )
            .unwrap(),
        ]
    };
    CanonicalForgePositionState::try_new(context.repository_id, entries).unwrap()
}

#[test]
fn append_seal_binds_semantics_and_keeps_exact_comment_identity_distinct() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let context = context(format);
        let command = command();
        let proposed = append_proposal(&context, &command).unwrap();
        assert_eq!(append_proposal(&context, &command).unwrap(), proposed);
        assert!(proposed.1.request.atomic());
        assert!(proposed.1.request.ref_commands().is_empty());
        assert!(proposed.1.request.push_options().is_empty());
        let strict = proposal(
            &context,
            &PullRequestCommentCommand {
                number: command.number,
                expected_version: ExpectedVersion::NewStream,
                body: command.body.clone(),
                anchor: None,
            },
        )
        .unwrap();
        assert_eq!(strict.0, proposed.0);
        let identity = proposed.1.derive().unwrap().0;
        assert_ne!(strict.1.derive().unwrap().0, identity);
        for field in 0..8 {
            let mut changed_context = context.clone();
            let mut changed = command.clone();
            match field {
                0 => changed.body.push('!'),
                1 => changed.number = PullRequestNumber::try_new(2).unwrap(),
                2 => changed_context.principal_id = PrincipalId::from_bytes([4; 16]),
                3 => {
                    changed_context.idempotency_key =
                        IdempotencyKey::new(b"other-key".to_vec()).unwrap()
                }
                4 => {
                    changed_context.object_format = match format {
                        GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
                        GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
                    }
                }
                5 => changed_context.repository_id = RepositoryId::from_bytes([5; 16]),
                6 => changed_context.tenant_id = TenantId::from_bytes([6; 16]),
                _ => changed.anchor = Some(anchor(format)),
            }
            assert_ne!(
                append_proposal(&changed_context, &changed)
                    .unwrap()
                    .1
                    .derive()
                    .unwrap()
                    .0,
                identity,
                "field {field}"
            );
        }
        let mut relocated = context;
        relocated.head_key = HeadKey::new(b"different-physical-placement".to_vec()).unwrap();
        assert_eq!(append_proposal(&relocated, &command).unwrap(), proposed);
    }
}

#[test]
fn current_frontiers_change_only_position_and_never_text_anchor_or_seal() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let context = context(format);
        for anchored in [false, true] {
            let mut command = command();
            command.anchor = anchored.then(|| anchor(format));
            let (submitted, seal) = append_proposal(&context, &command).unwrap();
            for previous in [0, 1, 2, 27, u64::MAX - 1] {
                let planned =
                    plan_append_event(&context, &submitted, &positions(&context, previous))
                        .unwrap();
                assert_eq!(planned.version.get(), previous + 1);
                assert_eq!(planned.aggregate, submitted.aggregate);
                assert_eq!(planned.payload, submitted.payload);
                assert_eq!(append_proposal(&context, &command).unwrap().1, seal);
            }
            assert_eq!(submitted.version, AggregateVersion::FIRST);
        }
    }
}

#[test]
fn exhaustion_wrong_scope_and_substituted_templates_fail_closed() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let context = context(format);
        let (submitted, _) = append_proposal(&context, &command()).unwrap();
        assert_eq!(
            plan_append_event(&context, &submitted, &positions(&context, u64::MAX)),
            Err(ProjectionFailure::Refuse(
                RefusalCode::ResourceBudgetExceeded
            ))
        );
        let other =
            CanonicalForgePositionState::try_new(RepositoryId::from_bytes([9; 16]), Vec::new())
                .unwrap();
        assert_eq!(
            plan_append_event(&context, &submitted, &other),
            Err(ProjectionFailure::Unavailable(
                RefusalCode::AuthorityReceiptStale
            ))
        );
        for field in 0..3 {
            let mut changed = submitted.clone();
            match field {
                0 => changed.version = AggregateVersion::try_new(2).unwrap(),
                1 => {
                    let ForgeEventPayload::PullRequestCommentedNative(comment) =
                        &mut changed.payload
                    else {
                        unreachable!()
                    };
                    comment.actor = PrincipalId::from_bytes([9; 16]);
                }
                _ => changed.aggregate = AggregateId::PullRequest(PullRequestNumber::FIRST),
            }
            assert_eq!(
                plan_append_event(&context, &changed, &positions(&context, 2)),
                Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid)),
                "field {field}"
            );
        }
        let other_format = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        let mut wrong_domain = command();
        wrong_domain.anchor = Some(anchor(other_format));
        assert!(append_proposal(&context, &wrong_domain).is_err());
    }
}
