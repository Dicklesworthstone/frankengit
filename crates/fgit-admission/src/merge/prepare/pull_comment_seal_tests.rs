use super::*;
use crate::merge::native::pull_request::comments::{append_proposal, proposal};
use fgit_authority::{HeadKey, IdempotencyKey, SemanticRequest};
use fgit_forge::event::pull_request_comment::{
    PullRequestAppendCommentCommand, PullRequestCommentCommand, SourceCommentAnchor,
    SourceCommentComparison, SourceCommentSide,
};
use fgit_forge::{AggregateId, AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId};

fn context(format: GitHashAlgorithm) -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"pr-seal/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"original-key".to_vec()).unwrap(),
        object_format: format,
    }
}
fn command(format: GitHashAlgorithm, anchored: bool) -> PullRequestAppendCommentCommand {
    let oid = |byte: &str| GitOid::from_hex(format, &byte.repeat(format.digest_len())).unwrap();
    PullRequestAppendCommentCommand {
        number: PullRequestNumber::FIRST,
        body: "Original exact comment".into(),
        anchor: anchored.then(|| SourceCommentAnchor {
            pull_request_version: AggregateVersion::FIRST,
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: oid("11"),
            target_tip: oid("22"),
            compared_base: oid("22"),
            comparison: SourceCommentComparison::Direct,
            path: b"file.rs".to_vec(),
            side: SourceCommentSide::After,
            blob: oid("33"),
            mode: 0o100644,
            byte_start: 0,
            byte_end: 4,
            line_start: 0,
            line_count: 1,
        }),
    }
}

#[test]
fn only_explicit_append_seals_accept_replanned_conversation_positions() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let context = context(format);
        for anchored in [false, true] {
            let command = command(format, anchored);
            let (template, append) = append_proposal(&context, &command).unwrap();
            for previous in [0, 1, 27, u64::MAX - 1] {
                let (event, strict) = proposal(
                    &context,
                    &PullRequestCommentCommand {
                        number: command.number,
                        expected_version: AggregateVersion::try_new(previous)
                            .map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
                        body: command.body.clone(),
                        anchor: command.anchor.clone(),
                    },
                )
                .unwrap();
                assert_eq!(
                    verify_pull_request_comment_seal(&context, &event, &strict),
                    Ok(())
                );
                assert_eq!(
                    verify_pull_request_comment_seal(&context, &event, &append),
                    Ok(())
                );
                let changed = ForgeEvent {
                    version: if previous == 0 {
                        AggregateVersion::try_new(2).unwrap()
                    } else {
                        AggregateVersion::FIRST
                    },
                    ..event
                };
                assert_eq!(
                    verify_pull_request_comment_seal(&context, &changed, &strict),
                    Err(RefusalCode::EvidenceInvalid)
                );
            }
            assert_eq!(template.version, AggregateVersion::FIRST);
        }
    }
}

#[test]
fn independent_seal_verifier_rejects_substituted_pr_actor_body_anchor_and_profile() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let context = context(format);
        let (template, seal) = append_proposal(&context, &command(format, true)).unwrap();
        for field in 0..7 {
            let mut event = template.clone();
            let mut changed_context = context.clone();
            let ForgeEventPayload::PullRequestCommentedNative(comment) = &mut event.payload else {
                unreachable!()
            };
            match field {
                0 => comment.actor = PrincipalId::from_bytes([4; 16]),
                1 => {
                    event.aggregate =
                        AggregateId::PullRequestConversation(PullRequestNumber::try_new(2).unwrap())
                }
                2 => comment.body.push('!'),
                3 => comment.anchor.as_mut().unwrap().byte_end += 1,
                4 => comment.anchor = None,
                5 => event.aggregate = AggregateId::PullRequest(PullRequestNumber::FIRST),
                _ => changed_context.repository_id = RepositoryId::from_bytes([5; 16]),
            }
            assert_eq!(
                verify_pull_request_comment_seal(&changed_context, &event, &seal),
                Err(RefusalCode::EvidenceInvalid),
                "field {field}"
            );
        }
        let unrelated = SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            context.object_format,
            true,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let changed = SealAttempt {
            request: unrelated,
            ..seal
        };
        assert_eq!(
            verify_pull_request_comment_seal(&context, &template, &changed),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
}
