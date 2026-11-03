use super::*;
use crate::event::admission::{ForgeCommandProfile, ForgeReplanPolicy, classify_event};
use fgit_codec::wire::CanonicalBody;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

fn grant() -> AgentCredentialGrant {
    AgentCredentialGrant {
        agent: PrincipalId::from_bytes([1; 16]),
        sponsor: PrincipalId::from_bytes([2; 16]),
        sponsor_kind: SponsorKind::Human,
        tenant: TenantId::from_bytes([3; 16]),
        repository: RepositoryId::from_bytes([4; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([5; 16]),
        issued_at: 100,
        expires_at: 200,
        operations: ISSUES_READ | ISSUES_WRITE | PULLS_WRITE,
    }
}

fn issue() -> ForgeEvent {
    AgentCredentialCommand {
        id: AgentCredentialId::try_new([9; 32]).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: AgentCredentialAction::Issue(grant()),
    }
    .proposed_event(grant().sponsor)
    .unwrap()
}

fn revoke(original: &AgentCredentialSnapshot) -> ForgeEvent {
    AgentCredentialCommand {
        id: original.id,
        expected_version: ExpectedVersion::Exactly(original.version),
        action: AgentCredentialAction::Revoke(original.grant),
    }
    .proposed_event(PrincipalId::from_bytes([7; 16]))
    .unwrap()
}

#[test]
fn canonical_issue_and_permanent_revocation_preserve_exact_grant_at_frontier() {
    let opened = issue();
    let original = apply_event(None, &opened).unwrap();
    let revoked_event = revoke(&original);
    for event in [&opened, &revoked_event] {
        let bytes = encode_body(event).unwrap();
        let decoded = decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap();
        assert_eq!(decoded, *event);
        assert_eq!(encode_body(&decoded).unwrap(), bytes);
        for profile in [
            ForgeCommandProfile::ExactVersion,
            ForgeCommandProfile::Unknown,
            ForgeCommandProfile::AppendIssueCommentV1,
            ForgeCommandProfile::AppendPullRequestCommentV1,
            ForgeCommandProfile::AddIssueAssigneesV1,
            ForgeCommandProfile::AddIssueLabelsV1,
        ] {
            assert_eq!(
                classify_event(event, profile).replan,
                ForgeReplanPolicy::PreservePreconditions
            );
        }
    }
    let revoked = apply_event(Some(&original), &revoked_event).unwrap();
    assert!(revoked.revoked);
    assert_eq!(revoked.grant, original.grant);
    assert_eq!(revoked.version.get(), 2);
    assert_eq!(revoked.last_actor, PrincipalId::from_bytes([7; 16]));
    assert_eq!(
        apply_event(None, &revoked_event),
        Err(RefusalCode::EvidenceStale)
    );
    assert_eq!(
        apply_event(Some(&original), &opened),
        Err(RefusalCode::EvidenceStale)
    );
    assert_eq!(
        apply_event(Some(&revoked), &opened),
        Err(RefusalCode::EvidenceStale)
    );
    assert_eq!(
        apply_event(Some(&revoked), &revoked_event),
        Err(RefusalCode::EvidenceStale)
    );
    let mut changed = revoked_event;
    let ForgeEventPayload::AgentCredentialChangedNative(change) = &mut changed.payload else {
        unreachable!()
    };
    let AgentCredentialAction::Revoke(grant) = &mut change.action else {
        unreachable!()
    };
    grant.operations |= DISCUSSIONS_WRITE;
    assert_eq!(
        apply_event(Some(&original), &changed),
        Err(RefusalCode::EvidenceStale)
    );
}

#[test]
fn fixed_lifecycle_rejects_reissue_revoke_without_issue_and_sponsor_substitution() {
    let opened = issue();
    let AggregateId::AgentCredential(id) = opened.aggregate else {
        unreachable!()
    };
    assert!(AgentCredentialId::try_new([0; 32]).is_none());
    assert_eq!(id.to_string(), "09".repeat(32));
    assert_eq!(opened.aggregate.to_string(), id.aggregate_label());
    for (expected_version, action) in [
        (
            ExpectedVersion::Exactly(AggregateVersion::FIRST),
            AgentCredentialAction::Issue(grant()),
        ),
        (
            ExpectedVersion::NewStream,
            AgentCredentialAction::Revoke(grant()),
        ),
        (
            ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap()),
            AgentCredentialAction::Revoke(grant()),
        ),
    ] {
        assert_eq!(
            AgentCredentialCommand {
                id,
                expected_version,
                action
            }
            .proposed_event(grant().sponsor),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
    assert_eq!(
        AgentCredentialCommand {
            id,
            expected_version: ExpectedVersion::Exactly(
                AggregateVersion::try_new(u64::MAX).unwrap()
            ),
            action: AgentCredentialAction::Revoke(grant()),
        }
        .proposed_event(grant().sponsor),
        Err(RefusalCode::ResourceBudgetExceeded)
    );
    assert_eq!(
        AgentCredentialCommand {
            id,
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::Issue(grant()),
        }
        .proposed_event(grant().agent),
        Err(RefusalCode::EvidenceInvalid)
    );
    let mut wrong = opened.clone();
    wrong.aggregate = AggregateId::Issue(crate::IssueNumber::FIRST);
    assert!(encode_body(&wrong).is_err());
    wrong = opened;
    wrong.version = AggregateVersion::try_new(2).unwrap();
    assert!(encode_body(&wrong).is_err());
}

#[test]
fn grants_have_finite_lifetimes_explicit_scopes_and_nonzero_distinct_identities() {
    let valid = grant();
    assert!(valid.validate().is_ok());
    assert!(valid.permits(ISSUES_READ | ISSUES_WRITE));
    assert!(valid.permits(PULLS_WRITE));
    for denied in [0, PULLS_READ, DISCUSSIONS_WRITE, OUTCOMES_READ, 1 << 15] {
        assert!(!valid.permits(denied));
    }
    let maximum = AgentCredentialGrant {
        expires_at: valid.issued_at + MAX_LIFETIME_SECONDS,
        ..valid
    };
    assert!(maximum.validate().is_ok());
    for invalid in [
        AgentCredentialGrant {
            agent: valid.sponsor,
            ..valid
        },
        AgentCredentialGrant {
            agent: PrincipalId::from_bytes([0; 16]),
            ..valid
        },
        AgentCredentialGrant {
            sponsor: PrincipalId::from_bytes([0; 16]),
            ..valid
        },
        AgentCredentialGrant {
            tenant: TenantId::from_bytes([0; 16]),
            ..valid
        },
        AgentCredentialGrant {
            repository: RepositoryId::from_bytes([0; 16]),
            ..valid
        },
        AgentCredentialGrant {
            incarnation: RepositoryIncarnationId::from_bytes([0; 16]),
            ..valid
        },
        AgentCredentialGrant {
            issued_at: 0,
            ..valid
        },
        AgentCredentialGrant {
            expires_at: valid.issued_at,
            ..valid
        },
        AgentCredentialGrant {
            expires_at: valid.issued_at - 1,
            ..valid
        },
        AgentCredentialGrant {
            expires_at: maximum.expires_at + 1,
            ..valid
        },
        AgentCredentialGrant {
            operations: 0,
            ..valid
        },
        AgentCredentialGrant {
            operations: ALL_OPERATIONS | (1 << 15),
            ..valid
        },
    ] {
        assert!(invalid.validate().is_err(), "{invalid:?}");
    }
    assert!(
        AgentCredentialGrant {
            issued_at: u64::MAX - 1,
            expires_at: u64::MAX,
            ..valid
        }
        .validate()
        .is_ok()
    );
    for kind in [SponsorKind::Human, SponsorKind::Service] {
        assert_eq!(SponsorKind::from_code_point(kind.code_point()), Some(kind));
        assert!(
            AgentCredentialGrant {
                sponsor_kind: kind,
                ..valid
            }
            .validate()
            .is_ok()
        );
    }
    for unknown in [0, 3, u32::MAX] {
        assert_eq!(SponsorKind::from_code_point(unknown), None);
    }
}

#[test]
fn required_tags_unknown_fields_and_every_truncation_fail_closed() {
    let event = issue();
    let mut out = Encoder::new();
    event.write_payload(&mut out).unwrap();
    let bytes = out.into_bytes();
    assert_eq!(bytes.len(), 178);
    assert_eq!(&bytes[..8], &[0; 8]);
    assert_eq!(&bytes[8..12], &13u32.to_be_bytes());
    assert_eq!(&bytes[52..56], &25u32.to_be_bytes());
    assert_eq!(&bytes[72..76], &1u32.to_be_bytes());
    for end in 0..bytes.len() {
        let mut input = Decoder::new(&bytes[..end], DecodeLimits::DEFAULT);
        assert!(
            ForgeEvent::read_payload(&mut input).is_err(),
            "truncation {end}"
        );
    }
    for (start, replacement) in [
        (8, 14u32.to_be_bytes()),
        (52, 26u32.to_be_bytes()),
        (72, 3u32.to_be_bytes()),
        (108, 3u32.to_be_bytes()),
    ] {
        let mut changed = bytes.clone();
        changed[start..start + 4].copy_from_slice(&replacement);
        let mut input = Decoder::new(&changed, DecodeLimits::DEFAULT);
        assert!(
            ForgeEvent::read_payload(&mut input).is_err(),
            "unknown at {start}"
        );
    }
    let mut zero_id = bytes;
    zero_id[12..44].fill(0);
    assert!(ForgeEvent::read_payload(&mut Decoder::new(&zero_id, DecodeLimits::DEFAULT)).is_err());
    let legacy = ForgeEvent {
        aggregate: AggregateId::PullRequest(crate::PullRequestNumber::FIRST),
        version: AggregateVersion::FIRST,
        payload: ForgeEventPayload::PullRequestClosed { withdrawn: true },
    };
    let mut out = Encoder::new();
    legacy.write_payload(&mut out).unwrap();
    assert_eq!(
        out.as_bytes(),
        &[
            0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 1
        ]
    );
}

#[test]
fn lossless_bounded_labels_reject_noncanonical_padding_and_aliases() {
    for bytes in [[1; 32], [0xff; 32], [0x80; 32], {
        let mut bytes = [0; 32];
        bytes[31] = 1;
        bytes
    }] {
        let id = AgentCredentialId::try_new(bytes).unwrap();
        let label = id.aggregate_label();
        assert_eq!(label.len(), 58);
        assert!(fgit_types::AsciiSlug::try_new("credential", label.as_bytes()).is_ok());
        assert_eq!(AgentCredentialId::from_aggregate_label(&label), Some(id));
        assert_eq!(AggregateId::AgentCredential(id).to_string(), label);
        assert!(AgentCredentialId::from_aggregate_label(&label.to_uppercase()).is_none());
        assert!(AgentCredentialId::from_aggregate_label(&format!("{label}=")).is_none());
        assert!(AgentCredentialId::from_aggregate_label(&label[..57]).is_none());
        let mut padding = label;
        padding.pop();
        padding.push('b');
        assert!(AgentCredentialId::from_aggregate_label(&padding).is_none());
    }
    assert!(
        AgentCredentialId::from_aggregate_label(&format!("agent/{}", "a".repeat(52))).is_none()
    );
    assert!(
        AgentCredentialId::from_aggregate_label(&format!("check/{}", "7".repeat(52))).is_none()
    );
}
