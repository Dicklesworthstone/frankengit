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

fn read_complete_event_payload(bytes: &[u8]) -> Result<ForgeEvent, CodecRefusal> {
    let mut input = Decoder::new(bytes, DecodeLimits::DEFAULT);
    let event = ForgeEvent::read_payload(&mut input)?;
    input.finish()?;
    Ok(event)
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
    for denied in [
        0,
        PULLS_READ,
        DISCUSSIONS_WRITE,
        OUTCOMES_READ,
        PULLS_FEEDBACK_READ,
        PULLS_CHECK_EVIDENCE_READ,
    ] {
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
fn extended_operation_masks_reject_every_unassigned_flag() {
    assert_eq!(ALL_OPERATIONS, 0x3ffff);
    let known = AgentCredentialGrant {
        operations: ALL_OPERATIONS,
        ..grant()
    };
    assert!(known.validate().is_ok());
    for unknown in (18..32).map(|bit| 1u32 << bit) {
        let malformed = AgentCredentialGrant {
            operations: known.operations | unknown,
            ..known
        };
        assert!(malformed.validate().is_err());
        assert!(!malformed.permits(ISSUES_READ));
        assert!(!malformed.permits(unknown));
        assert!(!known.permits(unknown));
        assert!(!known.permits(ISSUES_READ | unknown));
    }
}

#[test]
fn source_reads_are_independent_of_legacy_metadata_and_feedback_scopes() {
    // Freeze the original seven-bit mask rather than giving historical grants
    // whatever future operations ALL_OPERATIONS might come to contain.
    let legacy = AgentCredentialGrant {
        operations: 0x007f,
        ..grant()
    };
    assert!(legacy.validate().is_ok());
    assert!(!legacy.permits(SOURCE_READ));
    let source = AgentCredentialGrant {
        operations: SOURCE_READ,
        ..grant()
    };
    assert!(source.validate().is_ok());
    assert!(source.permits(SOURCE_READ));
    for metadata in [
        ISSUES_READ,
        ISSUES_WRITE,
        PULLS_READ,
        PULLS_WRITE,
        DISCUSSIONS_READ,
        DISCUSSIONS_WRITE,
        OUTCOMES_READ,
    ] {
        assert!(legacy.permits(metadata));
        assert!(!source.permits(metadata));
        assert!(!source.permits(SOURCE_READ | metadata));
        let explicit = AgentCredentialGrant {
            operations: SOURCE_READ | metadata,
            ..grant()
        };
        assert!(explicit.validate().is_ok());
        assert!(explicit.permits(SOURCE_READ | metadata));
    }
    let feedback = AgentCredentialGrant {
        operations: SOURCE_READ | PULLS_FEEDBACK_READ,
        ..source
    };
    assert!(feedback.validate().is_ok());
    assert!(feedback.permits(SOURCE_READ | PULLS_FEEDBACK_READ));
    assert!(!source.permits(PULLS_FEEDBACK_READ));
    assert!(!source.permits(SOURCE_READ | PULLS_FEEDBACK_READ));
    assert!(!source.permits(0));
}

#[test]
fn expanded_grant_issue_and_revocation_round_trip_without_widening_legacy_grants() {
    for operations in [
        0x007f,
        0x00ff,
        0x01ff,
        0x03ff,
        SOURCE_READ,
        SOURCE_READ | PULLS_READ,
        SOURCE_HISTORY_READ,
        SOURCE_HISTORY_READ | SOURCE_READ | PULLS_READ,
        SOURCE_CANDIDATES,
        SOURCE_CANDIDATES | SOURCE_READ | PULLS_READ,
        MILESTONES_READ,
        MILESTONES_WRITE,
        MILESTONES_READ | MILESTONES_WRITE,
        MILESTONES_WRITE | ISSUES_WRITE,
        0x0fff,
        SOURCE_VERIFIED_READ,
        PULLS_DIFF_READ,
        SOURCE_VERIFIED_READ | PULLS_DIFF_READ | SOURCE_READ,
        0x6fff,
        PULLS_FEEDBACK_READ,
        PULLS_FEEDBACK_READ | PULLS_READ,
        PULLS_FEEDBACK_READ | PULLS_DIFF_READ,
        0xefff,
    ] {
        let grant = AgentCredentialGrant {
            operations,
            ..grant()
        };
        let issued = AgentCredentialCommand {
            id: AgentCredentialId::try_new([9; 32]).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::Issue(grant),
        }
        .proposed_event(grant.sponsor)
        .unwrap();
        let mut payload = Encoder::new();
        issued.write_payload(&mut payload).unwrap();
        // The required u16 operation field retains its original location and
        // meaning; granting the new bit does not reinterpret any older byte.
        assert_eq!(payload.as_bytes().len(), 178);
        assert_eq!(
            &payload.as_bytes()[176..178],
            &u16::try_from(operations).unwrap().to_be_bytes()
        );
        // All historical u16 bits are assigned. The empty mask remains invalid.
        let mut invalid = payload.into_bytes();
        invalid[176..178].fill(0);
        assert!(
            ForgeEvent::read_payload(&mut Decoder::new(&invalid, DecodeLimits::DEFAULT)).is_err()
        );
        let original = apply_event(None, &issued).unwrap();
        let revoked = revoke(&original);
        for event in [issued, revoked.clone()] {
            let bytes = encode_body(&event).unwrap();
            let decoded = decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap();
            assert_eq!(decoded, event);
            assert_eq!(encode_body(&decoded).unwrap(), bytes);
        }
        let final_state = apply_event(Some(&original), &revoked).unwrap();
        assert!(final_state.revoked);
        assert_eq!(original.grant, grant);
        assert_eq!(final_state.grant, grant);
        assert_eq!(
            original.grant.permits(SOURCE_READ),
            operations & SOURCE_READ != 0
        );
        assert_eq!(
            original.grant.permits(SOURCE_HISTORY_READ),
            operations & SOURCE_HISTORY_READ != 0
        );
        assert_eq!(
            original.grant.permits(SOURCE_CANDIDATES),
            operations & SOURCE_CANDIDATES != 0
        );
        assert_eq!(
            original.grant.permits(MILESTONES_READ),
            operations & MILESTONES_READ != 0
        );
        assert_eq!(
            original.grant.permits(MILESTONES_WRITE),
            operations & MILESTONES_WRITE != 0
        );
        assert_eq!(
            original.grant.permits(PULLS_FEEDBACK_READ),
            operations & PULLS_FEEDBACK_READ != 0
        );
        let mut substituted = revoked;
        let ForgeEventPayload::AgentCredentialChangedNative(change) = &mut substituted.payload
        else {
            unreachable!()
        };
        let AgentCredentialAction::Revoke(grant) = &mut change.action else {
            unreachable!()
        };
        grant.operations = (grant.operations ^ SOURCE_READ) | PULLS_WRITE;
        assert_eq!(
            apply_event(Some(&original), &substituted),
            Err(RefusalCode::EvidenceStale)
        );
    }
}

#[test]
fn history_access_is_independent_of_every_preexisting_operation() {
    // A previously issued all-scopes credential must not acquire history access
    // when readers upgrade. Freeze the actual old bits, not ALL_OPERATIONS.
    let old = AgentCredentialGrant {
        operations: 0x00ff,
        ..grant()
    };
    let history = AgentCredentialGrant {
        operations: SOURCE_HISTORY_READ,
        ..grant()
    };
    assert!(old.validate().is_ok());
    assert!(!old.permits(SOURCE_HISTORY_READ));
    assert!(history.validate().is_ok());
    assert!(history.permits(SOURCE_HISTORY_READ));
    assert!(!history.permits(0));
    for other in (0..8).map(|bit| 1u32 << bit) {
        assert!(old.permits(other));
        assert!(!history.permits(other));
        assert!(!history.permits(SOURCE_HISTORY_READ | other));
        let combined = AgentCredentialGrant {
            operations: SOURCE_HISTORY_READ | other,
            ..history
        };
        assert!(combined.validate().is_ok());
        assert!(combined.permits(SOURCE_HISTORY_READ | other));
    }
    let feedback = AgentCredentialGrant {
        operations: SOURCE_HISTORY_READ | PULLS_FEEDBACK_READ,
        ..history
    };
    assert!(feedback.validate().is_ok());
    assert!(feedback.permits(SOURCE_HISTORY_READ | PULLS_FEEDBACK_READ));
    assert!(!history.permits(PULLS_FEEDBACK_READ));
    assert!(!history.permits(SOURCE_HISTORY_READ | PULLS_FEEDBACK_READ));
}

#[test]
fn candidate_work_requires_a_new_explicit_grant_without_widening_old_masks() {
    let old = AgentCredentialGrant {
        operations: 0x01ff,
        ..grant()
    };
    let candidate = AgentCredentialGrant {
        operations: SOURCE_CANDIDATES,
        ..grant()
    };
    assert!(old.validate().is_ok());
    assert!(candidate.validate().is_ok());
    assert!(!old.permits(SOURCE_CANDIDATES));
    assert!(candidate.permits(SOURCE_CANDIDATES));
    for other in (0..9).map(|bit| 1u32 << bit) {
        assert!(old.permits(other));
        assert!(!candidate.permits(other));
        assert!(!candidate.permits(SOURCE_CANDIDATES | other));
        let combined = AgentCredentialGrant {
            operations: SOURCE_CANDIDATES | other,
            ..candidate
        };
        assert!(combined.validate().is_ok());
        assert!(combined.permits(SOURCE_CANDIDATES | other));
    }
    let feedback = AgentCredentialGrant {
        operations: SOURCE_CANDIDATES | PULLS_FEEDBACK_READ,
        ..candidate
    };
    assert!(feedback.validate().is_ok());
    assert!(feedback.permits(SOURCE_CANDIDATES | PULLS_FEEDBACK_READ));
    assert!(!candidate.permits(PULLS_FEEDBACK_READ));
    assert!(!candidate.permits(SOURCE_CANDIDATES | PULLS_FEEDBACK_READ));
}

#[test]
fn milestone_scopes_are_independent_and_do_not_expand_any_retained_grant() {
    let old = AgentCredentialGrant {
        operations: 0x03ff,
        ..grant()
    };
    assert!(old.validate().is_ok());
    for scope in [MILESTONES_READ, MILESTONES_WRITE] {
        assert!(!old.permits(scope));
        let milestone = AgentCredentialGrant {
            operations: scope,
            ..grant()
        };
        assert!(milestone.validate().is_ok());
        assert!(milestone.permits(scope));
        assert!(!milestone.permits(0));
        for other in (0..12).map(|bit| 1u32 << bit).filter(|bit| *bit != scope) {
            assert!(!milestone.permits(other));
            assert!(!milestone.permits(scope | other));
            let combined = AgentCredentialGrant {
                operations: scope | other,
                ..milestone
            };
            assert!(combined.validate().is_ok());
            assert!(combined.permits(scope | other));
        }
        let feedback = AgentCredentialGrant {
            operations: scope | PULLS_FEEDBACK_READ,
            ..milestone
        };
        assert!(feedback.validate().is_ok());
        assert!(feedback.permits(scope | PULLS_FEEDBACK_READ));
        assert!(!milestone.permits(PULLS_FEEDBACK_READ));
        assert!(!milestone.permits(scope | PULLS_FEEDBACK_READ));
    }
}

#[test]
fn required_tags_unknown_fields_and_every_truncation_fail_closed() {
    let event = issue();
    let mut out = Encoder::new();
    event.write_payload(&mut out).unwrap();
    let bytes = out.into_bytes();
    let frozen_legacy = [
        &[0u8; 8][..],
        &13u32.to_be_bytes(),
        &[9; 32],
        &1u64.to_be_bytes(),
        &25u32.to_be_bytes(),
        &[2; 16],
        &1u32.to_be_bytes(),
        &[1; 16],
        &[2; 16],
        &1u32.to_be_bytes(),
        &[3; 16],
        &[4; 16],
        &[5; 16],
        &100u64.to_be_bytes(),
        &200u64.to_be_bytes(),
        &0x000bu16.to_be_bytes(),
    ]
    .concat();
    assert_eq!(
        bytes, frozen_legacy,
        "legacy grants must retain their exact canonical bytes"
    );
    let revoked = revoke(&apply_event(None, &event).unwrap());
    let mut revoked_bytes = Encoder::new();
    revoked.write_payload(&mut revoked_bytes).unwrap();
    let mut frozen_revoked = frozen_legacy;
    frozen_revoked[44..52].copy_from_slice(&2u64.to_be_bytes());
    frozen_revoked[56..72].fill(7);
    frozen_revoked[72..76].copy_from_slice(&2u32.to_be_bytes());
    assert_eq!(revoked_bytes.as_bytes(), frozen_revoked);
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
        (8, u32::MAX.to_be_bytes()),
        (52, 26u32.to_be_bytes()),
        (72, 9u32.to_be_bytes()),
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

fn source_scope(paths: &[&[u8]]) -> SourcePublicationScope {
    SourcePublicationScope::new(
        "exact:726566732f68656164732f6167656e74",
        paths.iter().map(|path| path.to_vec()).collect(),
    )
    .unwrap()
}

#[test]
fn source_publication_requires_its_new_bit_and_explicit_extended_scope() {
    let id = AgentCredentialId::try_new([9; 32]).unwrap();
    let source = AgentCredentialGrant {
        operations: SOURCE_PUBLISH,
        ..grant()
    };
    let historical = AgentCredentialGrant {
        operations: 0x0fff,
        ..grant()
    };
    assert!(!historical.permits(SOURCE_PUBLISH));
    for other in (0..12).map(|bit| 1u32 << bit) {
        assert!(!source.permits(other));
    }
    for action in [
        AgentCredentialAction::Issue(source),
        AgentCredentialAction::IssueSource {
            grant: historical,
            scope: source_scope(&[b"src"]),
        },
    ] {
        assert_eq!(
            AgentCredentialCommand {
                id,
                expected_version: ExpectedVersion::NewStream,
                action,
            }
            .proposed_event(source.sponsor),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
    let issued = AgentCredentialCommand {
        id,
        expected_version: ExpectedVersion::NewStream,
        action: AgentCredentialAction::IssueSource {
            grant: source,
            scope: source_scope(&[b"src"]),
        },
    }
    .proposed_event(source.sponsor)
    .unwrap();
    let original = apply_event(None, &issued).unwrap();
    assert_eq!(original.source_scope, Some(source_scope(&[b"src"])));
    assert!(!original.grant.permits(SOURCE_READ | SOURCE_CANDIDATES));
    let mut legacy_bytes = Encoder::new();
    issue().write_payload(&mut legacy_bytes).unwrap();
    assert_eq!(legacy_bytes.as_bytes().len(), 178);
    assert_eq!(&legacy_bytes.as_bytes()[72..76], &1u32.to_be_bytes());
}

#[test]
fn task_branch_creation_is_an_independent_scoped_grant_without_legacy_widening() {
    assert_eq!(SOURCE_BRANCH_CREATE, 1 << 16);
    let legacy = AgentCredentialGrant {
        operations: 0xffff,
        ..grant()
    };
    assert!(!legacy.permits(SOURCE_BRANCH_CREATE));
    for operations in [SOURCE_BRANCH_CREATE, SOURCE_BRANCH_CREATE | SOURCE_PUBLISH] {
        let grant = AgentCredentialGrant {
            operations,
            ..grant()
        };
        assert!(grant.requires_source_scope());
        assert!(!grant.permits(SOURCE_READ | SOURCE_CANDIDATES));
        let id = AgentCredentialId::try_new([8; 32]).unwrap();
        let command = |action| AgentCredentialCommand {
            id,
            expected_version: ExpectedVersion::NewStream,
            action,
        };
        assert_eq!(
            command(AgentCredentialAction::Issue(grant)).proposed_event(grant.sponsor),
            Err(RefusalCode::EvidenceInvalid)
        );
        let issued = command(AgentCredentialAction::issuance(
            grant,
            Some(source_scope(&[b"src"])),
        ))
        .proposed_event(grant.sponsor)
        .unwrap();
        let state = apply_event(None, &issued).unwrap();
        let revoked = AgentCredentialCommand {
            id,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: AgentCredentialAction::revocation(grant, state.source_scope.clone()),
        }
        .proposed_event(grant.sponsor)
        .unwrap();
        for (event, tag) in [(&issued, 5u32), (&revoked, 6)] {
            let frame = encode_body(event).unwrap();
            assert_eq!(
                decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap(),
                *event
            );
            let mut payload = Encoder::new();
            event.write_payload(&mut payload).unwrap();
            assert_eq!(&payload.as_bytes()[72..76], &tag.to_be_bytes());
            assert_eq!(&payload.as_bytes()[176..180], &operations.to_be_bytes());
            for end in 0..payload.as_bytes().len() {
                assert!(
                    ForgeEvent::read_payload(&mut Decoder::new(
                        &payload.as_bytes()[..end],
                        DecodeLimits::DEFAULT,
                    ))
                    .is_err()
                );
            }
            for invalid_mask in [
                0,
                SOURCE_PUBLISH,
                0xffff,
                SOURCE_BRANCH_CREATE | (1 << 18),
                u32::MAX,
            ] {
                let mut malformed = payload.as_bytes().to_vec();
                malformed[176..180].copy_from_slice(&invalid_mask.to_be_bytes());
                assert!(
                    ForgeEvent::read_payload(&mut Decoder::new(&malformed, DecodeLimits::DEFAULT))
                        .is_err()
                );
            }
            // Wider masks cannot be smuggled into a historical action code,
            // and the new action tags have no unscoped alias.
            for invalid_tag in [tag - 2, tag - 4, 7, 8, 9] {
                let mut downgraded = payload.as_bytes().to_vec();
                downgraded[72..76].copy_from_slice(&invalid_tag.to_be_bytes());
                assert!(read_complete_event_payload(&downgraded).is_err());
            }
        }
        assert!(apply_event(Some(&state), &revoked).unwrap().revoked);
        if operations == SOURCE_BRANCH_CREATE {
            assert!(!state.grant.permits(SOURCE_PUBLISH));
        }
    }
    // Retain both existing action tags and existing bytes when the new bit is
    // absent; neither upgrading a reader nor adding a scope grants creation.
    let old_event = AgentCredentialCommand {
        id: AgentCredentialId::try_new([7; 32]).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: AgentCredentialAction::issuance(legacy, Some(source_scope(&[b"src"]))),
    }
    .proposed_event(legacy.sponsor)
    .unwrap();
    let frame = encode_body(&old_event).unwrap();
    let mut old_payload = Encoder::new();
    old_event.write_payload(&mut old_payload).unwrap();
    assert_eq!(&old_payload.as_bytes()[72..76], &3u32.to_be_bytes());
    assert_eq!(&old_payload.as_bytes()[176..178], &u16::MAX.to_be_bytes());
    let decoded = decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap();
    assert_eq!(encode_body(&decoded).unwrap(), frame);
    assert!(
        !apply_event(None, &decoded)
            .unwrap()
            .grant
            .permits(SOURCE_BRANCH_CREATE)
    );
}

#[test]
fn check_evidence_disclosure_is_independent_of_all_retained_operations() {
    assert_eq!(PULLS_CHECK_EVIDENCE_READ, 1 << 17);
    let retained = AgentCredentialGrant {
        operations: 0x1ffff,
        ..grant()
    };
    let evidence = AgentCredentialGrant {
        operations: PULLS_CHECK_EVIDENCE_READ,
        ..grant()
    };
    assert!(retained.validate().is_ok());
    assert!(!retained.permits(PULLS_CHECK_EVIDENCE_READ));
    assert!(evidence.validate().is_ok());
    assert!(evidence.permits(PULLS_CHECK_EVIDENCE_READ));
    assert!(!evidence.requires_source_scope());
    assert!(!evidence.permits(0));
    for operation in (0..17).map(|bit| 1u32 << bit) {
        assert!(retained.permits(operation));
        assert!(!retained.permits(operation | PULLS_CHECK_EVIDENCE_READ));
        assert!(!evidence.permits(operation));
        assert!(!evidence.permits(operation | PULLS_CHECK_EVIDENCE_READ));
        let explicit = AgentCredentialGrant {
            operations: operation | PULLS_CHECK_EVIDENCE_READ,
            ..evidence
        };
        assert!(explicit.permits(operation | PULLS_CHECK_EVIDENCE_READ));
        assert_eq!(
            explicit.requires_source_scope(),
            operation == SOURCE_PUBLISH || operation == SOURCE_BRANCH_CREATE
        );
    }
}

#[test]
fn check_evidence_grants_round_trip_with_canonical_unscoped_extended_actions() {
    for operations in [
        PULLS_CHECK_EVIDENCE_READ,
        PULLS_CHECK_EVIDENCE_READ | PULLS_FEEDBACK_READ,
        PULLS_CHECK_EVIDENCE_READ | SOURCE_READ | PULLS_READ,
        0x2efff,
    ] {
        let grant = AgentCredentialGrant {
            operations,
            ..grant()
        };
        let issued = AgentCredentialCommand {
            id: AgentCredentialId::try_new([6; 32]).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::Issue(grant),
        }
        .proposed_event(grant.sponsor)
        .unwrap();
        let original = apply_event(None, &issued).unwrap();
        assert!(original.source_scope.is_none());
        let revoked = revoke(&original);
        for (event, tag) in [(&issued, 7u32), (&revoked, 8)] {
            let frame = encode_body(event).unwrap();
            let decoded = decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap();
            assert_eq!(decoded, *event);
            assert_eq!(encode_body(&decoded).unwrap(), frame);
            let mut payload = Encoder::new();
            event.write_payload(&mut payload).unwrap();
            assert_eq!(payload.as_bytes().len(), 180);
            assert_eq!(&payload.as_bytes()[72..76], &tag.to_be_bytes());
            assert_eq!(&payload.as_bytes()[176..180], &operations.to_be_bytes());
            for end in 0..payload.as_bytes().len() {
                assert!(
                    ForgeEvent::read_payload(&mut Decoder::new(
                        &payload.as_bytes()[..end],
                        DecodeLimits::DEFAULT,
                    ))
                    .is_err()
                );
            }
            for invalid_mask in [
                0,
                PULLS_FEEDBACK_READ,
                0xefff,
                SOURCE_BRANCH_CREATE,
                PULLS_CHECK_EVIDENCE_READ | SOURCE_PUBLISH,
                PULLS_CHECK_EVIDENCE_READ | (1 << 18),
                u32::MAX,
            ] {
                let mut malformed = payload.as_bytes().to_vec();
                malformed[176..180].copy_from_slice(&invalid_mask.to_be_bytes());
                assert!(
                    ForgeEvent::read_payload(&mut Decoder::new(&malformed, DecodeLimits::DEFAULT))
                        .is_err(),
                    "mask {invalid_mask:#x} must not have an unscoped extended spelling"
                );
            }
            for invalid_tag in [1u32, 2, 3, 4, 5, 6, 9] {
                let mut malformed = payload.as_bytes().to_vec();
                malformed[72..76].copy_from_slice(&invalid_tag.to_be_bytes());
                assert!(read_complete_event_payload(&malformed).is_err());
            }
        }
        let terminal = apply_event(Some(&original), &revoked).unwrap();
        assert!(terminal.revoked);
        assert_eq!(terminal.grant, grant);
        assert!(terminal.source_scope.is_none());
        let changed = AgentCredentialCommand {
            id: original.id,
            expected_version: ExpectedVersion::Exactly(original.version),
            action: AgentCredentialAction::Revoke(AgentCredentialGrant {
                operations: (operations ^ PULLS_CHECK_EVIDENCE_READ) | ISSUES_READ,
                ..grant
            }),
        }
        .proposed_event(grant.sponsor)
        .unwrap();
        assert_eq!(
            apply_event(Some(&original), &changed),
            Err(RefusalCode::EvidenceStale)
        );
        assert_eq!(
            NativeAgentCredentialEvent {
                actor: grant.sponsor,
                action: AgentCredentialAction::IssueSource {
                    grant,
                    scope: source_scope(&[b"src"]),
                },
            }
            .validate(),
            Err(invalid_native("agent_credential.source_scope_required"))
        );
    }
}

#[test]
fn check_evidence_preserves_separately_granted_source_ceilings_and_retained_bytes() {
    for operations in [
        0x1ffff,
        PULLS_CHECK_EVIDENCE_READ | SOURCE_PUBLISH,
        PULLS_CHECK_EVIDENCE_READ | SOURCE_BRANCH_CREATE,
        ALL_OPERATIONS,
    ] {
        let grant = AgentCredentialGrant {
            operations,
            ..grant()
        };
        let scope = source_scope(&[b"src"]);
        let issued = AgentCredentialCommand {
            id: AgentCredentialId::try_new([5; 32]).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::issuance(grant, Some(scope.clone())),
        }
        .proposed_event(grant.sponsor)
        .unwrap();
        let original = apply_event(None, &issued).unwrap();
        let revoked = AgentCredentialCommand {
            id: original.id,
            expected_version: ExpectedVersion::Exactly(original.version),
            action: AgentCredentialAction::revocation(grant, Some(scope.clone())),
        }
        .proposed_event(grant.sponsor)
        .unwrap();
        for (event, tag) in [(&issued, 5u32), (&revoked, 6)] {
            let frame = encode_body(event).unwrap();
            let decoded = decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap();
            assert_eq!(decoded, *event);
            assert_eq!(encode_body(&decoded).unwrap(), frame);
            let mut payload = Encoder::new();
            event.write_payload(&mut payload).unwrap();
            assert_eq!(&payload.as_bytes()[72..76], &tag.to_be_bytes());
            assert_eq!(&payload.as_bytes()[176..180], &operations.to_be_bytes());
        }
        let terminal = apply_event(Some(&original), &revoked).unwrap();
        assert!(terminal.revoked);
        assert_eq!(terminal.grant, grant);
        assert_eq!(terminal.source_scope, Some(scope));
        assert_eq!(
            terminal.grant.permits(PULLS_CHECK_EVIDENCE_READ),
            operations != 0x1ffff
        );
    }
}

#[test]
fn source_issue_and_revocation_round_trip_and_pin_every_attenuation() {
    let grant = AgentCredentialGrant {
        operations: SOURCE_PUBLISH | SOURCE_READ,
        ..grant()
    };
    let scope = source_scope(&[b"src", b"data/\xff"]);
    let issued = AgentCredentialCommand {
        id: AgentCredentialId::try_new([9; 32]).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: AgentCredentialAction::issuance(grant, Some(scope.clone())),
    }
    .proposed_event(grant.sponsor)
    .unwrap();
    let original = apply_event(None, &issued).unwrap();
    let revoke = |scope| {
        AgentCredentialCommand {
            id: original.id,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: AgentCredentialAction::revocation(grant, Some(scope)),
        }
        .proposed_event(grant.sponsor)
        .unwrap()
    };
    let revoked = revoke(scope.clone());
    for (event, tag) in [(&issued, 3u32), (&revoked, 4)] {
        let frame = encode_body(event).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap(),
            *event
        );
        let mut bytes = Encoder::new();
        event.write_payload(&mut bytes).unwrap();
        assert_eq!(&bytes.as_bytes()[72..76], &tag.to_be_bytes());
        assert_eq!(
            &bytes.as_bytes()[176..178],
            &u16::try_from(grant.operations).unwrap().to_be_bytes()
        );
        for end in 0..bytes.as_bytes().len() {
            assert!(
                ForgeEvent::read_payload(&mut Decoder::new(
                    &bytes.as_bytes()[..end],
                    DecodeLimits::DEFAULT,
                ))
                .is_err(),
                "source action {tag}, truncation {end}"
            );
        }
        // A wider encoding cannot alias an existing source grant, even when
        // its complete u32 mask and scope would otherwise parse correctly.
        let mut wide_alias = bytes.as_bytes().to_vec();
        wide_alias[72..76].copy_from_slice(&(tag + 2).to_be_bytes());
        wide_alias.splice(176..178, grant.operations.to_be_bytes());
        assert!(
            ForgeEvent::read_payload(&mut Decoder::new(&wide_alias, DecodeLimits::DEFAULT))
                .is_err()
        );
        // A newer source grant cannot be reinterpreted as a legacy flat grant.
        let mut downgraded = bytes.into_bytes();
        downgraded[72..76].copy_from_slice(&(tag - 2).to_be_bytes());
        assert!(
            ForgeEvent::read_payload(&mut Decoder::new(&downgraded, DecodeLimits::DEFAULT,))
                .is_err()
        );
    }
    let final_state = apply_event(Some(&original), &revoked).unwrap();
    assert!(final_state.revoked);
    assert_eq!(final_state.source_scope, original.source_scope);
    assert_eq!(final_state.grant, original.grant);
    for replacement in [source_scope(&[b"src"]), source_scope(&[b""])] {
        assert_eq!(
            apply_event(Some(&original), &revoke(replacement)),
            Err(RefusalCode::EvidenceStale)
        );
    }
    let other_ref = SourcePublicationScope::new(
        "exact:726566732f68656164732f6d61696e",
        scope.path_prefixes().to_vec(),
    )
    .unwrap();
    assert_eq!(
        apply_event(Some(&original), &revoke(other_ref)),
        Err(RefusalCode::EvidenceStale)
    );
    assert_eq!(
        apply_event(Some(&final_state), &issued),
        Err(RefusalCode::EvidenceStale)
    );
    assert_eq!(
        apply_event(Some(&final_state), &revoked),
        Err(RefusalCode::EvidenceStale)
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

#[test]
fn proof_and_pull_diff_grants_preserve_prior_operation_bits_and_are_independent() {
    assert_eq!(SOURCE_PUBLISH, 1 << 12);
    assert_eq!(SOURCE_VERIFIED_READ, 1 << 13);
    assert_eq!(PULLS_DIFF_READ, 1 << 14);
    for historical in [0x007f, 0x00ff, 0x01ff, 0x03ff, 0x0fff, 0x1fff] {
        let old = AgentCredentialGrant {
            operations: historical,
            ..grant()
        };
        assert!(old.validate().is_ok());
        assert!(!old.permits(SOURCE_VERIFIED_READ));
        assert!(!old.permits(PULLS_DIFF_READ));
    }
    for operation in [SOURCE_VERIFIED_READ, PULLS_DIFF_READ] {
        let selected = AgentCredentialGrant {
            operations: operation,
            ..grant()
        };
        assert!(selected.validate().is_ok());
        assert!(selected.permits(operation));
        for other in (0..15).map(|bit| 1 << bit).filter(|bit| *bit != operation) {
            assert!(!selected.permits(other));
            assert!(!selected.permits(operation | other));
        }
        assert!(!selected.permits(PULLS_FEEDBACK_READ));
    }
}

#[test]
fn feedback_retains_the_last_legacy_bit_without_widening_any_retained_grant() {
    assert_eq!(PULLS_FEEDBACK_READ, 0x8000);
    assert_eq!(ALL_OPERATIONS & 0xffff, u32::from(u16::MAX));
    let old = AgentCredentialGrant {
        operations: 0x7fff,
        ..grant()
    };
    let feedback = AgentCredentialGrant {
        operations: PULLS_FEEDBACK_READ,
        ..grant()
    };
    assert!(old.validate().is_ok());
    assert!(!old.permits(PULLS_FEEDBACK_READ));
    assert!(feedback.validate().is_ok());
    assert!(feedback.permits(PULLS_FEEDBACK_READ));
    assert!(!feedback.permits(0));
    assert!(!feedback.permits(SOURCE_BRANCH_CREATE));
    assert!(!feedback.permits(PULLS_CHECK_EVIDENCE_READ));
    for operation in (0..15).map(|bit| 1u32 << bit) {
        assert!(old.permits(operation));
        assert!(!old.permits(operation | PULLS_FEEDBACK_READ));
        assert!(!feedback.permits(operation));
        assert!(!feedback.permits(operation | PULLS_FEEDBACK_READ));
        let explicit = AgentCredentialGrant {
            operations: operation | PULLS_FEEDBACK_READ,
            ..feedback
        };
        assert!(explicit.validate().is_ok());
        assert!(explicit.permits(operation | PULLS_FEEDBACK_READ));
    }
}

#[test]
fn complete_masks_preserve_their_wire_bits_and_source_publication_ceiling() {
    for operations in [0x7fff, 0xffff] {
        let grant = AgentCredentialGrant {
            operations,
            ..grant()
        };
        assert!(grant.validate().is_ok());
        assert_eq!(
            grant.permits(PULLS_FEEDBACK_READ),
            operations == u32::from(u16::MAX)
        );
        assert!(!grant.permits(SOURCE_BRANCH_CREATE));
        let command = AgentCredentialCommand {
            id: AgentCredentialId::try_new([9; 32]).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::Issue(grant),
        };
        // Feedback does not relax the separate publication attenuation.
        assert_eq!(
            command.proposed_event(grant.sponsor),
            Err(RefusalCode::EvidenceInvalid)
        );
        let scope = source_scope(&[b"src"]);
        let issued = AgentCredentialCommand {
            action: AgentCredentialAction::IssueSource {
                grant,
                scope: scope.clone(),
            },
            ..command
        }
        .proposed_event(grant.sponsor)
        .unwrap();
        let mut payload = Encoder::new();
        issued.write_payload(&mut payload).unwrap();
        assert_eq!(&payload.as_bytes()[72..76], &3u32.to_be_bytes());
        assert_eq!(
            &payload.as_bytes()[176..178],
            &u16::try_from(operations).unwrap().to_be_bytes()
        );
        let bytes = encode_body(&issued).unwrap();
        let decoded = decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap();
        assert_eq!(encode_body(&decoded).unwrap(), bytes);
        let retained = apply_event(None, &decoded).unwrap();
        assert_eq!(retained.grant, grant);
        assert_eq!(retained.source_scope, Some(scope));
    }
}
