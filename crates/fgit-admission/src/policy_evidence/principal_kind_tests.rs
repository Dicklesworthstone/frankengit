use super::authentication_tests::{agent, setup, with_policy};
use super::*;
use crate::evidence::{AgentAuthentication, DecisionEvidenceBodies};
use fgit_forge::event::agent_credential::{AgentCredentialId, SponsorKind};
use fgit_types::GitHashAlgorithm;

const AGENT: &str = "policy release { rule agent { when actor.kind == agent and actor.id == \"33333333333333333333333333333333\" and actor.authentication == single_factor then allow } default deny \"authenticated agent required\" }";

#[test]
fn principal_kind_receipt_replays_exact_profile_and_complete_sponsor_witness() {
    let selected = fgit_forge::event::protection::compile_ref_policy(AGENT).unwrap();
    let alternative = fgit_forge::event::protection::compile_ref_policy("policy alternative { rule r { when not actor.kind == human then allow } default deny \"human excluded\" }").unwrap();
    for algorithm in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, basis, current, request, fold) = setup(algorithm);
        for kind in [SponsorKind::Human, SponsorKind::Service] {
            let witness = agent(&context, kind);
            let authentication = AdmissionAuthentication::AgentCredential(witness);
            let mut bodies = DecisionEvidenceBodies::derive_with_authentication(
                &context,
                &basis,
                &request,
                &fold,
                authentication,
            )
            .unwrap();
            bodies
                .record_activated_policy(
                    &context,
                    &basis,
                    &current,
                    RootLayoutVersion::LegacyWholeBody,
                    &fold,
                    Vec::new(),
                    selected.clone(),
                    RefPolicyPublication::Direct,
                )
                .unwrap();
            let PolicyDecisionRecord::PrincipalKindActivated(record) = bodies.policy_decision()
            else {
                panic!("principal kind profile")
            };
            assert_eq!(record.agent_provenance(), &witness);
            assert_eq!(record.authentication(), authentication);
            assert_eq!(
                bodies.policy_decision().authentication(),
                Some(authentication)
            );
            assert_eq!(
                bodies.principal_snapshot().agent_provenance(),
                Some(&witness)
            );
            record.replay().unwrap();
            bodies
                .verify_decision(&context, &basis, &request, &fold)
                .unwrap();
            record
                .verify_provenance(
                    &basis,
                    &current,
                    RootLayoutVersion::LegacyWholeBody,
                    &[],
                    &selected,
                )
                .unwrap();
            assert_eq!(
                record.verify_provenance(
                    &basis,
                    &current,
                    RootLayoutVersion::LegacyWholeBody,
                    &[],
                    &alternative,
                ),
                Err(RefusalCode::EvidenceInvalid)
            );

            let frame = bodies.policy_decision().encode().unwrap();
            assert_eq!(
                read_frame_header(&frame, DecodeLimits::DEFAULT)
                    .unwrap()
                    .0
                    .schema
                    .minor(),
                6
            );
            let decoded = PolicyDecisionRecord::decode(&frame, DecodeLimits::DEFAULT).unwrap();
            assert_eq!(&decoded, bodies.policy_decision());
            assert_eq!(decoded.encode().unwrap(), frame);
            assert!(PolicyDecisionRecord::decode(&frame, DecodeLimits::MINIMAL).is_err());
            for length in [0, 1, frame.len() / 2, frame.len() - 1] {
                assert!(
                    PolicyDecisionRecord::decode(&frame[..length], DecodeLimits::DEFAULT).is_err()
                );
            }
            let mut suffix = frame.clone();
            suffix.push(0);
            assert!(PolicyDecisionRecord::decode(&suffix, DecodeLimits::DEFAULT).is_err());
            let mut expired = frame.clone();
            let end = expired.len();
            expired[end - 8..].copy_from_slice(&witness.authenticated_at().to_be_bytes());
            assert!(PolicyDecisionRecord::decode(&expired, DecodeLimits::DEFAULT).is_err());
            let trace = record.evaluation().trace().as_bytes();
            let start = frame
                .windows(trace.len())
                .position(|window| window == trace)
                .unwrap();
            let mut forged_trace = frame;
            forged_trace[start] ^= 1;
            assert!(PolicyDecisionRecord::decode(&forged_trace, DecodeLimits::DEFAULT).is_err());
        }
    }
}

#[test]
fn principal_kind_evidence_refuses_unknown_kind_and_does_not_borrow_sponsor_identity() {
    let (context, basis, current, request, fold) = setup(GitHashAlgorithm::Sha1);
    for predicate in [
        "actor.kind == agent",
        "not actor.kind == human",
        "actor.id == \"unreachable\" and actor.kind == agent",
    ] {
        let selected = fgit_forge::event::protection::compile_ref_policy(&format!(
            "policy p {{ rule r {{ when {predicate} then allow }} default allow }}"
        ))
        .unwrap();
        let mut legacy = DecisionEvidenceBodies::derive(&context, &basis, &request, &fold).unwrap();
        assert_eq!(
            legacy.record_activated_policy(
                &context,
                &basis,
                &current,
                RootLayoutVersion::LegacyWholeBody,
                &fold,
                Vec::new(),
                selected.clone(),
                RefPolicyPublication::Direct,
            ),
            Err(RefusalCode::EvidenceMissing)
        );
        for authentication in [
            AdmissionAuthentication::OperatorAssertion,
            AdmissionAuthentication::HttpToken,
            AdmissionAuthentication::SshDeployKey,
        ] {
            let mut bodies = DecisionEvidenceBodies::derive_with_authentication(
                &context,
                &basis,
                &request,
                &fold,
                authentication,
            )
            .unwrap();
            assert_eq!(
                bodies.record_activated_policy(
                    &context,
                    &basis,
                    &current,
                    RootLayoutVersion::LegacyWholeBody,
                    &fold,
                    Vec::new(),
                    selected.clone(),
                    RefPolicyPublication::Direct,
                ),
                Err(RefusalCode::EvidenceMissing)
            );
        }
    }
    for predicate in [
        "actor.kind == human",
        "actor.kind == service",
        "actor.kind == agent and actor.authentication >= multi_factor",
    ] {
        let selected = fgit_forge::event::protection::compile_ref_policy(&format!(
            "policy p {{ rule r {{ when {predicate} then allow }} default deny \"actor requirement\" }}"
        )).unwrap();
        for kind in [SponsorKind::Human, SponsorKind::Service] {
            let mut bodies = DecisionEvidenceBodies::derive_with_authentication(
                &context,
                &basis,
                &request,
                &fold,
                AdmissionAuthentication::AgentCredential(agent(&context, kind)),
            )
            .unwrap();
            assert_eq!(
                bodies.record_activated_policy(
                    &context,
                    &basis,
                    &current,
                    RootLayoutVersion::LegacyWholeBody,
                    &fold,
                    Vec::new(),
                    selected.clone(),
                    RefPolicyPublication::Direct,
                ),
                Err(RefusalCode::ProtectedRefTransitionDenied)
            );
        }
    }
}

struct Relabelled<'a, const MINOR: u16> {
    fields: &'a ActivatedPolicyDecisionEvidence,
    profile: Profile,
    witness: Option<AgentAuthentication>,
}

impl<const MINOR: u16> CanonicalBody for Relabelled<'_, MINOR> {
    const DOMAIN: DomainTag = PolicyDecisionEvidence::DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = PolicyDecisionEvidence::SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = MINOR;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.fields.write_fields(out, self.profile)?;
        if let Some(witness) = self.witness {
            witness.write_fields(out)?;
        }
        Ok(())
    }

    fn read_payload(_: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Err(invalid("test.kind_relabelled"))
    }
}

#[test]
fn principal_kind_schema_cannot_be_relabelled_or_substituted_for_original_witness() {
    let (context, basis, current, request, fold) = setup(GitHashAlgorithm::Sha256);
    let selected = fgit_forge::event::protection::compile_ref_policy(AGENT).unwrap();
    let witness = agent(&context, SponsorKind::Human);
    let mut bodies = DecisionEvidenceBodies::derive_with_authentication(
        &context,
        &basis,
        &request,
        &fold,
        AdmissionAuthentication::AgentCredential(witness),
    )
    .unwrap();
    bodies
        .record_activated_policy(
            &context,
            &basis,
            &current,
            RootLayoutVersion::LegacyWholeBody,
            &fold,
            Vec::new(),
            selected.clone(),
            RefPolicyPublication::Direct,
        )
        .unwrap();
    let PolicyDecisionRecord::PrincipalKindActivated(record) = bodies.policy_decision() else {
        panic!("principal kind profile")
    };
    assert!(encode_body(&record.0).is_err());
    for frame in [
        encode_body(&Relabelled::<2> {
            fields: &record.0,
            profile: Profile::RepositoryPrincipalKindV1,
            witness: None,
        })
        .unwrap(),
        encode_body(&Relabelled::<3> {
            fields: &record.0,
            profile: Profile::RepositoryPrincipalKindV1,
            witness: None,
        })
        .unwrap(),
        encode_body(&Relabelled::<4> {
            fields: &record.0,
            profile: Profile::RepositoryPrincipalKindV1,
            witness: Some(witness),
        })
        .unwrap(),
        encode_body(&Relabelled::<5> {
            fields: &record.0,
            profile: Profile::RepositoryPrincipalKindV1,
            witness: Some(witness),
        })
        .unwrap(),
        encode_body(&Relabelled::<6> {
            fields: &record.0,
            profile: Profile::RepositoryPrincipalKindV1,
            witness: None,
        })
        .unwrap(),
        encode_body(&Relabelled::<7> {
            fields: &record.0,
            profile: Profile::RepositoryPrincipalKindV1,
            witness: Some(witness),
        })
        .unwrap(),
    ] {
        assert!(PolicyDecisionRecord::decode(&frame, DecodeLimits::DEFAULT).is_err());
    }
    // Every witness field participates in the enclosing RCR's original
    // principal snapshot, even when policy truth and the agent ID agree.
    for field in 0..7 {
        let changed = AgentAuthentication::try_new(
            witness.agent(),
            if field == 0 {
                PrincipalId::from_bytes([0x45; 16])
            } else {
                witness.sponsor()
            },
            if field == 1 {
                SponsorKind::Service
            } else {
                witness.sponsor_kind()
            },
            if field == 2 {
                AgentCredentialId::try_new([0x56; 32]).unwrap()
            } else {
                witness.credential_id()
            },
            if field == 3 {
                fgit_codec::harness::digest_of(8)
            } else {
                witness.grant_root()
            },
            if field == 4 {
                [0x67; 32]
            } else {
                *witness.run_commitment()
            },
            if field == 5 {
                101
            } else {
                witness.authenticated_at()
            },
            if field == 6 {
                201
            } else {
                witness.expires_at()
            },
        )
        .unwrap();
        let changed_record = PrincipalKindPolicyDecisionEvidence::evaluate(
            bodies.policy_decision().base().clone(),
            &context,
            &basis,
            &current,
            RootLayoutVersion::LegacyWholeBody,
            &fold,
            Vec::new(),
            selected.clone(),
            RefPolicyPublication::Direct,
            changed,
        )
        .unwrap();
        changed_record.replay().unwrap();
        assert_eq!(
            with_policy(
                &bodies,
                PolicyDecisionRecord::PrincipalKindActivated(Box::new(changed_record))
            )
            .verify_decision(&context, &basis, &request, &fold),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
    let other_agent = AgentAuthentication::try_new(
        PrincipalId::from_bytes([0x77; 16]),
        witness.sponsor(),
        witness.sponsor_kind(),
        witness.credential_id(),
        witness.grant_root(),
        *witness.run_commitment(),
        witness.authenticated_at(),
        witness.expires_at(),
    )
    .unwrap();
    let frame = encode_body(&Relabelled::<6> {
        fields: &record.0,
        profile: Profile::RepositoryPrincipalKindV1,
        witness: Some(other_agent),
    })
    .unwrap();
    assert!(PolicyDecisionRecord::decode(&frame, DecodeLimits::DEFAULT).is_err());

    let old_policy = fgit_forge::event::protection::compile_ref_policy("policy p { rule r { when actor.authentication >= single_factor then allow } default deny \"credential\" }").unwrap();
    let historical = AgentAuthenticationPolicyDecisionEvidence::evaluate(
        bodies.policy_decision().base().clone(),
        &context,
        &basis,
        &current,
        RootLayoutVersion::LegacyWholeBody,
        &fold,
        Vec::new(),
        old_policy,
        RefPolicyPublication::Direct,
        witness,
    )
    .unwrap();
    let upgraded = encode_body(&Relabelled::<6> {
        fields: &historical.0,
        profile: Profile::RepositoryAuthenticationV1,
        witness: Some(witness),
    })
    .unwrap();
    assert!(PolicyDecisionRecord::decode(&upgraded, DecodeLimits::DEFAULT).is_err());
}
