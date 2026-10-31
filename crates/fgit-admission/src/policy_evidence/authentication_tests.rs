use super::*;
use crate::evidence::DecisionEvidenceBodies;
use fgit_types::{GitHashAlgorithm, GitOidSha1, GitOidSha256};

const CREDENTIAL: &str = "policy release { rule credential { when actor.id == \"33333333333333333333333333333333\" and actor.authentication >= single_factor then allow } default deny \"verified credential required\" }";

fn setup(
    algorithm: GitHashAlgorithm,
) -> (
    AdmissionContext,
    PublicationBasis,
    CanonicalRefState,
    fgit_reference::intent::TransactionRequest,
    TransactionFoldReport,
) {
    let oid = match algorithm {
        GitHashAlgorithm::Sha1 => GitOid::Sha1(GitOidSha1::from_bytes([2; 20])),
        GitHashAlgorithm::Sha256 => GitOid::Sha256(GitOidSha256::from_bytes([2; 32])),
    };
    super::tests::folded(
        algorithm,
        RefName::try_new(b"refs/tags/release").unwrap(),
        RefName::try_new(b"refs/heads/main").unwrap(),
        None,
        Some(oid),
    )
}

#[test]
fn authenticated_receipts_replay_exact_snapshot_principal_and_recorded_transport() {
    let selected = fgit_forge::event::protection::compile_ref_policy(CREDENTIAL).unwrap();
    let alternative = fgit_forge::event::protection::compile_ref_policy("policy alternative { rule r { when actor.authentication >= single_factor then allow } default deny \"credential\" }").unwrap();
    for algorithm in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, basis, current, request, fold) = setup(algorithm);
        let mut roots = Vec::new();
        for authentication in [
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
            let PolicyDecisionRecord::AuthenticationActivated(record) = bodies.policy_decision()
            else {
                panic!("authentication profile")
            };
            assert_eq!(record.authentication(), authentication);
            assert_eq!(
                bodies.policy_decision().authentication(),
                Some(authentication)
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
                    &alternative
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
                4
            );
            let decoded = PolicyDecisionRecord::decode(&frame, DecodeLimits::DEFAULT).unwrap();
            assert_eq!(&decoded, bodies.policy_decision());
            assert_eq!(decoded.encode().unwrap(), frame);
            roots.push(decoded.root().unwrap());
            assert!(PolicyDecisionRecord::decode(&frame, DecodeLimits::MINIMAL).is_err());
            for length in [0, 1, frame.len() / 2, frame.len() - 1] {
                assert!(
                    PolicyDecisionRecord::decode(&frame[..length], DecodeLimits::DEFAULT).is_err()
                );
            }
            let mut suffix = frame;
            suffix.push(0);
            assert!(PolicyDecisionRecord::decode(&suffix, DecodeLimits::DEFAULT).is_err());
        }
        assert_ne!(
            roots[0], roots[1],
            "equal strength does not erase recorded provenance"
        );
    }
}

#[test]
fn explicit_operator_none_can_satisfy_negation_but_legacy_unknown_cannot() {
    let (context, basis, current, request, fold) = setup(GitHashAlgorithm::Sha1);
    for source in [
        "policy p { rule r { when actor.authentication == none then allow } default deny \"operator\" }",
        "policy p { rule r { when not actor.authentication >= single_factor then allow } default deny \"operator\" }",
    ] {
        let snapshot = fgit_forge::event::protection::compile_ref_policy(source).unwrap();
        let mut legacy = DecisionEvidenceBodies::derive(&context, &basis, &request, &fold).unwrap();
        assert_eq!(
            legacy.record_activated_policy(
                &context,
                &basis,
                &current,
                RootLayoutVersion::LegacyWholeBody,
                &fold,
                Vec::new(),
                snapshot.clone(),
                RefPolicyPublication::Direct
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
            let result = bodies.record_activated_policy(
                &context,
                &basis,
                &current,
                RootLayoutVersion::LegacyWholeBody,
                &fold,
                Vec::new(),
                snapshot.clone(),
                RefPolicyPublication::Direct,
            );
            if authentication == AdmissionAuthentication::OperatorAssertion {
                result.unwrap();
                bodies
                    .verify_decision(&context, &basis, &request, &fold)
                    .unwrap();
                let frame = bodies.policy_decision().encode().unwrap();
                PolicyDecisionRecord::decode(&frame, DecodeLimits::DEFAULT).unwrap();
            } else {
                assert_eq!(result, Err(RefusalCode::ProtectedRefTransitionDenied));
            }
        }
    }
}

struct Downgraded<'a, const MINOR: u16>(&'a AuthenticationPolicyDecisionEvidence);

impl<const MINOR: u16> CanonicalBody for Downgraded<'_, MINOR> {
    const DOMAIN: DomainTag = PolicyDecisionEvidence::DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = PolicyDecisionEvidence::SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = MINOR;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        // Drop the new provenance suffix as an attacker relabelling the old
        // shared shape would. The old profile must still reject the snapshot.
        self.0
            .0
            .write_fields(out, Profile::RepositoryAuthenticationV1)
    }

    fn read_payload(_: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Err(invalid("test.downgrade"))
    }
}

struct Altered<'a> {
    record: &'a AuthenticationPolicyDecisionEvidence,
    provenance: u64,
    trace: &'a str,
}

impl CanonicalBody for Altered<'_> {
    const DOMAIN: DomainTag = PolicyDecisionEvidence::DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = PolicyDecisionEvidence::SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 4;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_bytes(
            "policy_decision.references",
            &encode_body(self.record.references())?,
        )?;
        out.write_raw_byte(1); // the fixture is a direct ref publication
        out.write_internal_object_id(
            self.record
                .evaluation()
                .snapshot_id()
                .as_internal_object_id(),
        )?;
        out.write_bytes(
            "policy_decision.snapshot",
            &self.record.evaluation().snapshot().encode()?,
        )?;
        out.write_raw_byte(self.record.evaluation().decision().code_point());
        out.write_text("policy_decision.trace", self.trace)?;
        out.write_scalar(self.provenance);
        Ok(())
    }

    fn read_payload(_: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Err(invalid("test.altered"))
    }
}

#[test]
fn authentication_schema_refuses_downgrade_unknown_provenance_and_forged_trace() {
    let (context, basis, current, request, fold) = setup(GitHashAlgorithm::Sha256);
    let selected = fgit_forge::event::protection::compile_ref_policy(CREDENTIAL).unwrap();
    let mut bodies = DecisionEvidenceBodies::derive_with_authentication(
        &context,
        &basis,
        &request,
        &fold,
        AdmissionAuthentication::HttpToken,
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
            selected,
            RefPolicyPublication::Direct,
        )
        .unwrap();
    let PolicyDecisionRecord::AuthenticationActivated(record) = bodies.policy_decision() else {
        panic!("authentication profile")
    };
    assert!(
        encode_body(&record.0).is_err(),
        "schema1.2 cannot encode authentication"
    );
    for frame in [
        encode_body(&Downgraded::<2>(record)).unwrap(),
        encode_body(&Downgraded::<3>(record)).unwrap(),
    ] {
        assert!(PolicyDecisionRecord::decode(&frame, DecodeLimits::DEFAULT).is_err());
    }
    for provenance in [0, 4, u64::MAX] {
        let frame = encode_body(&Altered {
            record,
            provenance,
            trace: record.evaluation().trace(),
        })
        .unwrap();
        assert!(PolicyDecisionRecord::decode(&frame, DecodeLimits::DEFAULT).is_err());
    }
    let frame = encode_body(&Altered {
        record,
        provenance: AdmissionAuthentication::OperatorAssertion.code_point(),
        trace: record.evaluation().trace(),
    })
    .unwrap();
    assert!(
        PolicyDecisionRecord::decode(&frame, DecodeLimits::DEFAULT).is_err(),
        "claiming weaker auth cannot reuse an allowing trace"
    );
    let frame = encode_body(&Altered {
        record,
        provenance: AdmissionAuthentication::HttpToken.code_point(),
        trace: "policy release\ndecision allow\n",
    })
    .unwrap();
    assert!(PolicyDecisionRecord::decode(&frame, DecodeLimits::DEFAULT).is_err());
    let control = encode_body(&Altered {
        record,
        provenance: record.authentication().code_point(),
        trace: record.evaluation().trace(),
    })
    .unwrap();
    assert_eq!(control, bodies.policy_decision().encode().unwrap());
    PolicyDecisionRecord::decode(&control, DecodeLimits::DEFAULT).unwrap();
}
