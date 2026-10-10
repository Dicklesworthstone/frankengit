//! Real MCP inspection, independent exact approval and protected no-new-commit
//! publication. Both Git formats and a multi-commit source history are native.
use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::ExpectedVersion;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_node::LoopbackReceiveSession;
use fgit_types::DecisionOutcome;

fn source_candidate(f: &Fixture) -> (CandidateBinding, Vec<u8>) {
    // Retain the production-generated native pack, but advertise the exact
    // source-tip candidate on its PR target and bind the selected target base.
    let pack_start = f
        .source_bundle
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .unwrap()
        + 2;
    let mut bundle = format!(
        "# v3 git bundle\n@object-format={}\n-{} target\n{} {}\n\n",
        f.subject.source_tip.algorithm().as_str(),
        f.subject.target_tip,
        f.subject.source_tip,
        std::str::from_utf8(f.subject.target_ref.as_bytes()).unwrap(),
    )
    .into_bytes();
    bundle.extend_from_slice(&f.source_bundle[pack_start..]);
    (
        CandidateBinding {
            merge_base: f.subject.target_tip,
            commit: f.subject.source_tip,
        },
        bundle,
    )
}

fn protect(f: &mut Fixture) {
    let node = &f.backend().node;
    let request = node.request_context();
    let session = LoopbackReceiveSession::authenticated(
        actor(1),
        IdempotencyKey::new(b"protect-mcp-ff".to_vec()).unwrap(),
    );
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: f.subject.policy_epoch,
        protection: ReviewProtection {
            administrators: vec![actor(1)],
            branches: vec![ProtectedBranch {
                name: f.subject.target_ref.clone(),
                reviewers: vec![actor(2)],
            }],
        },
    };
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &request,
            &session,
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    f.subject.policy_epoch = f.subject.policy_epoch.next().unwrap();
}

#[test]
fn exact_source_inspection_approval_and_protected_fast_forward_cross_real_mcp_grants() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::fast_forward(format);
        protect(&mut f);
        let before = f.head();
        let (candidate, bundle) = source_candidate(&f);
        let arguments = candidate_arguments(&f.subject, candidate, &bundle).unwrap();
        let arguments = arguments.object().unwrap();
        let mut inspect = arguments.clone();
        inspect.insert("operation".into(), text(INSPECT));
        inspect.insert("expected_head".into(), text(head_token(before.0)));
        inspect.insert(
            "expected_bundle_sha256".into(),
            text(hex(&fgit_crypto::sha256_digest(&bundle))),
        );
        let response = f.protocol_call(NAME, inspect.clone());
        let inspected = content(&response);
        assert_eq!(
            inspected["candidate_arguments"].object().unwrap(),
            arguments
        );
        assert_eq!(
            inspected["publication_tool"].text(),
            Some("frankengit_pull_fast_forward")
        );
        let Value::Array(parents) = &inspected["parents"] else {
            unreachable!()
        };
        assert_eq!(parents.len(), 1);
        assert_ne!(
            parents[0].text(),
            Some(raw_oid(f.subject.target_tip).as_str())
        );
        assert_eq!(
            inspected["candidate_commit"].text(),
            Some(raw_oid(f.subject.source_tip).as_str())
        );
        let review = inspected["review"].object().unwrap();
        assert_eq!(
            review["requested_before"].text(),
            Some(raw_oid(f.subject.target_tip).as_str())
        );
        assert_eq!(review["requested_after"], inspected["candidate_commit"]);
        let Value::Array(entries) = &review["entries"] else {
            unreachable!()
        };
        assert_eq!(entries.len(), 2);
        assert_eq!(f.head(), before, "inspection does not approve or publish");

        let mut approval = arguments.clone();
        approval.insert("idempotency_key".into(), text("exact-ff-vote"));
        approval.insert("review_version".into(), text("0"));
        approval.insert("decision".into(), text("approve"));
        assert_eq!(
            f.call(reviews::NAME, &approval).unwrap_err().code,
            "tool_not_granted"
        );
        let mut publication = subject_fields(&f.subject);
        publication.remove("policy_epoch");
        publication.insert("idempotency_key".into(), text("missing-ff-review"));
        let mut merger = f.options();
        merger.source = false;
        merger.pulls = false;
        merger.writes.merges = true;
        merger.principal = Some(actor(3));
        f.reopen(merger.clone());
        let refused = f
            .call("frankengit_pull_fast_forward", &publication)
            .unwrap();
        assert_eq!(refused.object().unwrap()["outcome"].text(), Some("refused"));
        let mut reviewer = merger.clone();
        reviewer.writes = Default::default();
        reviewer.writes.reviews = true;
        reviewer.principal = Some(actor(2));
        f.reopen(reviewer);
        let response = f.protocol_call(reviews::NAME, approval.clone());
        let approved = content(&response);
        assert_eq!(approved["outcome"].text(), Some("committed"));
        let after_review = f.head();
        assert_eq!(
            f.call(reviews::NAME, &approval).unwrap().object().unwrap(),
            approved
        );
        assert_eq!(f.head(), after_review);

        f.reopen(merger.clone());
        assert_eq!(
            f.call("frankengit_pull_fast_forward", &publication)
                .unwrap(),
            refused
        );
        publication.insert("idempotency_key".into(), text("approved-ff"));
        let response = f.protocol_call("frankengit_pull_fast_forward", publication.clone());
        let published = content(&response);
        assert_eq!(published["outcome"].text(), Some("committed"));
        assert_eq!(published["creates_commit"], Value::Bool(false));
        let node = &f.backend().node;
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            selected.snapshot().refs[&f.subject.target_ref],
            f.subject.source_tip
        );
        assert_eq!(
            selected.snapshot().refs[&f.subject.source_ref],
            f.subject.source_tip
        );
        let after = f.head();
        f.reopen(merger);
        assert_eq!(
            f.call("frankengit_pull_fast_forward", &publication)
                .unwrap()
                .object()
                .unwrap(),
            published
        );
        assert_eq!(f.head(), after);
    }
}
