//! Real MCP construction, independent candidate approval and atomic queue
//! publication over native divergent histories. Neither preparation nor
//! inspection can stage objects or claim authority to land the result.
use super::super::super::super::queues as queue_tools;
use super::super::queue as adapter;
use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::ExpectedVersion;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_node::LoopbackReceiveSession;
use fgit_types::DecisionOutcome;

fn protect(f: &mut Fixture) {
    let node = &f.backend().node;
    let request = node.request_context();
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: f.subject.policy_epoch,
        protection: ReviewProtection {
            ref_policy: None,
            administrators: vec![actor(1)],
            branches: vec![ProtectedBranch {
                path_reviews: Vec::new(),
                required_candidate_checks: Vec::new(),
                require_merge_queue: true,
                required_approvals: 1,
                required_checks: Vec::new(),
                name: f.subject.target_ref.clone(),
                reviewers: vec![actor(2)],
            }],
        },
    };
    let session = LoopbackReceiveSession::authenticated(
        actor(1),
        IdempotencyKey::new(b"protect-mcp-queue".to_vec()).unwrap(),
    );
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

fn enqueue(f: &mut Fixture) {
    let mut writer = f.options();
    writer.queues.write = true;
    writer.principal = Some(actor(1));
    f.reopen(writer);
    let args = fields([
        ("number", text("7")),
        ("expected_version", text("0")),
        ("idempotency_key", text("enqueue-native-candidate")),
        (
            "expected_incarnation",
            text(f.backend().node.repository_incarnation_id().to_string()),
        ),
        (
            "object_format",
            text(f.subject.source_tip.algorithm().as_str()),
        ),
        (
            "target_reference_hex",
            text(hex(f.subject.target_ref.as_bytes())),
        ),
        (
            "source_reference_hex",
            text(hex(f.subject.source_ref.as_bytes())),
        ),
        ("expected_source", text(raw_oid(f.subject.source_tip))),
        ("expected_target", text(raw_oid(f.subject.target_tip))),
        (
            "pull_request",
            text(f.subject.pull_request.get().to_string()),
        ),
        (
            "expected_pull_request_version",
            text(f.subject.pull_request_version.get().to_string()),
        ),
    ]);
    let response = f.protocol_call(queue_tools::ENQUEUE, args);
    assert_eq!(content(&response)["outcome"].text(), Some("committed"));
    let mut reader = f.options();
    reader.queues.write = false;
    reader.queues.read = true;
    reader.principal = None;
    f.reopen(reader);
}

fn prepare_args(f: &Fixture) -> Object {
    let mut args = f.prepare_args();
    args.insert("operation".into(), text(QUEUE_PREPARE));
    args.insert("queue_number".into(), text("7"));
    args.insert("expected_queue_version".into(), text("1"));
    args
}

#[test]
fn exact_queue_preparation_inspection_review_and_landing_cross_independent_mcp_grants() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, false);
        protect(&mut f);
        enqueue(&mut f);
        let before = f.head();
        let args = prepare_args(&f);
        let response = f.protocol_call(NAME, args.clone());
        let prepared = content(&response);
        assert_eq!(prepared["state"].text(), Some("clean"));
        assert_eq!(prepared["queue_number"].text(), Some("7"));
        assert_eq!(prepared["expected_queue_version"].text(), Some("1"));
        assert_eq!(
            prepared["snapshot_token"].text(),
            Some(head_token(before.0).as_str())
        );
        assert_eq!(
            prepared["publication_tool"].text(),
            Some(queue_tools::LAND_CANDIDATE)
        );
        assert_eq!(prepared["approval_granted"], Value::Bool(false));
        assert_eq!(prepared["repository_changed"], Value::Bool(false));
        assert_eq!(
            prepared["parents"],
            Value::Array(vec![
                text(raw_oid(f.subject.target_tip)),
                text(raw_oid(f.subject.source_tip)),
            ])
        );
        let review = prepared["candidate_arguments"].object().unwrap().clone();
        let inspection = prepared["inspection_arguments"].object().unwrap().clone();
        let mut landing = prepared["publication_arguments"].object().unwrap().clone();
        let (subject, candidate) = reviews::subject(&review, format).unwrap();
        assert_eq!(subject, f.subject);
        assert!(f.backend().node.read_git_object(candidate.commit).is_err());
        assert!(!landing.contains_key("idempotency_key"));
        assert!(!landing.contains_key("required_reviewers"));
        assert_eq!(landing["number"].text(), Some("7"));
        assert_eq!(landing["pull_request"].text(), Some("1"));
        assert_eq!(f.call(NAME, &args).unwrap().object().unwrap(), prepared);
        let inspection_response = f.protocol_call(NAME, inspection);
        let inspected = content(&inspection_response);
        assert_eq!(inspected["candidate_commit"], prepared["candidate_commit"]);
        assert_eq!(
            inspected["candidate_arguments"],
            prepared["candidate_arguments"]
        );
        assert_eq!(
            inspected["review"].object().unwrap()["complete"],
            Value::Bool(true)
        );
        assert_eq!(f.head(), before);
        assert_eq!(
            f.call(queue_tools::LAND_CANDIDATE, &landing)
                .unwrap_err()
                .code,
            "tool_not_granted"
        );

        let mut merger = f.options();
        merger.source = false;
        merger.pulls = false;
        merger.queues.read = false;
        merger.queues.land = true;
        merger.principal = Some(actor(3));
        f.reopen(merger.clone());
        landing.insert("idempotency_key".into(), text("candidate-without-review"));
        let refusal = f.call(queue_tools::LAND_CANDIDATE, &landing).unwrap();
        assert_eq!(refusal.object().unwrap()["outcome"].text(), Some("refused"));
        assert_eq!(
            refusal.object().unwrap()["refusal_code"].text(),
            Some("EvidenceMissing")
        );
        let refused_args = landing.clone();

        let mut reviewer = merger.clone();
        reviewer.queues.land = false;
        reviewer.writes.reviews = true;
        reviewer.principal = Some(actor(2));
        f.reopen(reviewer);
        let mut approval = review;
        approval.insert("idempotency_key".into(), text("approve-queue-candidate"));
        approval.insert("review_version".into(), text("0"));
        approval.insert("decision".into(), text("approve"));
        let approval_response = f.protocol_call(reviews::NAME, approval);
        assert_eq!(
            content(&approval_response)["outcome"].text(),
            Some("committed")
        );

        f.reopen(merger.clone());
        assert_eq!(
            f.call(queue_tools::LAND_CANDIDATE, &refused_args).unwrap(),
            refusal
        );
        landing.insert(
            "idempotency_key".into(),
            text("land-reviewed-queue-candidate"),
        );
        let publication_response = f.protocol_call(queue_tools::LAND_CANDIDATE, landing.clone());
        let published = content(&publication_response);
        assert_eq!(published["outcome"].text(), Some("committed"));
        assert_eq!(published["action"].text(), Some("land-candidate"));
        assert_eq!(published["refs_changed"], Value::Bool(true));
        let node = &f.backend().node;
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            selected.snapshot().refs[&subject.target_ref],
            candidate.commit
        );
        assert_eq!(
            selected.snapshot().refs[&subject.source_ref],
            subject.source_tip
        );
        let request = node.request_context();
        let queue = node
            .runtime()
            .block_on(node.read_queue_in(
                &request,
                &Default::default(),
                fgit_forge::QueueNumber::try_new(7).unwrap(),
                None,
            ))
            .unwrap()
            .queue
            .unwrap();
        assert_eq!(queue.version.get(), 3);
        assert!(queue.entries.is_empty());
        assert!(queue.active_batch.is_none());
        let after = f.head();
        let mut recovery = landing.clone();
        recovery.remove("bundle_hex_chunks");
        f.reopen(merger);
        assert_eq!(
            f.call(queue_tools::LAND_CANDIDATE, &recovery)
                .unwrap()
                .object()
                .unwrap(),
            published
        );
        assert_eq!(f.head(), after);
    }
}

#[test]
fn queue_reads_precede_parsing_and_stale_exact_subjects_never_become_prepared_candidates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, false);
        enqueue(&mut f);
        let before = f.head();
        let args = prepare_args(&f);
        for (field, value) in [
            ("queue_number", text("8")),
            ("expected_queue_version", text("2")),
            ("number", text("2")),
            ("expected_version", text("2")),
            ("expected_source", text(raw_oid(f.base))),
            ("expected_target", text(raw_oid(f.base))),
            ("policy_epoch", text("2")),
            ("expected_head", text(head_token(f.genesis))),
            ("max_output_bytes", json::number(1)),
        ] {
            let mut stale = args.clone();
            stale.insert(field.into(), value);
            assert!(f.call(NAME, &stale).is_err(), "{field}");
            assert_eq!(f.head(), before);
        }
        for mask in 0..7 {
            let mut options = f.options();
            options.source = mask & 1 != 0;
            options.pulls = mask & 2 != 0;
            options.queues.read = mask & 4 != 0;
            options.queues.write = true;
            options.queues.land = true;
            options.writes.merges = true;
            options.writes.reviews = true;
            options.principal = Some(actor(3));
            f.reopen(options);
            let hostile = fields([("operation", text(QUEUE_PREPARE))]);
            assert_eq!(f.call(NAME, &hostile).unwrap_err().code, "tool_not_granted");
            assert_eq!(
                adapter::call(f.backend(), &hostile).unwrap_err().code,
                "tool_not_granted"
            );
            assert_eq!(f.head(), before);
        }
    }
}

#[test]
fn conflicting_queue_heads_have_no_inspection_review_or_landing_template() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, true);
        enqueue(&mut f);
        let before = f.head();
        let args = prepare_args(&f);
        let value = f.call(NAME, &args).unwrap();
        let result = value.object().unwrap();
        assert_eq!(result["state"].text(), Some("conflicted"));
        assert_eq!(result["candidate_available"], Value::Bool(false));
        for field in [
            "candidate_arguments",
            "inspection_arguments",
            "publication_arguments",
            "candidate_commit",
            "parents",
        ] {
            assert_eq!(result[field], Value::Null, "{field}");
        }
        assert_eq!(f.head(), before);
    }
}
