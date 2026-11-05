//! Live pre-dispatch recovery uses the same preparation and final dispatch
//! boundary as the public native consumer, with deterministic cancellation
//! between them. No test reconstructs validated custody from retry inputs.

use super::*;

fn request(node: &OneNode) -> NodeRequestContext {
    node.command_request_context(Some(
        crate::GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap(),
    ))
}

fn retain_cancelled<A: GitHashAlgorithm>(
    node: &OneNode,
    broker: &mut CurrentAuthorityRevocationCheckedEffectBroker,
    clock: &TrustedLocalAgentPublicationClock<'_>,
    input: TrustedLocalAgentPublicationInput<'_, A>,
) -> UndispatchedNativeAgentPublication {
    let request = request(node);
    let prepared = node
        .runtime()
        .block_on(
            node.prepare_agent_ref_transaction_trusted_local_in(&request, broker, clock, input),
        )
        .unwrap();
    let PreparedNativeAgentPublication::Ready(publication) = prepared else {
        panic!("new preparation must retain real custody before dispatch");
    };
    assert_eq!(broker.records().len(), 1);
    assert_eq!(broker.dispatch_authorizations().len(), 1);
    request.cancel();
    let error = node
        .runtime()
        .block_on(node.dispatch_agent_ref_transaction_in(&request, clock, publication))
        .unwrap_err();
    let NativeAgentPublicationError::Started {
        publication,
        reason,
    } = error
    else {
        panic!("post-start cancellation must retain the undispatched owner");
    };
    assert!(matches!(
        reason,
        NativeAgentPublicationRefusal::CancelledOrExpired
    ));
    *publication
}

fn retained_error(
    result: Result<NativeAgentPublicationResult, NativeAgentPublicationError>,
    reason_contains: &str,
) -> UndispatchedNativeAgentPublication {
    let NativeAgentPublicationError::Started {
        publication,
        reason,
    } = result.unwrap_err()
    else {
        panic!("refusal must return the exact undispatched custody");
    };
    assert!(format!("{reason}").contains(reason_contains), "{reason}");
    *publication
}

#[test]
fn cancelled_before_admission_resumes_without_inputs_or_another_resource_charge() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, Format::Sha256, true);
    let branch = RefName::try_new(b"refs/heads/agent/resumed").unwrap();
    let change = prepared_creation::<Sha256>(&node, &source, branch.as_bytes());
    let approved = approval(&change, b"resume-original-creation");
    let chain = chain(10_000, true);
    let mut broker = broker(&node, &change, &scratch.journal("journal"));
    let clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    let publication = retain_cancelled(
        &node,
        &mut broker,
        &clock,
        input(&change, &approved, &chain),
    );
    let binding = publication.binding().clone();
    let before = broker.records()[0].clone();
    assert_eq!(before.budget_reserved, before.budget_consumed);
    assert_ne!(before.budget_consumed, ResourceVector::ZERO);
    for object in change.export.objects() {
        assert!(publication.staging.contains(object.oid().erase()));
        assert!(node.read_git_object(object.oid().erase()).is_err());
    }
    // The live owner contains every byte/proof needed for the sole dispatch;
    // callers cannot supply replacement transport, export, approval or key.
    drop(change);
    drop(approved);
    let result = node
        .runtime()
        .block_on(node.resume_undispatched_agent_ref_transaction_in(
            &request(&node),
            &mut broker,
            &clock,
            publication,
            &chain,
        ))
        .unwrap();
    let NativeAgentPublicationResult::Submitted(result) = result else {
        panic!("fresh authorized original admission");
    };
    let admission = result.admission.unwrap();
    assert_eq!(admission.session.tx_ids, [binding.tx_id()]);
    assert!(matches!(
        admission.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let RefTransactionResolution::Decided(settled) = result.responsibility.unwrap() else {
        panic!("original responsibility must settle");
    };
    assert_eq!(settled.observation().binding(), &binding);
    let records = broker.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].budget_reserved, before.budget_reserved);
    assert_eq!(records[0].budget_consumed, before.budget_consumed);
    assert_eq!(broker.authorizations().len(), 1);
    assert_eq!(broker.dispatch_authorizations().len(), 2);
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request(&node)))
        .unwrap();
    assert_eq!(selected.snapshot().refs[&reference()], source.commit);
    assert!(selected.snapshot().refs.contains_key(&branch));
    assert!(broker.close().is_quiescent());
    drop(clock);
    node.shutdown().unwrap();
}

#[test]
fn resume_requires_original_clock_broker_chain_and_a_bounded_new_deadline() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, Format::Sha1, true);
    let change = prepared::<Sha1>(&node, &source, reference().as_bytes(), false);
    let approved = approval(&change, b"resume-gates");
    let chain = chain(10_000, true);
    let mut broker = broker(&node, &change, &scratch.journal("journal"));
    let clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    let mut publication = retain_cancelled(
        &node,
        &mut broker,
        &clock,
        input(&change, &approved, &chain),
    );
    let before = broker.records()[0].clone();
    let changed_clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    publication = retained_error(
        node.runtime()
            .block_on(node.resume_undispatched_agent_ref_transaction_in(
                &request(&node),
                &mut broker,
                &changed_clock,
                publication,
                &chain,
            )),
        "Clock",
    );
    drop(changed_clock);
    let mut other_broker = self::broker(&node, &change, &scratch.journal("other-journal"));
    publication = retained_error(
        node.runtime()
            .block_on(node.resume_undispatched_agent_ref_transaction_in(
                &request(&node),
                &mut other_broker,
                &clock,
                publication,
                &chain,
            )),
        "Binding",
    );
    assert!(other_broker.records().is_empty());
    assert!(other_broker.close().is_quiescent());
    let prepare_only = self::chain(10_000, false);
    publication = retained_error(
        node.runtime()
            .block_on(node.resume_undispatched_agent_ref_transaction_in(
                &request(&node),
                &mut broker,
                &clock,
                publication,
                &prepare_only,
            )),
        "FreshAuthorization",
    );
    let long_request = node.command_request_context(Some(
        crate::GitDaemonSessionTimeout::try_new(Duration::from_secs(20_000)).unwrap(),
    ));
    publication = retained_error(
        node.runtime()
            .block_on(node.resume_undispatched_agent_ref_transaction_in(
                &long_request,
                &mut broker,
                &clock,
                publication,
                &chain,
            )),
        "AuthorizationDeadlineUnbound",
    );
    assert_eq!(broker.records(), [before]);
    assert_eq!(
        node.runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt(),
        &change.original_read,
    );
    let result = node
        .runtime()
        .block_on(node.resume_undispatched_agent_ref_transaction_in(
            &request(&node),
            &mut broker,
            &clock,
            publication,
            &chain,
        ))
        .unwrap();
    let NativeAgentPublicationResult::Submitted(result) = result else {
        panic!("the original owner remains usable after refused substitutions");
    };
    assert!(matches!(
        result.admission.unwrap().commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    assert!(matches!(
        result.responsibility.unwrap(),
        RefTransactionResolution::Decided(_)
    ));
    assert!(broker.close().is_quiescent());
    drop(clock);
    node.shutdown().unwrap();
}

#[test]
fn moved_basis_refuses_resume_but_original_terminal_is_reconciled_before_authorization() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, Format::Sha1, true);
    let change = prepared::<Sha1>(&node, &source, reference().as_bytes(), false);
    let key = b"resume-original-terminal";
    let approved = approval(&change, key);
    let chain = chain(10_000, true);
    let mut broker = broker(&node, &change, &scratch.journal("journal"));
    let clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    let publication = retain_cancelled(
        &node,
        &mut broker,
        &clock,
        input(&change, &approved, &chain),
    );
    let binding = publication.binding().clone();
    let before = broker.records()[0].clone();
    source_on_branch(
        &node,
        &RefName::try_new(b"refs/heads/unrelated").unwrap(),
        b"advance-resume-basis",
        b"diff --git a/lib.rs b/lib.rs\nnew file mode 100644\n--- /dev/null\n+++ b/lib.rs\n@@ -0,0 +1 @@\n+fn unrelated() {}\n",
    );
    let publication = retained_error(
        node.runtime()
            .block_on(node.resume_undispatched_agent_ref_transaction_in(
                &request(&node),
                &mut broker,
                &clock,
                publication,
                &chain,
            )),
        "prepared authority basis moved",
    );
    assert_eq!(broker.records(), [before]);
    assert_eq!(broker.dispatch_authorizations().len(), 1);
    // An independent trusted operator completes the exact original request via
    // ordinary admission. A canonical terminal now exists despite the obsolete
    // prepared basis; observing it must neither dispatch nor reauthorize.
    let admitted = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &request(&node),
            OWNER,
            key,
            &reference(),
            source.commit,
            fgit_crypto::git_object_id(Format::Sha1, GitObjectKind::Commit, &change.body),
            &change.bundle,
        ))
        .unwrap();
    assert_eq!(admitted.session.tx_ids, [binding.tx_id()]);
    assert!(matches!(
        admitted.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let terminal_head = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    let prepare_only = self::chain(10_000, false);
    let result = node
        .runtime()
        .block_on(node.resume_undispatched_agent_ref_transaction_in(
            &request(&node),
            &mut broker,
            &clock,
            publication,
            &prepare_only,
        ))
        .unwrap();
    let NativeAgentPublicationResult::Reconciled(settled) = result else {
        panic!("terminal recovery precedes fresh authorization");
    };
    assert_eq!(settled.observation().binding(), &binding);
    assert_eq!(
        settled.observation().terminal(),
        &admitted.commands[0].terminal
    );
    assert_eq!(broker.dispatch_authorizations().len(), 1);
    assert_eq!(
        node.runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt(),
        terminal_head.receipt(),
    );
    assert!(broker.close().is_quiescent());
    drop(clock);
    node.shutdown().unwrap();
}
