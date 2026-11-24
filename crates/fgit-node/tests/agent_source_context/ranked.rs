use super::*;

fn selected<C: Fn() -> LogicalTime + Sync>(
    node: &OneNode,
    run: &IntentRun,
    query: &InitialQuery,
    control: ContextControl,
    context_limits: ContextLimits,
    selection: AgentContextSelection,
    now: &C,
) -> Result<AgentSourceContext, AgentContextReadError> {
    node.runtime()
        .block_on(node.retrieve_agent_context_selected_local_in(
            &node.outbox_delivery_context(),
            AgentContextRead {
                run,
                authorization: &SourceReadContext::trusted_local_native(node),
                reference: &reference(),
                query,
                checkpoints: &Checkpoints::default(),
                retrieval_limits: InitialLimits::default(),
                context_limits,
                control,
            },
            selection,
            now,
        ))
}

#[test]
fn weighted_agent_context_selects_channel_agreement_with_exact_native_lineage_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, commit) = fixture_with_text(&root, format, root.config(format), b"nested\n");
        build_index(&node);
        let before = generation(&node);
        let run = run(&node, scope());
        let query = InitialQuery::new(&[b"nested".to_vec()], &[]).unwrap();
        let limits = ContextLimits {
            max_files: 1,
            ..Default::default()
        };
        let raw = invoke(&node, &run, &query, control(scope()), limits, &|| {
            LogicalTime::new(41)
        })
        .unwrap();
        let explicit_raw = selected(
            &node,
            &run,
            &query,
            control(scope()),
            limits,
            AgentContextSelection::RawPathPrefix,
            &|| LogicalTime::new(41),
        )
        .unwrap();
        assert_eq!(raw.packet(), explicit_raw.packet());
        assert_eq!(raw.context().files(), explicit_raw.context().files());
        assert!(raw.ranking().is_none());
        assert_eq!(raw.context().files()[0].path(), b"alpha.txt");

        let all = invoke(
            &node,
            &run,
            &query,
            control(scope()),
            Default::default(),
            &|| LogicalTime::new(41),
        )
        .unwrap();
        let ranked = selected(
            &node,
            &run,
            &query,
            control(scope()),
            limits,
            AgentContextSelection::WeightedRrf,
            &|| LogicalTime::new(41),
        )
        .unwrap();
        assert_eq!(ranked.context().retrieval().source().commit, commit);
        assert!(!ranked.context().complete());
        assert_eq!(ranked.context().candidate_files(), 2);
        assert_eq!(ranked.context().files().len(), 1);
        let file = &ranked.context().files()[0];
        assert_eq!(file.path(), b"dir/nested.txt");
        // Selection changes neither original anchors nor their authorization
        // labels, exact native bytes, or the run's authenticated authority.
        assert_eq!(
            file,
            all.context()
                .files()
                .iter()
                .find(|file| file.path() == b"dir/nested.txt")
                .unwrap()
        );
        assert_eq!(
            ranked.packet().authority_read_receipt(),
            run.authority_read_receipt().unwrap()
        );
        assert_eq!(ranked.packet().control(), &control(scope()));
        assert_eq!(
            ranked.packet().sources()[0].untrusted_bytes(),
            b"needle in nested\n"
        );
        let receipt = ranked.ranking().unwrap();
        assert_eq!(receipt.candidate_files(), 2);
        assert_eq!(receipt.selected().len(), 1);
        let winner = &receipt.selected()[0];
        assert_eq!(winner.path(), file.path());
        assert_eq!(winner.blob(), file.blob());
        assert_eq!(winner.score_q16(), 65_536 / 62 + 65_536 / 61);
        assert_eq!(winner.contributions().len(), 2);
        assert_eq!(winner.contributions()[0].document_rank(), 2);
        assert_eq!(winner.contributions()[1].document_rank(), 1);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn weighted_context_obeys_run_scope_expiry_source_bytes_and_final_cancellation() {
    let root = Scratch::new();
    let (node, _) = fixture_with_text(
        &root,
        GitHashAlgorithm::Sha256,
        root.config(GitHashAlgorithm::Sha256),
        b"nested\n",
    );
    let query = InitialQuery::new(&[b"nested".to_vec()], &[]).unwrap();
    let narrow_scope = ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]);
    let narrow = run(&node, narrow_scope);
    // Refuse the missing operation before even looking for a missing index.
    assert!(matches!(
        selected(
            &node,
            &narrow,
            &query,
            control(narrow_scope),
            Default::default(),
            AgentContextSelection::WeightedRrf,
            &|| LogicalTime::new(41)
        ),
        Err(AgentContextReadError::Binding(
            AgentContextRefusal::ReadOperationOutsideRun
        ))
    ));
    build_index(&node);
    let run = run(&node, scope());
    let limits = ContextLimits {
        max_files: 1,
        max_source_bytes: b"needle in nested\n".len(),
        ..Default::default()
    };
    assert!(
        selected(
            &node,
            &run,
            &query,
            control(scope()),
            limits,
            AgentContextSelection::WeightedRrf,
            &|| LogicalTime::new(41)
        )
        .is_ok()
    );
    // A ranked winner that exceeds the source envelope cannot be silently
    // replaced with the smaller alphabetically earlier document.
    assert!(
        selected(
            &node,
            &run,
            &query,
            control(scope()),
            ContextLimits {
                max_source_bytes: 7,
                ..limits
            },
            AgentContextSelection::WeightedRrf,
            &|| LogicalTime::new(41)
        )
        .is_err()
    );
    assert!(matches!(
        selected(
            &node,
            &run,
            &query,
            control(scope()),
            limits,
            AgentContextSelection::WeightedRrf,
            &|| LogicalTime::new(100)
        ),
        Err(AgentContextReadError::RunExpired)
    ));
    let request = node.outbox_delivery_context();
    let calls = AtomicUsize::new(0);
    let clock = || {
        if calls.fetch_add(1, Ordering::Relaxed) == 3 {
            request.cancel();
        }
        LogicalTime::new(41)
    };
    let result = node
        .runtime()
        .block_on(node.retrieve_agent_context_selected_local_in(
            &request,
            AgentContextRead {
                run: &run,
                authorization: &SourceReadContext::trusted_local_native(&node),
                reference: &reference(),
                query: &query,
                checkpoints: &Checkpoints::default(),
                retrieval_limits: Default::default(),
                context_limits: limits,
                control: control(scope()),
            },
            AgentContextSelection::WeightedRrf,
            &clock,
        ));
    assert!(matches!(
        result,
        Err(AgentContextReadError::Retrieval(RetrievalError::Source(
            NodeWorkspaceRefusal::Cancelled { .. }
        )))
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 4);
    node.shutdown().unwrap();
}
