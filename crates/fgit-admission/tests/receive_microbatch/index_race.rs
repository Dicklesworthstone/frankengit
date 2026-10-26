//! A racing publication may make the accelerator newer than the cumulative
//! snapshot. Only a stable head can turn a disagreement into corruption.

use super::*;

#[test]
fn publication_during_an_accelerator_probe_replans_instead_of_reporting_corruption() {
    let format = GitObjectFormat::Sha256;
    let context = context(format, b"index-read-race");
    let input = receive(
        format,
        (0..3)
            .map(|index| command(format, &format!("refs/heads/index-race-{index}"), 0, 1))
            .collect(),
        false,
    );
    let (reference, _, reference_projection) = setup(&context, &[], None);
    let expected = admit_validated_receive(
        &reference.inner,
        &context,
        &input,
        AdmissionLimits::default(),
        &Sequential(&reference_projection),
    )
    .unwrap();
    let (authority, staging, projection) = setup(&context, &[], None);
    let target = fgit_authority::outcome_key(
        context.tenant_id,
        context.repository_id,
        expected.session.tx_ids[0],
    )
    .unwrap();
    *authority.index_rival.lock().unwrap() = Some((
        target,
        Rival {
            context: context.clone(),
            receive: input.clone(),
            projection: projection.clone(),
            staging: staging.clone(),
            interrupt_after_first: true,
        },
    ));

    // The first cumulative scan sees genesis. Its first index read instead
    // sees the rival's real terminal outcome. Removing the post-probe token
    // check turns this legitimate race into AcceleratorConflict.
    let result = run(&authority, &context, &input, &projection);
    assert!(authority.index_rival.lock().unwrap().is_none());
    assert_eq!(result.session, expected.session);
    assert_eq!(codes(&result), vec![None; 3]);
    assert_eq!(
        authority.publications.load(Ordering::SeqCst),
        1,
        "the obsolete preflight must be retried before attempting its CAS"
    );
    assert_eq!(
        head(&authority.inner, &context)
            .latest_decision_sequence
            .unwrap()
            .get(),
        3
    );
    assert_eq!(
        head(&authority.inner, &context).generation.get(),
        HeadGeneration::FIRST.get() + 2
    );
    let publication = batch(&authority.inner, &context);
    assert_eq!(publication.decisions.len(), 2);
    assert_eq!(
        publication
            .decisions
            .iter()
            .map(|decision| decision.tx_id)
            .collect::<Vec<_>>(),
        result.session.tx_ids[1..]
    );
    assert_eq!(refs(&authority.inner, &staging, &context).refs().len(), 3);
    verify_outcomes(&authority.inner, &context, &result);
    let published = authority.inner.read_head(&context.head_key).unwrap();
    assert_eq!(run(&authority, &context, &input, &projection), result);
    assert_eq!(
        authority.inner.read_head(&context.head_key).unwrap(),
        published
    );
    assert_eq!(authority.publications.load(Ordering::SeqCst), 1);
}
