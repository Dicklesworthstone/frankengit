#![forbid(unsafe_code)]

//! File-backed regression coverage for the installed projection identity.
//! These tests use sqlmodel's real FrankenSQLite driver. They retain
//! their private files on failure; they do not establish the wider FG-093c
//! crash, cancellation, resource, concurrency, or cross-target campaign.

use std::future::Future;
use std::num::NonZeroU16;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
use fgit_projection::identity::{BuildIdentity, IdentityAdvanceError};
use fgit_projection::session::flatten;
use fgit_projection::store::StoreReadError;
use fgit_projection::{
    AppliedDecisionPage, DecisionRecord, ProjectionError, ProjectionIdentity, ProjectionPosition,
    ProjectionSession, SchemaReconciliation, apply_batch, ensure_schema_generation,
    ensure_schema_generation_on, read_applied_page,
};
use sqlmodel_core::Connection;
use sqlmodel_frankensqlite::FrankenConnection;

type Session = ProjectionSession<FrankenConnection>;

fn identity(projection: u32, schema: u32, build: BuildIdentity) -> ProjectionIdentity {
    ProjectionIdentity::new(
        "generation-test-inc",
        "generation-test-head",
        7,
        projection,
        schema,
        build,
    )
}

fn record(seq: u64) -> DecisionRecord {
    DecisionRecord {
        seq: ProjectionPosition::new(seq),
        digest: format!("canonical-decision-{seq}"),
        source_incarnation: "generation-test-inc".to_owned(),
        authority_head: "generation-test-head".to_owned(),
        authority_head_generation: 7,
    }
}

fn database_path(label: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fgit-projection-{label}-{}-{timestamp}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::create_dir(&directory).expect("create private retained test directory");
    eprintln!("projection regression files: {}", directory.display());
    directory
        .join("projection.db")
        .to_str()
        .expect("test path UTF-8")
        .to_owned()
}

fn open(path: &str, identity: ProjectionIdentity) -> Result<Session, ProjectionError> {
    Ok(ProjectionSession::new(
        FrankenConnection::open_file(path).map_err(ProjectionError::Sql)?,
        identity,
    ))
}

fn run_case<F: Future<Output = Result<(), ProjectionError>>>(case: impl FnOnce(Cx) -> F) {
    let node = fgit_runtime::boot::RuntimeProfile::deterministic()
        .build()
        .expect("node");
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("runtime");
    let cx = node.request_cx(fgit_runtime::meter::BudgetClass::Request);
    runtime
        .block_on(case(cx))
        .expect("file-backed identity regression");
    assert!(
        runtime.shutdown_timeout(Duration::from_secs(5)),
        "runtime drains"
    );
}

fn assert_identity_refusal(error: ProjectionError) {
    assert!(
        matches!(
            error,
            ProjectionError::Identity(IdentityAdvanceError::BindingMismatch {
                field: "projection_identity",
                ..
            })
        ),
        "unexpected refusal: {error}"
    );
}

fn assert_missing_receipt(error: ProjectionError) {
    assert!(
        matches!(
            error,
            ProjectionError::Corrupt(StoreReadError::MissingColumn("projection_identity_receipt"))
        ),
        "unexpected missing-receipt result: {error}"
    );
}

async fn page(session: &Session, cx: &Cx) -> Result<AppliedDecisionPage, ProjectionError> {
    read_applied_page(
        session,
        cx,
        ProjectionPosition::new(1),
        ProjectionPosition::new(u64::MAX),
        NonZeroU16::new(3).expect("nonzero"),
    )
    .await
}

async fn pages(session: &Session, cx: &Cx) -> Result<Vec<AppliedDecisionPage>, ProjectionError> {
    let mut result = Vec::new();
    let mut start = ProjectionPosition::new(1);
    let mut end = ProjectionPosition::new(u64::MAX);
    loop {
        let current = read_applied_page(
            session,
            cx,
            start,
            end,
            NonZeroU16::new(3).expect("nonzero"),
        )
        .await?;
        let next = current.next_start;
        if let Some(watermark) = current.watermark {
            end = watermark;
        }
        result.push(current);
        let Some(next) = next else {
            return Ok(result);
        };
        assert!(next > start, "pagination must progress");
        start = next;
    }
}

#[test]
fn reopened_database_rejects_other_projection_generations_and_builds() {
    run_case(|cx| async move {
        let path = database_path("reopen");
        let admitted = identity(1, 1, BuildIdentity::current());
        let session = open(&path, admitted.clone())?;
        ensure_schema_generation(&session, &cx, 1).await?;
        apply_batch(&session, &cx, &[record(1), record(2)]).await?;
        session.close(&cx).await?;

        for substituted in [
            identity(2, 1, BuildIdentity::current()),
            identity(
                1,
                1,
                BuildIdentity {
                    crate_version: "different-build",
                    ..BuildIdentity::current()
                },
            ),
            identity(
                1,
                1,
                BuildIdentity {
                    toolchain: "other-toolchain",
                    ..BuildIdentity::current()
                },
            ),
        ] {
            // All watermark fields agree. Only the installed identity differs.
            let session = open(&path, substituted)?;
            assert_identity_refusal(
                page(&session, &cx)
                    .await
                    .expect_err("foreign generation read"),
            );
            assert_identity_refusal(
                apply_batch(&session, &cx, &[record(2)])
                    .await
                    .expect_err("foreign replay"),
            );
            assert_identity_refusal(
                apply_batch(&session, &cx, &[record(3)])
                    .await
                    .expect_err("foreign fold"),
            );
            assert_eq!(
                session
                    .load_watermark_row(&cx)
                    .await?
                    .expect("watermark retained")
                    .last_position,
                Some(ProjectionPosition::new(2))
            );
            session.close(&cx).await?;
        }

        // Refusals rolled back; the correctly bound session can read, replay,
        // and advance the exact persisted prefix without repairing the DB.
        let session = open(&path, admitted)?;
        assert_eq!(
            page(&session, &cx).await?.decisions,
            vec![
                fgit_projection::AppliedDecision {
                    seq: record(1).seq,
                    digest: record(1).digest
                },
                fgit_projection::AppliedDecision {
                    seq: record(2).seq,
                    digest: record(2).digest
                },
            ]
        );
        assert_eq!(
            apply_batch(&session, &cx, &[record(2)])
                .await?
                .idempotent_replays,
            1
        );
        assert_eq!(apply_batch(&session, &cx, &[record(3)]).await?.applied, 1);
        session.close(&cx).await?;
        Ok(())
    });
}

#[test]
fn missing_receipt_refuses_even_an_empty_installed_generation_and_recovers_explicitly() {
    run_case(|cx| async move {
        for count in [0, 2] {
            let path = database_path("missing");
            let admitted = identity(1, 1, BuildIdentity::current());
            let session = open(&path, admitted.clone())?;
            ensure_schema_generation(&session, &cx, 1).await?;
            let records = (1..=count).map(record).collect::<Vec<_>>();
            apply_batch(&session, &cx, &records).await?;
            let expected = page(&session, &cx).await?;
            assert_eq!(
                expected.decisions.len(),
                usize::try_from(count).expect("small count")
            );
            flatten(
                session
                    .connection_ref()
                    .execute(
                        &cx,
                        "DELETE FROM fgit_projection_identity WHERE singleton = 1",
                        &[],
                    )
                    .await,
                "plant_missing_identity",
            )?;
            assert_missing_receipt(page(&session, &cx).await.expect_err("missing receipt read"));
            assert_missing_receipt(
                apply_batch(&session, &cx, &[record(count + 1)])
                    .await
                    .expect_err("missing receipt fold"),
            );
            if count != 0 {
                assert_missing_receipt(
                    apply_batch(&session, &cx, &[record(count)])
                        .await
                        .expect_err("missing receipt replay"),
                );
            }
            assert_eq!(
                session
                    .load_watermark_row(&cx)
                    .await?
                    .expect("watermark retained")
                    .last_position,
                (count != 0).then_some(ProjectionPosition::new(count))
            );
            session.close(&cx).await?;

            let session = open(&path, admitted)?;
            assert_missing_receipt(
                page(&session, &cx)
                    .await
                    .expect_err("still missing after reopen"),
            );
            // The owner explicitly restores the known exact receipt. A read
            // or fold never installs it implicitly or adopts another identity.
            session.persist_identity_receipt(&cx).await?;
            assert_eq!(
                page(&session, &cx).await?,
                expected,
                "refusals changed no rows or watermark"
            );
            assert_eq!(
                apply_batch(&session, &cx, &[record(count + 1)])
                    .await?
                    .applied,
                1
            );
            session.close(&cx).await?;
        }
        Ok(())
    });
}

#[test]
fn schema_replacement_refuses_old_session_and_rebuilds_exact_ordered_pages() {
    run_case(|cx| async move {
        let path = database_path("schema");
        let session = open(&path, identity(1, 1, BuildIdentity::current()))?;
        ensure_schema_generation(&session, &cx, 1).await?;
        let records = (1..=7).map(record).collect::<Vec<_>>();
        apply_batch(&session, &cx, &records).await?;
        let expected = pages(&session, &cx).await?;
        let replacement = identity(2, 2, BuildIdentity::current());
        assert_eq!(
            ensure_schema_generation_on(session.connection_ref(), &cx, &replacement).await?,
            SchemaReconciliation::ReadyForFold
        );
        assert!(matches!(
            page(&session, &cx).await,
            Err(ProjectionError::Identity(_))
        ));
        assert!(matches!(
            apply_batch(&session, &cx, &[record(1)]).await,
            Err(ProjectionError::Identity(_))
        ));
        session.close(&cx).await?;

        let session = open(&path, replacement.clone())?;
        let empty = page(&session, &cx).await?;
        assert!(empty.decisions.is_empty());
        assert_eq!(
            empty.watermark, None,
            "legitimate installed empty generation is readable"
        );
        apply_batch(&session, &cx, &records[..4]).await?;
        session.close(&cx).await?;
        let session = open(&path, replacement)?;
        assert_eq!(
            apply_batch(&session, &cx, &records[..4])
                .await?
                .idempotent_replays,
            4
        );
        apply_batch(&session, &cx, &records[4..]).await?;
        assert_eq!(pages(&session, &cx).await?, expected);
        session.close(&cx).await?;
        Ok(())
    });
}

#[test]
fn clean_rebuilds_with_identical_input_and_identity_have_equivalent_pages_and_receipts() {
    run_case(|cx| async move {
        let admitted = identity(1, 1, BuildIdentity::current());
        let records = (1..=7).map(record).collect::<Vec<_>>();
        let mut observations = Vec::new();
        for chunk_size in [1, 3, 7] {
            let path = database_path("rebuild");
            let session = open(&path, admitted.clone())?;
            ensure_schema_generation(&session, &cx, 1).await?;
            for batch in records.chunks(chunk_size) {
                apply_batch(&session, &cx, batch).await?;
            }
            session.close(&cx).await?;
            let session = open(&path, admitted.clone())?;
            let receipt = flatten(
                session
                    .connection_ref()
                    .query_one(
                        &cx,
                        "SELECT receipt FROM fgit_projection_identity WHERE singleton = 1",
                        &[],
                    )
                    .await,
                "read_receipt",
            )?
            .expect("installed receipt");
            let receipt = receipt
                .get_by_name("receipt")
                .and_then(sqlmodel_core::Value::as_str)
                .expect("receipt text");
            assert_eq!(receipt, admitted.render_receipt());
            let actual = pages(&session, &cx).await?;
            assert_eq!(
                actual
                    .iter()
                    .map(|page| page.decisions.len())
                    .collect::<Vec<_>>(),
                vec![3, 3, 1]
            );
            assert_eq!(
                actual
                    .iter()
                    .map(|page| page.next_start)
                    .collect::<Vec<_>>(),
                vec![
                    Some(ProjectionPosition::new(4)),
                    Some(ProjectionPosition::new(7)),
                    None,
                ]
            );
            assert!(
                actual
                    .iter()
                    .all(|page| page.watermark == Some(ProjectionPosition::new(7)))
            );
            assert_eq!(
                actual
                    .iter()
                    .flat_map(|page| page.decisions.iter())
                    .map(|decision| { (decision.seq, decision.digest.as_str()) })
                    .collect::<Vec<_>>(),
                records
                    .iter()
                    .map(|record| { (record.seq, record.digest.as_str()) })
                    .collect::<Vec<_>>()
            );
            observations.push((actual, receipt.to_owned()));
            session.close(&cx).await?;
        }
        assert_eq!(observations[0], observations[1]);
        assert_eq!(observations[1], observations[2]);
        Ok(())
    });
}
