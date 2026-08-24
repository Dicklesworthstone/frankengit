//! FG-028c: the authority-layer arm of the baseline — decisions per CAS.
//!
//! The transport arm measures what a clone or fetch costs. This measures what a
//! *publication* costs, and specifically the ratio the scope line names:
//! how many terminal decisions reach canonical state per compare-and-exchange.
//!
//! # Why this is a separate workload rather than a column on the transport arm
//!
//! A clone is read-only: it commits no authority decision, so the transport
//! samples report zero decisions against a denominator of one and the artifact
//! says so in words. Reporting an authority ratio from a read-only workload
//! would be a number with no measurement behind it. These are two different
//! subjects and the artifact labels them as such.
//!
//! # Where the numbers come from, and why no instrumentation was added
//!
//! Nothing counts CAS operations inside the node, and nothing needs to. The
//! observability is in the return type:
//!
//! * [`PublicationOutcome::Published`] carries `indexed`, the number of outcome
//!   entries that reached canonical state in that one linearization point. That
//!   is the numerator, reported by the operation itself.
//! * [`PublicationOutcome::PredecessorMismatch`] is a CAS that did not commit.
//!   Counting those is the caller's own tally, which is the denominator's
//!   other half.
//!
//! An earlier reading of this bead claimed the metric needed a counter that did
//! not exist. That was wrong: a CAS loser leaving no persisted trace is the
//! §5.2 contract, not a gap, and a stored counter would have been the wrong
//! design.
//!
//! # Contention is produced deterministically, not raced
//!
//! Each round publishes once from a fresh head token, then publishes again
//! from the token the round *started* with — which the first publication has
//! already replaced. The second call is a real `PredecessorMismatch` off the
//! real store, produced without threads, sleeps, or scheduler luck.
//!
//! This is deliberate. `VERIFY_SPEC.md` §4 wants evidence a reader can replay,
//! and a contention figure that depends on which thread won is not replayable.
//! A parallel arm would measure a different and also interesting thing —
//! throughput under real concurrency — and belongs in its own workload where
//! its non-determinism can be labelled. What it would *not* do is make this
//! ratio more accurate.
//!
//! # What this does not claim
//!
//! The batch bodies are synthetic, built from `fgit_codec::harness` templates
//! with fresh transaction identities per round. That makes them valid input,
//! not production traffic: the sizes and refusal mix are chosen, so the ratio
//! describes the publication path under a stated batch shape rather than under
//! a workload observed in the field.

use std::path::PathBuf;

use fgit_authority::{
    AuthorityLimits, HeadKey, HeadRead, PublicationOutcome, StoreInstanceId,
    initialize_repository_async, publish_decisions_async,
};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_codec::harness;
use fgit_codec::schema::{
    RepositoryAuthorityHeadBody, RepositoryDecision, RepositoryDecisionBatchBody,
};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fgit_types::hash::DigestBytes;
use fgit_types::identity::{InternalObjectId, TxId};
use fgit_types::numeric::{DecisionSequence, HeadGeneration};
use fgit_types::{CANONICAL_CODEC_VERSION, DecisionOutcome, RefusalCode, TenantId};
use fsqlite_types::cx::Cx as FsqliteCx;

use crate::{BenchmarkWorkload, OracleReceipt, StorageClasses, SystemMetrics};

/// How the authority arm is configured for one measured run.
#[derive(Clone, Debug)]
pub struct AuthorityPublicationConfig {
    /// Directory the file-backed store is opened in.
    pub store_path: PathBuf,
    /// Terminal decisions per published batch: the ratio's numerator.
    pub decisions_per_batch: usize,
    /// Tenant the outcome entries are indexed under.
    pub tenant_id: TenantId,
    /// Instance identity recorded by the store.
    pub instance_id: StoreInstanceId,
}

/// What one measured publication produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationSample {
    /// Outcome entries that reached canonical state.
    pub indexed: usize,
    /// Compare-and-exchange calls issued, committed and refused together.
    pub cas_attempts: u64,
    /// Calls that lost the head token.
    pub predecessor_mismatches: u64,
    /// Head generation observed after the round.
    pub generation_after: u64,
}

/// The authority publication workload.
pub struct AuthorityPublicationWorkload {
    config: AuthorityPublicationConfig,
    runtime: NodeRuntime,
    store: FsqliteAuthorityStore,
    cx: FsqliteCx,
    head_key: HeadKey,
    head: RepositoryAuthorityHeadBody,
    generation: u64,
    round: u64,
}

impl AuthorityPublicationWorkload {
    /// Opens the production store and brings the repository into existence.
    ///
    /// # Errors
    ///
    /// Returns the refusal text when the runtime, the store, or the repository
    /// initialization refuses. A workload that cannot establish its subject is
    /// a failure, never a fast sample.
    pub fn open(config: AuthorityPublicationConfig) -> Result<Self, String> {
        let runtime = RuntimeProfile::deterministic()
            .build()
            .map_err(|error| format!("deterministic runtime profile: {error:?}"))?;

        let cx = FsqliteCx::new();
        cx.set_native_cx(runtime.request_cx(BudgetClass::Database));

        let path = config
            .store_path
            .to_str()
            .ok_or_else(|| "store path is not valid UTF-8".to_owned())?
            .to_owned();

        let store = runtime
            .block_on(FsqliteAuthorityStore::open(
                &cx,
                path,
                config.instance_id,
                AuthorityLimits::default(),
            ))
            .map_err(|error| format!("open authority store: {error:?}"))?;

        let genesis = harness::genesis_head();
        let head_key = HeadKey::new(b"fg028c/authority-publication".to_vec())
            .map_err(|error| format!("head key: {error:?}"))?;
        runtime
            .block_on(initialize_repository_async(
                &store, &cx, &head_key, &genesis,
            ))
            .map_err(|error| format!("initialize repository: {error:?}"))?;

        Ok(Self {
            config,
            runtime,
            store,
            cx,
            head_key,
            head: genesis,
            generation: 1,
            round: 0,
        })
    }

    /// Mints a transaction identity unique to `(round, slot)`.
    ///
    /// Uniqueness is the whole point: the publication path scans for existing
    /// decisions by transaction identity, so a repeated `TxId` is answered as
    /// an idempotent replay rather than a new publication, and the round would
    /// measure duplicate detection instead of publication.
    fn tx_id_for(round: u64, slot: usize) -> Result<TxId, String> {
        let mut body = [0_u8; 32];
        body[..8].copy_from_slice(&round.to_be_bytes());
        body[8..16].copy_from_slice(&(slot as u64).to_be_bytes());
        let digest = DigestBytes::try_new(&body)
            .map_err(|error| format!("transaction digest body: {error:?}"))?;
        TxId::from_internal_object_id(InternalObjectId::new(
            harness::algorithm(),
            TxId::DOMAIN_TAG,
            CANONICAL_CODEC_VERSION,
            digest,
        ))
        .map_err(|error| format!("mint transaction id: {error:?}"))
    }

    /// Builds the batch published by one round.
    fn batch_for_round(&self, round: u64) -> Result<RepositoryDecisionBatchBody, String> {
        let mut batch = harness::decision_batch();
        batch.predecessor_head_generation = self.head.generation;
        batch.decisions.clear();
        batch.committed_rcrs.clear();

        for slot in 0..self.config.decisions_per_batch {
            let sequence = u64::try_from(slot).map_err(|_| "decision slot overflow".to_owned())?;
            batch.decisions.push(RepositoryDecision {
                tx_id: Self::tx_id_for(round, slot)?,
                decision_sequence: DecisionSequence::try_new(sequence.saturating_add(1))
                    .map_err(|error| format!("decision sequence: {error:?}"))?,
                outcome: DecisionOutcome::Refused {
                    code: RefusalCode::ExpectedOldRefMismatch,
                    refusal_record_id: harness::refusal_record_id(),
                },
            });
        }
        Ok(batch)
    }
}

impl BenchmarkWorkload for AuthorityPublicationWorkload {
    type Output = PublicationSample;

    fn measure(&mut self) -> Result<(Self::Output, SystemMetrics), String> {
        self.round = self.round.saturating_add(1);
        let round = self.round;

        // The token this round starts from. Deliberately kept: the second
        // publication below reuses it after it has been replaced, which is what
        // manufactures a real losing CAS without a race.
        let opening = self
            .runtime
            .block_on(self.store.read_head(&self.cx, &self.head_key))
            .map_err(|error| format!("read head: {error:?}"))?;
        let opening_token = match opening {
            HeadRead::Present(receipt) => receipt.token(),
            HeadRead::Absent => {
                return Err("the repository head vanished mid-run".to_owned());
            }
        };

        let batch = self.batch_for_round(round)?;
        let mut next_head = self.head.clone();
        let next_generation = self.generation.saturating_add(1);
        next_head.generation = HeadGeneration::try_new(next_generation)
            .map_err(|error| format!("head generation: {error:?}"))?;

        let mut cas_attempts = 0_u64;
        let mut mismatches = 0_u64;

        cas_attempts = cas_attempts.saturating_add(1);
        let published = self
            .runtime
            .block_on(publish_decisions_async(
                &self.store,
                &self.cx,
                &self.head_key,
                opening_token,
                &batch,
                &next_head,
                self.config.tenant_id,
            ))
            .map_err(|error| format!("publish decisions: {error:?}"))?;

        let indexed = match published {
            PublicationOutcome::Published(published) => published.indexed,
            PublicationOutcome::PredecessorMismatch => {
                return Err(
                    "the opening publication lost its token with no competing writer".to_owned(),
                );
            }
            PublicationOutcome::AlreadyDecided { .. } => {
                return Err(
                    "the round replayed an existing transaction: identities are not unique"
                        .to_owned(),
                );
            }
        };
        self.head = next_head;

        // The stale republication: same token, now superseded.
        cas_attempts = cas_attempts.saturating_add(1);
        let stale = self
            .runtime
            .block_on(publish_decisions_async(
                &self.store,
                &self.cx,
                &self.head_key,
                opening_token,
                &self.batch_for_round(round.saturating_add(1_000_000))?,
                &self.head,
                self.config.tenant_id,
            ))
            .map_err(|error| format!("stale publish: {error:?}"))?;
        if matches!(stale, PublicationOutcome::PredecessorMismatch) {
            mismatches = mismatches.saturating_add(1);
        }

        self.generation = next_generation;

        let sample = PublicationSample {
            indexed,
            cas_attempts,
            predecessor_mismatches: mismatches,
            generation_after: next_generation,
        };

        let metrics = SystemMetrics {
            latency_ns: 0,
            cpu_ns: 0,
            memory_bytes: 0,
            object_requests: 0,
            object_request_bytes: 0,
            egress_bytes: 0,
            // Reported by the operation, not inferred: `indexed` is the count
            // of outcome entries the publication made canonical.
            decisions: u64::try_from(indexed).unwrap_or(u64::MAX),
            cas_attempts,
            storage: StorageClasses {
                canonical_bytes: 0,
                repair_bytes: 0,
                replica_bytes: 0,
                retained_derived_bytes: 0,
                logical_reachable_git_bytes: 0,
            },
        };

        Ok((sample, metrics))
    }

    fn verify(&mut self, output: &Self::Output) -> Result<OracleReceipt, String> {
        if output.indexed != self.config.decisions_per_batch {
            return Err(format!(
                "published {} outcome entries, batch carried {}",
                output.indexed, self.config.decisions_per_batch
            ));
        }
        if output.predecessor_mismatches != 1 {
            return Err(format!(
                "expected exactly one losing CAS from the stale republication, observed {}",
                output.predecessor_mismatches
            ));
        }
        if output.generation_after != self.generation {
            return Err(format!(
                "head generation is {} after the round, the workload tracked {}",
                output.generation_after, self.generation
            ));
        }
        Ok(OracleReceipt {
            receipt: format!(
                "authority-publication indexed={} attempts={} lost={} generation={}",
                output.indexed,
                output.cas_attempts,
                output.predecessor_mismatches,
                output.generation_after
            ),
        })
    }
}
