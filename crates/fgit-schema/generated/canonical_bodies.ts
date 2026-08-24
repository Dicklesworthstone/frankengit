// GENERATED FILE - DO NOT EDIT.
//
// Produced by `cargo run -p fgit-schema --bin fgit-schema-gen -- generate`.
// The generator is a repository-owned command: no build script, no proc
// macro, no network. `... -- check` refuses if this file differs from what
// the current descriptors produce, so an edit here fails the fast lane
// instead of drifting.

/** An algorithm-tagged digest. `bytes` is lowercase hex. */
export interface Digest {
  algorithm: number;
  bytes: string;
}

/** A schema identifier. */
export interface SchemaId {
  family: string;
  major: number;
  minor: number;
}

/** A domain-bound derived identity. */
export interface DerivedId {
  algorithm: number;
  domain: string;
  codec_major: number;
  codec_minor: number;
  digest: string;
}

/** One terminal decision within a batch, in the batch's own order. */
export interface RepositoryDecision {
  /** Sealed transaction the decision belongs to. */
  tx_id: DerivedId;
  /** Position in the terminal-decision order, refusals included. */
  decision_sequence: string;
  /** The terminal outcome. */
  outcome: DecisionOutcome;
}

/** The terminal outcome of one decision: committed, or refused with a reason. */
export type DecisionOutcome =
  | DecisionOutcomeCommitted
  | DecisionOutcomeRefused;

/** The decision committed, naming the record it produced. */
export interface DecisionOutcomeCommitted {
  /** The raw wire byte that selects this variant. */
  discriminant: 1;
  /** The Repository Commit Record this decision produced. */
  repository_commit_id: DerivedId;
}

/** The decision was refused, naming the reason and the evidence record. */
export interface DecisionOutcomeRefused {
  /** The raw wire byte that selects this variant. */
  discriminant: 2;
  /** Terminal refusal reason, from the closed refusal vocabulary. */
  code: number;
  /** The refusal record carrying the evidence. */
  refusal_record_id: DerivedId;
}

/**
 * The one value whose conditional replacement publishes repository state.
 *
 * schema authority-head v1.0, domain frankengit/authority-head/v1
 */
export interface AuthorityHeadV1 {
  /** Repository this head governs. */
  repository_id: string;
  /** Monotone head generation. */
  generation: string;
  /** Exact predecessor head, absent only for the genesis head. */
  predecessor_head_id?: DerivedId;
  /** Most recent decision batch, absent before the first decision. */
  decision_tail_id?: DerivedId;
  /** Latest terminal-decision position, absent before the first decision. */
  latest_decision_sequence?: string;
  /** Latest committed record, absent before the first commit. */
  latest_committed_rcr_id?: DerivedId;
  /** Latest committed-transition position, absent before the first commit. */
  latest_repository_sequence?: string;
  /** Root over the current ref state. */
  ref_root: Digest;
  /** Root over the current forge position. */
  forge_position_root: Digest;
  /** Root over the rebuildable outcome index. */
  outcome_index_root: Digest;
  /** Root over the current retention state. */
  retention_root: Digest;
  /** Root over the current external-effect outbox. */
  outbox_root: Digest;
  /** Root over the configuration needed to interpret this head. */
  configuration_root: Digest;
  /** Current policy epoch. */
  policy_epoch: string;
  /** Current format and algorithm registry epoch. */
  format_registry_epoch: string;
  /** Most recent checkpoint capsule, when one exists. */
  last_checkpoint_id?: DerivedId;
}

/**
 * The batch of terminal decisions published against one authority head.
 *
 * schema decision-batch v1.1, domain frankengit/decision-batch/v1
 */
export interface DecisionBatchV1 {
  /** Repository the batch belongs to. */
  repository_id: string;
  /** Head this batch was prepared against. */
  predecessor_head_id: DerivedId;
  /** Generation of that head, which makes the basis check monotone. */
  predecessor_head_generation: string;
  /** Decision-sequence position of the first decision in the batch. */
  first_decision_sequence: string;
  /** Terminal decisions, in deterministic batch order. */
  decisions: RepositoryDecision[];
  /** Commit records for the committed decisions, in repository order. */
  committed_rcrs: RcrV1[];
  /** Root over the resulting ref state. */
  resulting_ref_root: Digest;
  /** Root over the resulting forge position. */
  resulting_forge_position_root: Digest;
  /** Root over the rebuildable outcome index. */
  resulting_outcome_index_root: Digest;
  /** Root over the resulting retention state. */
  resulting_retention_root: Digest;
  /** Root over the resulting external-effect outbox. */
  resulting_outbox_root: Digest;
  /** Policy epoch after the batch. */
  resulting_policy_epoch: string;
  /** Merkle commitment over this batch's ordered decision evidence. */
  batch_evidence_root: Digest;
  /** Compaction generation bound by this publication, when it publishes one. */
  compaction_generation_link?: Digest;
}

/**
 * The terminal record of one refused transaction, with the evidence behind it.
 *
 * schema refusal-record v1.0, domain frankengit/refusal-record/v1
 */
export interface RefusalRecordV1 {
  /** Sealed transaction that was refused. */
  tx_id: DerivedId;
  /** Seal the refusal is bound to. */
  seal_id: DerivedId;
  /** Position in the terminal-decision order. */
  decision_sequence: string;
  /** Terminal refusal reason, drawn from the closed refusal vocabulary. */
  code: number;
  /** Policy epoch the refusal was decided under. */
  policy_epoch: string;
  /** Human-readable detail, bounded by MAX_REFUSAL_DETAIL_LEN. */
  detail: string;
  /** Root over the evidence that supports the refusal. */
  evidence_root: Digest;
}

/**
 * The canonical source and forge mutation record for one committed logical transaction.
 *
 * schema rcr v1.0, domain frankengit/rcr/v1
 */
export interface RcrV1 {
  /** Repository the record belongs to. */
  repository_id: string;
  /** Position in the committed-transition order. */
  repository_sequence: string;
  /** Previously committed record, absent only at repository creation. */
  parent_rcr_id?: DerivedId;
  /** Sealed transaction this record commits. */
  tx_id: DerivedId;
  /** Immutable principal and capability snapshot the decision used. */
  principal_snapshot_id: DerivedId;
  /** Digest binding the client-visible semantic request. */
  canonical_request_digest: Digest;
  /** Root over the ref changes this record applies. */
  ref_delta_root: Digest;
  /** Root over the resulting ref state. */
  resulting_ref_root: Digest;
  /** Root over the validated object closure. */
  object_closure_root: Digest;
  /** Root over the forge events committed with the ref changes. */
  forge_event_batch_root: Digest;
  /** Root over the resulting forge position. */
  resulting_forge_position_root: Digest;
  /** Policy epoch the decision was evaluated under. */
  policy_epoch: string;
  /** Root over the policy decision evidence. */
  policy_decision_root: Digest;
  /** Root over the invariant evidence. */
  invariant_evidence_root: Digest;
  /** Root over the external-effect obligations this record owes. */
  outbox_effect_root: Digest;
  /** Root over the retention change this record makes. */
  retention_delta_root: Digest;
}

/**
 * The sealed, immutable statement of one logical mutation request.
 *
 * schema txn-seal v1.0, domain frankengit/txn-seal/v1
 */
export interface TxnSealV1 {
  /** Identity of the sealed logical mutation. */
  tx_id: DerivedId;
  /** Owning tenant. */
  tenant_id: string;
  /** Target repository. */
  repository_id: string;
  /** Principal the gateway authenticated. */
  authenticated_principal_id: string;
  /** Digest of the client's idempotency key. */
  idempotency_key_digest: Digest;
  /** Digest binding every client-visible semantic field of the request. */
  canonical_request_digest: Digest;
  /** Schema of the request that was canonicalized. */
  request_schema: SchemaId;
}
