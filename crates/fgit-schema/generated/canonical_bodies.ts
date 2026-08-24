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
