# GENERATED FILE - DO NOT EDIT.
#
# Produced by `cargo run -p fgit-schema --bin fgit-schema-gen -- generate`.
# The generator is a repository-owned command: no build script, no proc
# macro, no network. `... -- check` refuses if this file differs from what
# the current descriptors produce, so an edit here fails the fast lane
# instead of drifting.

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Digest:
    """An algorithm-tagged digest. bytes_hex is lowercase hex."""

    algorithm: int
    bytes_hex: str


@dataclass(frozen=True, slots=True)
class SchemaId:
    """A schema identifier."""

    family: str
    major: int
    minor: int


@dataclass(frozen=True, slots=True)
class DerivedId:
    """A domain-bound derived identity."""

    algorithm: int
    domain: str
    codec_major: int
    codec_minor: int
    digest: str


@dataclass(frozen=True, slots=True)
class AuthorityHeadV1:
    """The one value whose conditional replacement publishes repository state.

    schema authority-head v1.0, domain frankengit/authority-head/v1
    """

    # Repository this head governs.
    repository_id: str
    # Monotone head generation.
    generation: int
    # Root over the current ref state.
    ref_root: Digest
    # Root over the current forge position.
    forge_position_root: Digest
    # Root over the rebuildable outcome index.
    outcome_index_root: Digest
    # Root over the current retention state.
    retention_root: Digest
    # Root over the current external-effect outbox.
    outbox_root: Digest
    # Root over the configuration needed to interpret this head.
    configuration_root: Digest
    # Current policy epoch.
    policy_epoch: int
    # Current format and algorithm registry epoch.
    format_registry_epoch: int
    # Exact predecessor head, absent only for the genesis head.
    predecessor_head_id: DerivedId | None = None
    # Most recent decision batch, absent before the first decision.
    decision_tail_id: DerivedId | None = None
    # Latest terminal-decision position, absent before the first decision.
    latest_decision_sequence: int | None = None
    # Latest committed record, absent before the first commit.
    latest_committed_rcr_id: DerivedId | None = None
    # Latest committed-transition position, absent before the first commit.
    latest_repository_sequence: int | None = None
    # Most recent checkpoint capsule, when one exists.
    last_checkpoint_id: DerivedId | None = None


@dataclass(frozen=True, slots=True)
class RefusalRecordV1:
    """The terminal record of one refused transaction, with the evidence behind it.

    schema refusal-record v1.0, domain frankengit/refusal-record/v1
    """

    # Sealed transaction that was refused.
    tx_id: DerivedId
    # Seal the refusal is bound to.
    seal_id: DerivedId
    # Position in the terminal-decision order.
    decision_sequence: int
    # Terminal refusal reason, drawn from the closed refusal vocabulary.
    code: int
    # Policy epoch the refusal was decided under.
    policy_epoch: int
    # Human-readable detail, bounded by MAX_REFUSAL_DETAIL_LEN.
    detail: str
    # Root over the evidence that supports the refusal.
    evidence_root: Digest


@dataclass(frozen=True, slots=True)
class RcrV1:
    """The canonical source and forge mutation record for one committed logical transaction.

    schema rcr v1.0, domain frankengit/rcr/v1
    """

    # Repository the record belongs to.
    repository_id: str
    # Position in the committed-transition order.
    repository_sequence: int
    # Sealed transaction this record commits.
    tx_id: DerivedId
    # Immutable principal and capability snapshot the decision used.
    principal_snapshot_id: DerivedId
    # Digest binding the client-visible semantic request.
    canonical_request_digest: Digest
    # Root over the ref changes this record applies.
    ref_delta_root: Digest
    # Root over the resulting ref state.
    resulting_ref_root: Digest
    # Root over the validated object closure.
    object_closure_root: Digest
    # Root over the forge events committed with the ref changes.
    forge_event_batch_root: Digest
    # Root over the resulting forge position.
    resulting_forge_position_root: Digest
    # Policy epoch the decision was evaluated under.
    policy_epoch: int
    # Root over the policy decision evidence.
    policy_decision_root: Digest
    # Root over the invariant evidence.
    invariant_evidence_root: Digest
    # Root over the external-effect obligations this record owes.
    outbox_effect_root: Digest
    # Root over the retention change this record makes.
    retention_delta_root: Digest
    # Previously committed record, absent only at repository creation.
    parent_rcr_id: DerivedId | None = None


@dataclass(frozen=True, slots=True)
class TxnSealV1:
    """The sealed, immutable statement of one logical mutation request.

    schema txn-seal v1.0, domain frankengit/txn-seal/v1
    """

    # Identity of the sealed logical mutation.
    tx_id: DerivedId
    # Owning tenant.
    tenant_id: str
    # Target repository.
    repository_id: str
    # Principal the gateway authenticated.
    authenticated_principal_id: str
    # Digest of the client's idempotency key.
    idempotency_key_digest: Digest
    # Digest binding every client-visible semantic field of the request.
    canonical_request_digest: Digest
    # Schema of the request that was canonicalized.
    request_schema: SchemaId


# Wire order per schema. The dataclasses above group required fields
# before optional ones because Python requires it; the canonical
# encoding does not, and THIS is the order the bytes are in.
WIRE_ORDER: dict[str, tuple[str, ...]] = {
    "AuthorityHeadV1": ("repository_id", "generation", "predecessor_head_id", "decision_tail_id", "latest_decision_sequence", "latest_committed_rcr_id", "latest_repository_sequence", "ref_root", "forge_position_root", "outcome_index_root", "retention_root", "outbox_root", "configuration_root", "policy_epoch", "format_registry_epoch", "last_checkpoint_id",),
    "RefusalRecordV1": ("tx_id", "seal_id", "decision_sequence", "code", "policy_epoch", "detail", "evidence_root",),
    "RcrV1": ("repository_id", "repository_sequence", "parent_rcr_id", "tx_id", "principal_snapshot_id", "canonical_request_digest", "ref_delta_root", "resulting_ref_root", "object_closure_root", "forge_event_batch_root", "resulting_forge_position_root", "policy_epoch", "policy_decision_root", "invariant_evidence_root", "outbox_effect_root", "retention_delta_root",),
    "TxnSealV1": ("tx_id", "tenant_id", "repository_id", "authenticated_principal_id", "idempotency_key_digest", "canonical_request_digest", "request_schema",),
}
