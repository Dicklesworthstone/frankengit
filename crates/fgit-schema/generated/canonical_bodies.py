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
class GitOid:
    """A native Git object identity. bytes_hex is lowercase hex."""

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
class RepositoryDecision:
    """One terminal decision within a batch, in the batch's own order."""

    # Sealed transaction the decision belongs to.
    tx_id: DerivedId
    # Position in the terminal-decision order, refusals included.
    decision_sequence: int
    # The terminal outcome.
    outcome: DecisionOutcome


@dataclass(frozen=True, slots=True)
class VerifiedReadMerkleProofPayload:
    """One native Merkle path, in the wire order consumed by the shared verifier."""

    # Zero-based ordered-leaf position the path proves.
    index: int
    # Exact number of leaves in the committed tree.
    leaf_count: int
    # Bottom-up sibling digest bodies, without an algorithm tag because the enclosing proof layout selects it.
    siblings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RefStateNeighbour:
    """One ordered ref-state neighbour and its membership path."""

    # Validated raw ref-name bytes, length-prefixed on the wire.
    name: str
    # Native object identity carried by the neighbour leaf.
    oid: GitOid
    # Membership path proving this exact neighbour under the pinned ref root.
    proof: VerifiedReadMerkleProofPayload


@dataclass(frozen=True, slots=True)
class RepositoryConfigurationV1:
    """Version-one repository configuration body carried inline by a verified read."""

    # Authenticated root layout needed to interpret the head roots.
    root_layout: int
    # Permanent native Git object identity algorithm.
    object_format: int
    # Ordered raw visibility-rule bytes; the last matching rule wins.
    hidden_ref_rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RepositoryIncarnationConfigurationV2:
    """Version-two repository configuration carrying the minted incarnation identity."""

    # Authenticated root layout needed to interpret the head roots.
    root_layout: int
    # Permanent native Git object identity algorithm.
    object_format: int
    # Minted incarnation preventing a delete/recreate location alias.
    repository_incarnation_id: str


@dataclass(frozen=True, slots=True)
class ObjectClosureNeighbour:
    """An authenticated object-closure leaf adjacent to the absent identity."""

    # The authenticated neighbouring object identity.
    oid: GitOid
    # The proof binding this neighbour to the committed closure root.
    proof: VerifiedReadMerkleProofPayload


@dataclass(frozen=True, slots=True)
class RepositoryIncarnationConfigurationV21:
    """Version-2.1 repository configuration carrying the incarnation identity and bound policy root."""

    # Authenticated root layout needed to interpret the head roots.
    root_layout: int
    # Permanent native Git object identity algorithm.
    object_format: int
    # Minted incarnation preventing a delete/recreate location alias.
    repository_incarnation_id: str
    # Policy root bound to this incarnation, absent when none is published.
    policy_root: Digest | None = None


@dataclass(frozen=True, slots=True)
class DecisionOutcomeCommitted:
    """The decision committed, naming the record it produced."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 1
    # The Repository Commit Record this decision produced.
    repository_commit_id: DerivedId


@dataclass(frozen=True, slots=True)
class DecisionOutcomeRefused:
    """The decision was refused, naming the reason and the evidence record."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 2
    # Terminal refusal reason, from the closed refusal vocabulary.
    code: int
    # The refusal record carrying the evidence.
    refusal_record_id: DerivedId


# The terminal outcome of one decision: committed, or refused with a reason.
DecisionOutcome = DecisionOutcomeCommitted | DecisionOutcomeRefused


@dataclass(frozen=True, slots=True)
class VerifiedReadConfigurationRepositoryV1:
    """RepositoryConfigurationBody schema v1.2."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 1
    # Exact V1 configuration payload, without a nested canonical frame.
    body: RepositoryConfigurationV1


@dataclass(frozen=True, slots=True)
class VerifiedReadConfigurationRepositoryIncarnationV2:
    """RepositoryIncarnationConfigurationBody schema v2.0."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 2
    # Exact V2 configuration payload, without a nested canonical frame.
    body: RepositoryIncarnationConfigurationV2


@dataclass(frozen=True, slots=True)
class VerifiedReadConfigurationRepositoryIncarnationV2_1:
    """RepositoryIncarnationConfigurationBodyV2_1 schema v2.1, carrying the policy root."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 3
    # Exact V2.1 configuration payload, without a nested canonical frame.
    body: RepositoryIncarnationConfigurationV21


# A version-tagged configuration body, inlined only when the answer needs one.
VerifiedReadConfiguration = VerifiedReadConfigurationRepositoryV1 | VerifiedReadConfigurationRepositoryIncarnationV2 | VerifiedReadConfigurationRepositoryIncarnationV2_1


@dataclass(frozen=True, slots=True)
class RefStateNonMembershipProofEmptyState:
    """The committed ref-state tree has no leaves."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 0


@dataclass(frozen=True, slots=True)
class RefStateNonMembershipProofBeforeFirst:
    """The requested name orders strictly before the authenticated first leaf."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 1
    # The authenticated first neighbour.
    first: RefStateNeighbour


@dataclass(frozen=True, slots=True)
class RefStateNonMembershipProofBetween:
    """The requested name orders strictly between two adjacent authenticated leaves."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 2
    # The authenticated predecessor neighbour.
    predecessor: RefStateNeighbour
    # The authenticated successor neighbour.
    successor: RefStateNeighbour


@dataclass(frozen=True, slots=True)
class RefStateNonMembershipProofAfterLast:
    """The requested name orders strictly after the authenticated last leaf."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 3
    # The authenticated last neighbour.
    last: RefStateNeighbour


# An absence proof selected by the requested name's ordered position.
RefStateNonMembershipProof = RefStateNonMembershipProofEmptyState | RefStateNonMembershipProofBeforeFirst | RefStateNonMembershipProofBetween | RefStateNonMembershipProofAfterLast


@dataclass(frozen=True, slots=True)
class VerifiedReadAnswerRefMembership:
    """One named ref and a path proving its membership in the pinned ref root."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 1
    # Validated claimed ref-name bytes.
    name: str
    # Claimed native object identity.
    oid: GitOid
    # Membership path for the named ref leaf.
    proof: VerifiedReadMerkleProofPayload


@dataclass(frozen=True, slots=True)
class VerifiedReadAnswerOutcomeMembership:
    """One terminal decision and a path proving its outcome-index membership."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 2
    # Canonical terminal decision selected by the transaction identity.
    decision: RepositoryDecision
    # Membership path for the canonical outcome leaf.
    proof: VerifiedReadMerkleProofPayload


@dataclass(frozen=True, slots=True)
class VerifiedReadAnswerAuthorizedRefAbsence:
    """A disclosure-authorized requested name and ordered non-membership witness."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 3
    # Validated requested ref-name bytes; authorization happened before lookup.
    name: str
    # Ordered absence witness under the pinned ref root.
    proof: RefStateNonMembershipProof


# One proof answer; unknown tags cannot be skipped and must refuse.
VerifiedReadAnswer = VerifiedReadAnswerRefMembership | VerifiedReadAnswerOutcomeMembership | VerifiedReadAnswerAuthorizedRefAbsence


@dataclass(frozen=True, slots=True)
class ObjectClosureNonMembershipProofEmptyClosure:
    """The committed object closure has no leaves."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 0


@dataclass(frozen=True, slots=True)
class ObjectClosureNonMembershipProofBeforeFirst:
    """The requested identity orders strictly before the authenticated first leaf."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 1
    # The authenticated first neighbour.
    first: ObjectClosureNeighbour


@dataclass(frozen=True, slots=True)
class ObjectClosureNonMembershipProofBetween:
    """The requested identity orders strictly between two adjacent leaves."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 2
    # The authenticated predecessor neighbour.
    predecessor: ObjectClosureNeighbour
    # The authenticated successor neighbour.
    successor: ObjectClosureNeighbour


@dataclass(frozen=True, slots=True)
class ObjectClosureNonMembershipProofAfterLast:
    """The requested identity orders strictly after the authenticated last leaf."""

    # The raw wire byte that selects this variant.
    DISCRIMINANT = 3
    # The authenticated last neighbour.
    last: ObjectClosureNeighbour


# An absence proof selected by the requested object identity's ordered position.
ObjectClosureNonMembershipProof = ObjectClosureNonMembershipProofEmptyClosure | ObjectClosureNonMembershipProofBeforeFirst | ObjectClosureNonMembershipProofBetween | ObjectClosureNonMembershipProofAfterLast


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
class DecisionBatchV1:
    """The batch of terminal decisions published against one authority head.

    schema decision-batch v1.1, domain frankengit/decision-batch/v1
    """

    # Repository the batch belongs to.
    repository_id: str
    # Head this batch was prepared against.
    predecessor_head_id: DerivedId
    # Generation of that head, which makes the basis check monotone.
    predecessor_head_generation: int
    # Decision-sequence position of the first decision in the batch.
    first_decision_sequence: int
    # Root over the resulting ref state.
    resulting_ref_root: Digest
    # Root over the resulting forge position.
    resulting_forge_position_root: Digest
    # Root over the rebuildable outcome index.
    resulting_outcome_index_root: Digest
    # Root over the resulting retention state.
    resulting_retention_root: Digest
    # Root over the resulting external-effect outbox.
    resulting_outbox_root: Digest
    # Policy epoch after the batch.
    resulting_policy_epoch: int
    # Merkle commitment over this batch's ordered decision evidence.
    batch_evidence_root: Digest
    # Terminal decisions, in deterministic batch order.
    decisions: tuple[RepositoryDecision, ...]
    # Commit records for the committed decisions, in repository order.
    committed_rcrs: tuple[RcrV1, ...]
    # Compaction generation bound by this publication, when it publishes one.
    compaction_generation_link: Digest | None = None


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


@dataclass(frozen=True, slots=True)
class VerifiedReadMerkleProofV1:
    """A canonical transport body for the native Merkle proof verifier.

    schema verified-read-merkle-proof v1.0, domain frankengit/verified-read-merkle-proof/v1
    """

    # Zero-based ordered-leaf position the path proves.
    index: int
    # Exact number of leaves in the committed tree.
    leaf_count: int
    # Bottom-up sibling digest bodies, without an algorithm tag because the enclosing proof layout selects it.
    siblings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VerifiedReadRefNonMembershipProofV1:
    """A canonical ordered ref-state non-membership witness for the shared Merkle verifier.

    schema verified-read-ref-non-membership-proof v1.0, domain frankengit/verified-read-ref-non-membership-proof/v1
    """

    # The empty, boundary, or between-neighbours absence shape.
    proof: RefStateNonMembershipProof


@dataclass(frozen=True, slots=True)
class VerifiedReadObjectNonMembershipProofV1:
    """A canonical ordered object-closure non-membership witness for the shared Merkle verifier.

    schema verified-read-object-non-membership-proof v1.0, domain frankengit/verified-read-object-non-membership-proof/v1
    """

    # The empty, boundary, or between-neighbours absence shape.
    proof: ObjectClosureNonMembershipProof


@dataclass(frozen=True, slots=True)
class VerifiedReadEnvelopeV1:
    """A relayed answer whose proof verifies only against the client's independently pinned authority head.

    schema verified-read-envelope v1.0, domain frankengit/verified-read-envelope/v1
    """

    # Verified-read envelope grammar version; V1 is the only accepted value in this build.
    version: int
    # Carried authority head, compared byte-for-byte to the client pin.
    head: AuthorityHeadV1
    # The ref, outcome, or authorization-gated absence claim and its witness.
    answer: VerifiedReadAnswer
    # Exact optional configuration body required to interpret the selected root layout.
    configuration: VerifiedReadConfiguration | None = None


@dataclass(frozen=True, slots=True)
class RepositoryCreationAttemptV1:
    """One attempt to create a repository, keyed so a retry is recognisable as the same attempt.

    schema repository-creation-attempt v1.0, domain frankengit/repository-creation-attempt/v1
    """

    # Tenant the attempt is made under.
    tenant_id: str
    # Repository the attempt would create.
    repository_id: str
    # Storage root layout version selected at creation.
    root_layout: int
    # Permanent native Git object identity algorithm.
    object_format: int
    # Digest of the caller's idempotency key; a retry carrying it is the same attempt.
    idempotency_key_digest: Digest
    # Incarnation this attempt would establish.
    repository_incarnation_id: str


@dataclass(frozen=True, slots=True)
class HiddenRefPolicyV1:
    """The ordered raw visibility rules a repository applies to ref advertisement.

    schema hidden-ref-policy v1.0, domain frankengit/hidden-ref-policy/v1
    """

    # Ordered raw visibility-rule bytes; the last matching rule wins.
    rules: tuple[str, ...]


# Wire order per schema. The dataclasses above group required fields
# before optional ones because Python requires it; the canonical
# encoding does not, and THIS is the order the bytes are in.
WIRE_ORDER: dict[str, tuple[str, ...]] = {
    "AuthorityHeadV1": ("repository_id", "generation", "predecessor_head_id", "decision_tail_id", "latest_decision_sequence", "latest_committed_rcr_id", "latest_repository_sequence", "ref_root", "forge_position_root", "outcome_index_root", "retention_root", "outbox_root", "configuration_root", "policy_epoch", "format_registry_epoch", "last_checkpoint_id",),
    "DecisionBatchV1": ("repository_id", "predecessor_head_id", "predecessor_head_generation", "first_decision_sequence", "decisions", "committed_rcrs", "resulting_ref_root", "resulting_forge_position_root", "resulting_outcome_index_root", "resulting_retention_root", "resulting_outbox_root", "resulting_policy_epoch", "batch_evidence_root", "compaction_generation_link",),
    "RefusalRecordV1": ("tx_id", "seal_id", "decision_sequence", "code", "policy_epoch", "detail", "evidence_root",),
    "RcrV1": ("repository_id", "repository_sequence", "parent_rcr_id", "tx_id", "principal_snapshot_id", "canonical_request_digest", "ref_delta_root", "resulting_ref_root", "object_closure_root", "forge_event_batch_root", "resulting_forge_position_root", "policy_epoch", "policy_decision_root", "invariant_evidence_root", "outbox_effect_root", "retention_delta_root",),
    "TxnSealV1": ("tx_id", "tenant_id", "repository_id", "authenticated_principal_id", "idempotency_key_digest", "canonical_request_digest", "request_schema",),
    "VerifiedReadMerkleProofV1": ("index", "leaf_count", "siblings",),
    "VerifiedReadRefNonMembershipProofV1": ("proof",),
    "VerifiedReadObjectNonMembershipProofV1": ("proof",),
    "VerifiedReadEnvelopeV1": ("version", "head", "configuration", "answer",),
    "RepositoryCreationAttemptV1": ("tenant_id", "repository_id", "root_layout", "object_format", "idempotency_key_digest", "repository_incarnation_id",),
    "HiddenRefPolicyV1": ("rules",),
}
