//! The described canonical bodies.
//!
//! Four of `fgit-codec`'s five canonical bodies are described here. The fifth,
//! `decision-batch`, is a **typed refusal** rather than an omission: it carries
//! sequences of nested structures and a payload-carrying tagged union, and the
//! descriptor format is deliberately non-recursive. Refusing it by name means
//! the gap is something a reader can act on instead of rediscover.
//!
//! Every constant here is checked against the real type by
//! `tests/conformance.rs`. A descriptor is a claim about `fgit-codec`, and an
//! unchecked claim about someone else's type is prose.

use crate::descriptor::{Cardinality, FieldDescriptor, FieldType, ScalarWidth, SchemaDescriptor};
use crate::error::SchemaRefusal;

/// Domain of the sealed-transaction identity.
const TXN_DOMAIN: &str = "frankengit/ref-txn/v2";
/// Domain of a transaction seal body identity.
const SEAL_DOMAIN: &str = "frankengit/txn-seal/v1";
/// Domain of a Repository Commit Record identity.
const RCR_DOMAIN: &str = "frankengit/rcr/v1";
/// Domain of a decision batch identity.
const BATCH_DOMAIN: &str = "frankengit/decision-batch/v1";
/// Domain of an authority head identity.
const HEAD_DOMAIN: &str = "frankengit/authority-head/v1";
/// Domain of a principal snapshot identity.
const SNAPSHOT_DOMAIN: &str = "frankengit/principal-snapshot/v1";
/// Domain of a repository capsule identity.
const CAPSULE_DOMAIN: &str = "frankengit/repository-capsule/v1";

/// Upper bound the canonical encoder enforces on refusal detail text.
const REFUSAL_DETAIL_MAX: u32 = 4096;

/// A monotone counter field. Every counter in the vocabulary is a `u64`.
const fn counter(name: &'static str, doc: &'static str) -> FieldDescriptor {
    FieldDescriptor {
        name,
        ty: FieldType::Scalar(ScalarWidth::U64),
        cardinality: Cardinality::Required,
        doc,
    }
}

/// A required algorithm-tagged digest, which is what every Merkle root is.
const fn root(name: &'static str, doc: &'static str) -> FieldDescriptor {
    FieldDescriptor {
        name,
        ty: FieldType::Digest,
        cardinality: Cardinality::Required,
        doc,
    }
}

/// A required identity derived through an `InternalObjectId`.
const fn derived(name: &'static str, domain: &'static str, doc: &'static str) -> FieldDescriptor {
    FieldDescriptor {
        name,
        ty: FieldType::DerivedId { domain },
        cardinality: Cardinality::Required,
        doc,
    }
}

/// An optional identity derived through an `InternalObjectId`.
const fn derived_opt(
    name: &'static str,
    domain: &'static str,
    doc: &'static str,
) -> FieldDescriptor {
    FieldDescriptor {
        name,
        ty: FieldType::DerivedId { domain },
        cardinality: Cardinality::Optional,
        doc,
    }
}

/// A required 16-byte assigned identity.
const fn opaque(name: &'static str, doc: &'static str) -> FieldDescriptor {
    FieldDescriptor {
        name,
        ty: FieldType::OpaqueId,
        cardinality: Cardinality::Required,
        doc,
    }
}

/// `frankengit/txn-seal/v1` — the sealed request.
pub static TXN_SEAL: SchemaDescriptor = SchemaDescriptor {
    family: "txn-seal",
    major: 1,
    minor: 0,
    domain: SEAL_DOMAIN,
    doc: "The sealed, immutable statement of one logical mutation request.",
    fields: &[
        derived(
            "tx_id",
            TXN_DOMAIN,
            "Identity of the sealed logical mutation.",
        ),
        opaque("tenant_id", "Owning tenant."),
        opaque("repository_id", "Target repository."),
        opaque(
            "authenticated_principal_id",
            "Principal the gateway authenticated.",
        ),
        root(
            "idempotency_key_digest",
            "Digest of the client's idempotency key.",
        ),
        root(
            "canonical_request_digest",
            "Digest binding every client-visible semantic field of the request.",
        ),
        FieldDescriptor {
            name: "request_schema",
            ty: FieldType::SchemaId,
            cardinality: Cardinality::Required,
            doc: "Schema of the request that was canonicalized.",
        },
    ],
};

/// `frankengit/rcr/v1` — one committed transition.
pub static REPOSITORY_COMMIT_RECORD: SchemaDescriptor = SchemaDescriptor {
    family: "rcr",
    major: 1,
    minor: 0,
    domain: RCR_DOMAIN,
    doc: "The canonical source and forge mutation record for one committed logical transaction.",
    fields: &[
        opaque("repository_id", "Repository the record belongs to."),
        counter(
            "repository_sequence",
            "Position in the committed-transition order.",
        ),
        derived_opt(
            "parent_rcr_id",
            RCR_DOMAIN,
            "Previously committed record, absent only at repository creation.",
        ),
        derived(
            "tx_id",
            TXN_DOMAIN,
            "Sealed transaction this record commits.",
        ),
        derived(
            "principal_snapshot_id",
            SNAPSHOT_DOMAIN,
            "Immutable principal and capability snapshot the decision used.",
        ),
        root(
            "canonical_request_digest",
            "Digest binding the client-visible semantic request.",
        ),
        root(
            "ref_delta_root",
            "Root over the ref changes this record applies.",
        ),
        root("resulting_ref_root", "Root over the resulting ref state."),
        root(
            "object_closure_root",
            "Root over the validated object closure.",
        ),
        root(
            "forge_event_batch_root",
            "Root over the forge events committed with the ref changes.",
        ),
        root(
            "resulting_forge_position_root",
            "Root over the resulting forge position.",
        ),
        counter(
            "policy_epoch",
            "Policy epoch the decision was evaluated under.",
        ),
        root(
            "policy_decision_root",
            "Root over the policy decision evidence.",
        ),
        root(
            "invariant_evidence_root",
            "Root over the invariant evidence.",
        ),
        root(
            "outbox_effect_root",
            "Root over the external-effect obligations this record owes.",
        ),
        root(
            "retention_delta_root",
            "Root over the retention change this record makes.",
        ),
    ],
};

/// `frankengit/authority-head/v1` — the single publication point.
pub static AUTHORITY_HEAD: SchemaDescriptor = SchemaDescriptor {
    family: "authority-head",
    major: 1,
    minor: 0,
    domain: HEAD_DOMAIN,
    doc: "The one value whose conditional replacement publishes repository state.",
    fields: &[
        opaque("repository_id", "Repository this head governs."),
        counter("generation", "Monotone head generation."),
        derived_opt(
            "predecessor_head_id",
            HEAD_DOMAIN,
            "Exact predecessor head, absent only for the genesis head.",
        ),
        derived_opt(
            "decision_tail_id",
            BATCH_DOMAIN,
            "Most recent decision batch, absent before the first decision.",
        ),
        FieldDescriptor {
            name: "latest_decision_sequence",
            ty: FieldType::Scalar(ScalarWidth::U64),
            cardinality: Cardinality::Optional,
            doc: "Latest terminal-decision position, absent before the first decision.",
        },
        derived_opt(
            "latest_committed_rcr_id",
            RCR_DOMAIN,
            "Latest committed record, absent before the first commit.",
        ),
        FieldDescriptor {
            name: "latest_repository_sequence",
            ty: FieldType::Scalar(ScalarWidth::U64),
            cardinality: Cardinality::Optional,
            doc: "Latest committed-transition position, absent before the first commit.",
        },
        root("ref_root", "Root over the current ref state."),
        root(
            "forge_position_root",
            "Root over the current forge position.",
        ),
        root(
            "outcome_index_root",
            "Root over the rebuildable outcome index.",
        ),
        root("retention_root", "Root over the current retention state."),
        root(
            "outbox_root",
            "Root over the current external-effect outbox.",
        ),
        root(
            "configuration_root",
            "Root over the configuration needed to interpret this head.",
        ),
        counter("policy_epoch", "Current policy epoch."),
        counter(
            "format_registry_epoch",
            "Current format and algorithm registry epoch.",
        ),
        derived_opt(
            "last_checkpoint_id",
            CAPSULE_DOMAIN,
            "Most recent checkpoint capsule, when one exists.",
        ),
    ],
};

/// `frankengit/refusal-record/v1` — a terminal refusal.
pub static REFUSAL_RECORD: SchemaDescriptor = SchemaDescriptor {
    family: "refusal-record",
    major: 1,
    minor: 0,
    domain: "frankengit/refusal-record/v1",
    doc: "The terminal record of one refused transaction, with the evidence behind it.",
    fields: &[
        derived("tx_id", TXN_DOMAIN, "Sealed transaction that was refused."),
        derived("seal_id", SEAL_DOMAIN, "Seal the refusal is bound to."),
        counter(
            "decision_sequence",
            "Position in the terminal-decision order.",
        ),
        FieldDescriptor {
            name: "code",
            ty: FieldType::CodePoint {
                vocabulary: "RefusalCode",
            },
            cardinality: Cardinality::Required,
            doc: "Terminal refusal reason, drawn from the closed refusal vocabulary.",
        },
        counter(
            "policy_epoch",
            "Policy epoch the refusal was decided under.",
        ),
        FieldDescriptor {
            name: "detail",
            ty: FieldType::Text {
                max_len: REFUSAL_DETAIL_MAX,
            },
            cardinality: Cardinality::Required,
            doc: "Human-readable detail, bounded by MAX_REFUSAL_DETAIL_LEN.",
        },
        root(
            "evidence_root",
            "Root over the evidence that supports the refusal.",
        ),
    ],
};

/// Every described body, in generation order.
///
/// Generation order is this slice's order, not a sort, so a reordering here is
/// a visible diff in every generated artifact rather than a silent reshuffle.
pub static DESCRIBED: &[&SchemaDescriptor] = &[
    &AUTHORITY_HEAD,
    &REFUSAL_RECORD,
    &REPOSITORY_COMMIT_RECORD,
    &TXN_SEAL,
];

/// A canonical body that exists and is deliberately not described.
struct UndescribedBody {
    family: &'static str,
    construct: &'static str,
}

/// Bodies `fgit-codec` encodes that this format cannot express.
static UNDESCRIBED: &[UndescribedBody] = &[UndescribedBody {
    family: "decision-batch",
    construct: "a sequence of nested structures (decisions, committed_rcrs) and a payload-carrying tagged union (DecisionOutcome)",
}];

/// The descriptor for a schema family.
///
/// Three outcomes, and the middle one is the point: a family this crate knows
/// about but cannot describe refuses with the reason, so "not described" never
/// reads as "has no fields".
pub fn descriptor_for(family: &str) -> Result<&'static SchemaDescriptor, SchemaRefusal> {
    if let Some(found) = DESCRIBED.iter().find(|entry| entry.family == family) {
        return Ok(found);
    }
    if let Some(known) = UNDESCRIBED.iter().find(|entry| entry.family == family) {
        return Err(SchemaRefusal::ShapeUnsupported {
            family: family.into(),
            construct: known.construct,
        });
    }
    Err(SchemaRefusal::FamilyUnregistered {
        family: family.into(),
    })
}

/// Refuses if two descriptors in `descriptors` claim the same family.
///
/// Takes the slice rather than reading [`DESCRIBED`] directly so a test can
/// hand it a duplicate. A guard that can only ever be run against known-good
/// input cannot be shown to fire, and an unfireable guard is decoration.
pub fn check_families_unique_in(
    descriptors: &[&'static SchemaDescriptor],
) -> Result<(), SchemaRefusal> {
    for (index, entry) in descriptors.iter().enumerate() {
        if descriptors[..index]
            .iter()
            .any(|earlier| earlier.family == entry.family)
        {
            return Err(SchemaRefusal::FamilyDuplicated {
                family: entry.family.into(),
            });
        }
    }
    Ok(())
}

/// Refuses if two registered descriptors claim the same family.
///
/// `descriptor_for` takes the first match, so a duplicate family would make
/// resolution depend on slice order — which §5.3 forbids for exactly this
/// reason. Checked rather than assumed, because the failure would be a
/// silently wrong artifact rather than an error.
pub fn check_families_unique() -> Result<(), SchemaRefusal> {
    check_families_unique_in(DESCRIBED)
}
