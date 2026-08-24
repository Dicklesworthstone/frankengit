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

use crate::descriptor::{
    Cardinality, FieldDescriptor, FieldType, ScalarWidth, SchemaDescriptor, StructureDescriptor,
    UnionDescriptor, UnionVariant,
};
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
/// Domain of a refusal record identity.
const REFUSAL_DOMAIN: &str = "frankengit/refusal-record/v1";

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

/// An optional algorithm-tagged digest, behind a presence tag.
const fn root_opt(name: &'static str, doc: &'static str) -> FieldDescriptor {
    FieldDescriptor {
        name,
        ty: FieldType::Digest,
        cardinality: Cardinality::Optional,
        doc,
    }
}

/// A counted repetition of a referenced structure.
const fn many(name: &'static str, structure: &'static str, doc: &'static str) -> FieldDescriptor {
    FieldDescriptor {
        name,
        ty: FieldType::Structure { name: structure },
        cardinality: Cardinality::Sequence,
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

// ------------------------------------------------- nested structures + unions

/// `DecisionOutcome` — one raw discriminant byte, then the variant's fields.
pub static DECISION_OUTCOME: UnionDescriptor = UnionDescriptor {
    name: "decision-outcome",
    doc: "The terminal outcome of one decision: committed, or refused with a reason.",
    variants: &[
        UnionVariant {
            name: "Committed",
            discriminant: 1,
            doc: "The decision committed, naming the record it produced.",
            fields: &[derived(
                "repository_commit_id",
                RCR_DOMAIN,
                "The Repository Commit Record this decision produced.",
            )],
        },
        UnionVariant {
            name: "Refused",
            discriminant: 2,
            doc: "The decision was refused, naming the reason and the evidence record.",
            fields: &[
                FieldDescriptor {
                    name: "code",
                    ty: FieldType::CodePoint {
                        vocabulary: "RefusalCode",
                    },
                    cardinality: Cardinality::Required,
                    doc: "Terminal refusal reason, from the closed refusal vocabulary.",
                },
                derived(
                    "refusal_record_id",
                    REFUSAL_DOMAIN,
                    "The refusal record carrying the evidence.",
                ),
            ],
        },
    ],
};

/// `RepositoryDecision` — encoded only inside a decision batch.
pub static REPOSITORY_DECISION: StructureDescriptor = StructureDescriptor {
    name: "repository-decision",
    doc: "One terminal decision within a batch, in the batch's own order.",
    fields: &[
        derived(
            "tx_id",
            TXN_DOMAIN,
            "Sealed transaction the decision belongs to.",
        ),
        counter(
            "decision_sequence",
            "Position in the terminal-decision order, refusals included.",
        ),
        FieldDescriptor {
            name: "outcome",
            ty: FieldType::Union {
                name: "decision-outcome",
            },
            cardinality: Cardinality::Required,
            doc: "The terminal outcome.",
        },
    ],
};

/// Every nested structure, by name.
pub static STRUCTURES: &[&StructureDescriptor] = &[&REPOSITORY_DECISION];

/// Every union, by name.
pub static UNIONS: &[&UnionDescriptor] = &[&DECISION_OUTCOME];

/// The fields a `Structure` reference resolves to.
///
/// Resolves against BOTH registries on purpose: `committed_rcrs` references the
/// `rcr` canonical body, and `decisions` references a nested structure. A
/// reference is always by name, never an inline copy, so the referenced
/// definition and its standalone use cannot drift apart.
#[must_use]
pub fn structure_fields(name: &str) -> Option<&'static [FieldDescriptor]> {
    if let Some(found) = STRUCTURES.iter().find(|entry| entry.name == name) {
        return Some(found.fields);
    }
    DESCRIBED
        .iter()
        .find(|entry| entry.family == name)
        .map(|entry| entry.fields)
}

/// The union descriptor a `Union` reference resolves to.
#[must_use]
pub fn union_for(name: &str) -> Option<&'static UnionDescriptor> {
    UNIONS.iter().copied().find(|entry| entry.name == name)
}

/// `frankengit/decision-batch/v1` — one publication's worth of decisions.
pub static DECISION_BATCH: SchemaDescriptor = SchemaDescriptor {
    family: "decision-batch",
    major: 1,
    minor: 1,
    domain: BATCH_DOMAIN,
    doc: "The batch of terminal decisions published against one authority head.",
    fields: &[
        opaque("repository_id", "Repository the batch belongs to."),
        derived(
            "predecessor_head_id",
            HEAD_DOMAIN,
            "Head this batch was prepared against.",
        ),
        counter(
            "predecessor_head_generation",
            "Generation of that head, which makes the basis check monotone.",
        ),
        counter(
            "first_decision_sequence",
            "Decision-sequence position of the first decision in the batch.",
        ),
        // Decision order is SEMANTIC, not incidental: each decision is
        // evaluated against the prior ones in the same batch, so this is one
        // of the few sequences a normalizer must never sort.
        many(
            "decisions",
            "repository-decision",
            "Terminal decisions, in deterministic batch order.",
        ),
        many(
            "committed_rcrs",
            "rcr",
            "Commit records for the committed decisions, in repository order.",
        ),
        root("resulting_ref_root", "Root over the resulting ref state."),
        root(
            "resulting_forge_position_root",
            "Root over the resulting forge position.",
        ),
        root(
            "resulting_outcome_index_root",
            "Root over the rebuildable outcome index.",
        ),
        root(
            "resulting_retention_root",
            "Root over the resulting retention state.",
        ),
        root(
            "resulting_outbox_root",
            "Root over the resulting external-effect outbox.",
        ),
        counter("resulting_policy_epoch", "Policy epoch after the batch."),
        root(
            "batch_evidence_root",
            "Merkle commitment over this batch's ordered decision evidence.",
        ),
        root_opt(
            "compaction_generation_link",
            "Compaction generation bound by this publication, when it publishes one.",
        ),
    ],
};

/// Every described body, in generation order.
///
/// Generation order is this slice's order, not a sort, so a reordering here is
/// a visible diff in every generated artifact rather than a silent reshuffle.
pub static DESCRIBED: &[&SchemaDescriptor] = &[
    &AUTHORITY_HEAD,
    &DECISION_BATCH,
    &REFUSAL_RECORD,
    &REPOSITORY_COMMIT_RECORD,
    &TXN_SEAL,
];

/// A canonical body that exists and is deliberately not described.
///
/// Public so a test can build one. With the shipped table empty this is the
/// only way the `ShapeUnsupported` arm can be driven at all.
pub struct UndescribedBody {
    /// The family whose body this format cannot express.
    pub family: &'static str,
    /// The exact construct that is missing, named in the refusal.
    pub construct: &'static str,
}

/// Bodies `fgit-codec` encodes that this format cannot express.
///
/// EMPTY as of `3xom`: describing `decision-batch` removed the last entry.
/// The table is kept rather than deleted because it is the seam where the
/// next undescribable body registers, and because an empty table plus a
/// reachable arm is honest where a deleted arm would silently reclassify
/// such a body as "unregistered".
pub static UNDESCRIBED: &[UndescribedBody] = &[];

// Every canonical body `fgit-codec` encodes is now described. The table above
// is deliberately kept rather than deleted: the NEXT body the codec adds is
// undescribable until someone describes it, and an empty table with a live
// refusal path is what makes that a typed refusal instead of a panic. The
// refusal is still reachable and still tested -- see
// `tests/workflow.rs`'s sibling in `tests/refusals.rs`.

/// The descriptor for a schema family.
///
/// Three outcomes, and the middle one is the point: a family this crate knows
/// about but cannot describe refuses with the reason, so "not described" never
/// reads as "has no fields".
pub fn descriptor_for(family: &str) -> Result<&'static SchemaDescriptor, SchemaRefusal> {
    descriptor_for_in(family, DESCRIBED, UNDESCRIBED)
}

/// `descriptor_for` over supplied tables.
///
/// This exists so the `ShapeUnsupported` arm stays reachable. `UNDESCRIBED` is
/// empty, so through `descriptor_for` that arm cannot fire, and a refusal that
/// cannot fire is decoration rather than behaviour. A test supplies a
/// non-empty table here and drives it.
pub fn descriptor_for_in(
    family: &str,
    described: &[&'static SchemaDescriptor],
    undescribed: &[UndescribedBody],
) -> Result<&'static SchemaDescriptor, SchemaRefusal> {
    if let Some(found) = described.iter().find(|entry| entry.family == family) {
        return Ok(found);
    }
    if let Some(known) = undescribed.iter().find(|entry| entry.family == family) {
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
/// Every `Structure`/`Union` reference resolves, over supplied tables.
///
/// Takes the tables so the refusal can be driven by a test. A gate whose
/// failure path has never been observed is a claim, not a check.
pub fn check_references_resolve_in(
    described: &[&'static SchemaDescriptor],
    structures: &[&'static StructureDescriptor],
    unions: &[&'static UnionDescriptor],
) -> Result<(), SchemaRefusal> {
    // Bodies, nested structures and union variants all carry fields, and a
    // reference in any of them ends up in the artifacts. Checking only the
    // bodies would leave a nested structure free to reference a ghost.
    let mut groups: Vec<(&str, &[FieldDescriptor])> = described
        .iter()
        .map(|entry| (entry.family, entry.fields))
        .collect();
    groups.extend(
        structures
            .iter()
            .map(|structure| (structure.name, structure.fields)),
    );
    for union in unions {
        groups.extend(
            union
                .variants
                .iter()
                .map(|variant| (union.name, variant.fields)),
        );
    }

    for (owner, fields) in groups {
        for field in fields {
            // Resolve first, refuse once. Each arm answers only "does this
            // name resolve, and in which registry", so the two resolution
            // rules stay adjacent and there is a single refusal site.
            let unresolved = match field.ty {
                // A structure reference may name a nested structure OR a
                // canonical body: `committed_rcrs` names the `rcr` body.
                FieldType::Structure { name } => {
                    (!structures.iter().any(|entry| entry.name == name)
                        && !described.iter().any(|entry| entry.family == name))
                    .then_some(("structure", name))
                }
                FieldType::Union { name } => {
                    (!unions.iter().any(|entry| entry.name == name)).then_some(("union", name))
                }
                _ => None,
            };
            if let Some((container, name)) = unresolved {
                return Err(SchemaRefusal::ReferenceUnresolved {
                    owner: owner.into(),
                    name: name.into(),
                    container,
                });
            }
        }
    }
    Ok(())
}

/// Every `Structure`/`Union` reference in the shipped registry resolves.
pub fn check_references_resolve() -> Result<(), SchemaRefusal> {
    check_references_resolve_in(DESCRIBED, STRUCTURES, UNIONS)
}

pub fn check_families_unique() -> Result<(), SchemaRefusal> {
    check_families_unique_in(DESCRIBED)
}
