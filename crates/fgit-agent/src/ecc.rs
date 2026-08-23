//! Evidence-Carrying Change: evidence classes, requirement dispositions, and
//! machine-classified verifier independence
//! (`docs/AGENT_PROTOCOL.md` §10–§11, `NORMATIVE_PROTOCOL_CONTRACTS.md` §28).
//!
//! # The one property this module exists to hold
//!
//! **Independence is enforced, not self-declared.** Normative contract 25 states
//! it in those words, and it is the whole reason [`VerifierAttestation`] carries
//! *facts* rather than a class: a verifier says which workspace, credentials,
//! harness, context, oracle, sponsor and human oversight it ran under, and
//! [`classify_independence`] derives the class by comparing those against the
//! producer's. There is no constructor that lets a verifier assert
//! "independent", because a protocol whose central anti-collusion control is a
//! self-report has no control at all.
//!
//! # Seven dimensions, and why not six
//!
//! `NORMATIVE_PROTOCOL_CONTRACTS.md` §28 classifies independence over
//! "workspace, credentials, model/harness, context, oracle, **sponsor**, and
//! human dimensions" — seven. AGENTS.md §9 lists the same set without sponsor.
//! The normative contract ranks above the contributor guide in §2's hierarchy
//! and this bead's own acceptance names seven, so seven is what
//! [`IndependenceDimension`] carries. The omission in AGENTS.md §9 looks like an
//! abbreviation rather than a competing rule, but it is recorded here so the
//! next reader does not treat six as the settled number.
//!
//! Sponsor is not redundant with credentials. Two verifiers can hold distinct
//! credentials issued under one sponsor, which is exactly the arrangement where
//! a sponsor-level compromise defeats credential separation.
//!
//! # What this slice deliberately does not carry
//!
//! §10's bundle names eighteen fields. This module carries the ones its
//! acceptance enforces — evidence records with classes, requirement
//! dispositions, non-claims, omissions, and verifier attestations — and carries
//! nothing it does not check. Per [`crate::intent`]'s rule, a field present but
//! unenforced reads as a control that exists.
//!
//! Absent by scope, not by oversight: the proposed object/tree closure and diff
//! commitment (they need the `TreeFS` export of §8), the refreshed authority
//! receipt and reconciliation record (§4.3 refresh relations), context-packet
//! *bodies* (§7 owns those; only their ids are bound here), and codec goldens
//! for the bundle. Each is a real part of §10 that this slice does not deliver.

use core::fmt;

use fgit_codec::{CanonicalBody, CodecRefusal, Decoder, Encoder};
use fgit_types::{DomainTag, SchemaFamily};

/// How a claim in an Evidence-Carrying Change was arrived at (§10.1).
///
/// The classes are structurally distinct rather than a severity ladder: an
/// omission is not a weak observation, and an unresolved question is not a
/// failed inference. §10.1's rule that *"'all tests pass' is a summary, not
/// evidence"* is why [`Self::Executed`] exists separately from
/// [`Self::Observed`] — running a check and reading its receipt are different
/// acts with different replay properties.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EvidenceClass {
    /// Read directly from an artifact that already existed.
    Observed,
    /// Produced by running a named command and capturing its receipt.
    Executed,
    /// Derived by reasoning over other evidence, without a run of its own.
    Inferred,
    /// Supported by a sample with a stated population and regime (§8 of
    /// AGENTS.md binds those fields; this class only marks the kind).
    Statistical,
    /// Deliberately not gathered, with the reason recorded.
    Omitted,
    /// A question the producer raised and could not settle.
    Unresolved,
}

impl EvidenceClass {
    /// Every class, for exhaustive policy checks.
    pub const ALL: &'static [Self] = &[
        Self::Observed,
        Self::Executed,
        Self::Inferred,
        Self::Statistical,
        Self::Omitted,
        Self::Unresolved,
    ];

    /// Stable wire/report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Executed => "executed",
            Self::Inferred => "inferred",
            Self::Statistical => "statistical",
            Self::Omitted => "omitted",
            Self::Unresolved => "unresolved",
        }
    }

    /// Stable wire code point.
    ///
    /// Assigned explicitly rather than taken from the declaration order, so
    /// inserting a class in the middle of the enum cannot silently renumber
    /// the ones after it and reinterpret already-encoded bundles.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::Observed => 1,
            Self::Executed => 2,
            Self::Inferred => 3,
            Self::Statistical => 4,
            Self::Omitted => 5,
            Self::Unresolved => 6,
        }
    }

    /// The class a code point names, or `None` for one this build does not
    /// define.
    ///
    /// An unknown class is refused rather than mapped to a default: a decoder
    /// that guessed would silently reclassify evidence it does not understand,
    /// which is the one thing this type exists to prevent.
    #[must_use]
    pub const fn from_code_point(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::Observed),
            2 => Some(Self::Executed),
            3 => Some(Self::Inferred),
            4 => Some(Self::Statistical),
            5 => Some(Self::Omitted),
            6 => Some(Self::Unresolved),
            _ => None,
        }
    }

    /// Whether this class asserts support for a claim.
    ///
    /// [`Self::Omitted`] and [`Self::Unresolved`] record the *absence* of
    /// support. A policy that requires evidence for a claim is not satisfied by
    /// a record saying the evidence was skipped, and this predicate is what
    /// keeps that distinction machine-checkable instead of editorial.
    #[must_use]
    pub const fn supports_a_claim(self) -> bool {
        matches!(
            self,
            Self::Observed | Self::Executed | Self::Inferred | Self::Statistical
        )
    }
}

impl fmt::Display for EvidenceClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The disposition of one acceptance requirement (§10.2).
///
/// §10.2 requires each requirement to be *exactly one* of these, and adds that
/// "missing requirements cannot disappear from a generated summary". The
/// absence of a default is deliberate: there is no value meaning "not yet
/// considered", so a requirement with no disposition is a construction error
/// rather than a silently empty row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RequirementDisposition {
    /// Met, with evidence bound.
    SatisfiedWithEvidence,
    /// Met in part, with the boundary stated explicitly.
    PartiallySatisfied,
    /// Does not apply, with the reason stated.
    NotApplicable,
    /// Prevented by a typed refusal.
    BlockedByRefusal,
    /// Not met.
    Unsatisfied,
}

impl RequirementDisposition {
    /// Stable wire code point, assigned explicitly (see
    /// [`EvidenceClass::code_point`] for why).
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::SatisfiedWithEvidence => 1,
            Self::PartiallySatisfied => 2,
            Self::NotApplicable => 3,
            Self::BlockedByRefusal => 4,
            Self::Unsatisfied => 5,
        }
    }

    /// The disposition a code point names, or `None` for an unknown one.
    #[must_use]
    pub const fn from_code_point(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::SatisfiedWithEvidence),
            2 => Some(Self::PartiallySatisfied),
            3 => Some(Self::NotApplicable),
            4 => Some(Self::BlockedByRefusal),
            5 => Some(Self::Unsatisfied),
            _ => None,
        }
    }

    /// Stable wire/report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SatisfiedWithEvidence => "satisfied_with_evidence",
            Self::PartiallySatisfied => "partially_satisfied",
            Self::NotApplicable => "not_applicable",
            Self::BlockedByRefusal => "blocked_by_refusal",
            Self::Unsatisfied => "unsatisfied",
        }
    }
}

impl fmt::Display for RequirementDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One axis along which a verifier can fail to be independent of a producer
/// (`NORMATIVE_PROTOCOL_CONTRACTS.md` §28).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum IndependenceDimension {
    /// Same mutable workspace: the verifier can see or be affected by
    /// uncommitted producer state.
    Workspace,
    /// Same credentials or effect authority.
    Credentials,
    /// Same model or harness, so a shared blind spot is shared.
    ModelHarness,
    /// Same supplied context or hidden state.
    Context,
    /// Same oracle or toolchain, so a wrong oracle agrees with itself.
    Oracle,
    /// Same sponsor. Distinct credentials under one sponsor still share the
    /// authority that issued them.
    Sponsor,
    /// Same human oversight.
    Human,
}

impl IndependenceDimension {
    /// Stable wire code point, assigned explicitly (see
    /// [`EvidenceClass::code_point`] for why).
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::Workspace => 1,
            Self::Credentials => 2,
            Self::ModelHarness => 3,
            Self::Context => 4,
            Self::Oracle => 5,
            Self::Sponsor => 6,
            Self::Human => 7,
        }
    }

    /// The dimension a code point names, or `None` for an unknown one.
    #[must_use]
    pub const fn from_code_point(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::Workspace),
            2 => Some(Self::Credentials),
            3 => Some(Self::ModelHarness),
            4 => Some(Self::Context),
            5 => Some(Self::Oracle),
            6 => Some(Self::Sponsor),
            7 => Some(Self::Human),
            _ => None,
        }
    }

    /// Every dimension, in the order the normative contract lists them.
    pub const ALL: &'static [Self] = &[
        Self::Workspace,
        Self::Credentials,
        Self::ModelHarness,
        Self::Context,
        Self::Oracle,
        Self::Sponsor,
        Self::Human,
    ];

    /// Stable wire/report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Credentials => "credentials",
            Self::ModelHarness => "model_harness",
            Self::Context => "context",
            Self::Oracle => "oracle",
            Self::Sponsor => "sponsor",
            Self::Human => "human",
        }
    }
}

impl fmt::Display for IndependenceDimension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The identities a party ran under, one per independence dimension.
///
/// These are opaque handles, compared only for equality. The module makes no
/// attempt to decide what "the same workspace" means in the filesystem — that
/// belongs to whoever mints the handles — but it does insist that the question
/// be answered by comparing two recorded values rather than by either party's
/// opinion of its own independence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PartyFacts {
    /// Mutable workspace identity.
    pub workspace: u128,
    /// Credential / effect-authority identity.
    pub credentials: u128,
    /// Model or harness identity.
    pub model_harness: u128,
    /// Supplied-context identity.
    pub context: u128,
    /// Oracle / toolchain identity.
    pub oracle: u128,
    /// Sponsor identity.
    pub sponsor: u128,
    /// Human-oversight identity.
    pub human: u128,
}

impl PartyFacts {
    /// The identity this party ran under along one dimension.
    #[must_use]
    pub const fn on(&self, dimension: IndependenceDimension) -> u128 {
        match dimension {
            IndependenceDimension::Workspace => self.workspace,
            IndependenceDimension::Credentials => self.credentials,
            IndependenceDimension::ModelHarness => self.model_harness,
            IndependenceDimension::Context => self.context,
            IndependenceDimension::Oracle => self.oracle,
            IndependenceDimension::Sponsor => self.sponsor,
            IndependenceDimension::Human => self.human,
        }
    }
}

/// A verifier's attestation: who verified, under what facts, and what they found.
///
/// There is deliberately no `independence` field. See the module header — a
/// self-declared class is not a control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifierAttestation {
    /// Verifier identity.
    pub verifier: u128,
    /// The facts the verifier ran under, for classification.
    pub facts: PartyFacts,
    /// Whether the verifier's own checks passed.
    pub upheld: bool,
}

/// The computed independence of one verifier from the producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndependenceClassification {
    /// The verifier this classifies.
    pub verifier: u128,
    /// Dimensions on which producer and verifier shared an identity, in the
    /// canonical order of [`IndependenceDimension::ALL`].
    pub shared: Vec<IndependenceDimension>,
}

impl IndependenceClassification {
    /// True only when no dimension is shared.
    #[must_use]
    pub const fn is_fully_independent(&self) -> bool {
        self.shared.is_empty()
    }

    /// Whether the verifier is independent along one specific dimension.
    #[must_use]
    pub fn is_independent_on(&self, dimension: IndependenceDimension) -> bool {
        !self.shared.contains(&dimension)
    }
}

/// Classifies a verifier's independence by comparing recorded facts.
///
/// This is the enforcement point for normative contract 25. It cannot be
/// bypassed by an attestation claiming independence, because no such field
/// exists to claim it with.
#[must_use]
pub fn classify_independence(
    producer: &PartyFacts,
    attestation: &VerifierAttestation,
) -> IndependenceClassification {
    let shared = IndependenceDimension::ALL
        .iter()
        .copied()
        .filter(|dimension| producer.on(*dimension) == attestation.facts.on(*dimension))
        .collect();
    IndependenceClassification {
        verifier: attestation.verifier,
        shared,
    }
}

/// Why a publication policy refused an Evidence-Carrying Change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EccRefusal {
    /// A required evidence class is absent from the bundle.
    MissingEvidenceClass {
        /// The class the policy required.
        required: EvidenceClass,
    },
    /// The policy named a class that records the absence of support
    /// (`Omitted` or `Unresolved`) as a *required* evidence class.
    ///
    /// Separate from [`Self::MissingEvidenceClass`] because the remedies
    /// differ, and they sit on opposite sides of the bundle/policy line: a
    /// missing class means the bundle forgot to gather evidence and the fix is
    /// to gather it, while this means the policy would accept a note saying
    /// evidence was skipped. Gathering more evidence never satisfies it.
    UnsupportedEvidenceClass {
        /// The class the policy required.
        required: EvidenceClass,
    },
    /// A requirement carries no disposition, which §10.2 forbids.
    RequirementWithoutDisposition {
        /// Index of the offending requirement.
        requirement: usize,
    },
    /// Policy demanded independence on a dimension the verifier shares.
    VerifierNotIndependent {
        /// The verifier that failed the check.
        verifier: u128,
        /// The first required dimension found to be shared.
        dimension: IndependenceDimension,
    },
    /// Policy demanded at least one verifier and the bundle carries none.
    NoVerifierAttestation,
}

impl fmt::Display for EccRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEvidenceClass { required } => {
                write!(formatter, "no {required} evidence in the change")
            }
            Self::UnsupportedEvidenceClass { required } => write!(
                formatter,
                "policy requires {required} evidence, which records absence of support"
            ),
            Self::RequirementWithoutDisposition { requirement } => write!(
                formatter,
                "acceptance requirement {requirement} carries no disposition"
            ),
            Self::VerifierNotIndependent {
                verifier,
                dimension,
            } => write!(
                formatter,
                "verifier {verifier:032x} shares {dimension} with the producer"
            ),
            Self::NoVerifierAttestation => {
                formatter.write_str("policy requires a verifier attestation and none is present")
            }
        }
    }
}

impl core::error::Error for EccRefusal {}

/// One evidence record's classification and the claim it supports (§10.1).
///
/// The full §10.1 record has eleven fields. This slice binds the two the
/// publication policy evaluates; the rest belong with the codec slice that
/// serialises them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceRecordRef {
    /// How this evidence was arrived at.
    pub class: EvidenceClass,
    /// Identity of the artifact or receipt the record points at.
    pub artifact: u128,
}

/// The publication policy an Evidence-Carrying Change is evaluated against.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct EccPolicy {
    /// Evidence classes that must be present AND supporting.
    pub required_classes: Vec<EvidenceClass>,
    /// Dimensions on which at least one verifier must be independent.
    pub required_independence: Vec<IndependenceDimension>,
    /// Whether any verifier attestation is required at all.
    pub requires_verifier: bool,
}

/// The bundle a producer submits for publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceCarryingChange {
    /// The run that produced it.
    pub intent_run: u128,
    /// Facts the producer ran under, for independence classification.
    pub producer: PartyFacts,
    /// Evidence records, each classified.
    pub evidence: Vec<EvidenceRecordRef>,
    /// One disposition per acceptance requirement, positionally.
    pub requirement_dispositions: Vec<Option<RequirementDisposition>>,
    /// Claims the producer explicitly does NOT make (§10.3).
    pub non_claims: Vec<u128>,
    /// Verifier attestations, unclassified as submitted.
    pub verifiers: Vec<VerifierAttestation>,
}

impl EvidenceCarryingChange {
    /// Evaluates the change against a publication policy.
    ///
    /// # Errors
    ///
    /// Returns the first [`EccRefusal`] the change violates. Checks run in a
    /// fixed order — dispositions, then evidence classes, then verifiers — so
    /// a bundle wrong in several ways reports the same refusal on every run.
    pub fn evaluate(
        &self,
        policy: &EccPolicy,
    ) -> Result<Vec<IndependenceClassification>, EccRefusal> {
        for (requirement, disposition) in self.requirement_dispositions.iter().enumerate() {
            if disposition.is_none() {
                return Err(EccRefusal::RequirementWithoutDisposition { requirement });
            }
        }

        for required in &policy.required_classes {
            // Policy coherence first. `Omitted` and `Unresolved` record the
            // *absence* of support, so a policy naming one as a required class
            // is asking for absence as if it were evidence -- and a bundle that
            // dutifully carried the matching row would satisfy the presence
            // check below and publish on a note saying evidence was skipped.
            if !required.supports_a_claim() {
                return Err(EccRefusal::UnsupportedEvidenceClass {
                    required: *required,
                });
            }
            let present = self.evidence.iter().any(|record| record.class == *required);
            if !present {
                return Err(EccRefusal::MissingEvidenceClass {
                    required: *required,
                });
            }
        }

        if policy.requires_verifier && self.verifiers.is_empty() {
            return Err(EccRefusal::NoVerifierAttestation);
        }

        let classifications: Vec<IndependenceClassification> = self
            .verifiers
            .iter()
            .map(|attestation| classify_independence(&self.producer, attestation))
            .collect();

        for dimension in &policy.required_independence {
            let satisfied = classifications
                .iter()
                .any(|classification| classification.is_independent_on(*dimension));
            if !satisfied {
                let offender = classifications
                    .first()
                    .map_or(0, |classification| classification.verifier);
                return Err(EccRefusal::VerifierNotIndependent {
                    verifier: offender,
                    dimension: *dimension,
                });
            }
        }

        Ok(classifications)
    }
}

/// The canonical byte encoding of an Evidence-Carrying Change.
///
/// # Payload layout, version 1
///
/// This table is the specification. The golden corpus under
/// `crates/fgit-agent/tests/goldens/` is generated from *this table* by a
/// separate Python implementation that cannot link this crate, so the corpus
/// checks the encoder against its documented format rather than against
/// itself. See that directory's `README.md` for exactly how far that
/// independence reaches — it is narrower than the codec corpus's, and the
/// README says so rather than borrowing the stronger claim.
///
/// Every identity is a 16-byte opaque id, which is [`fgit_types::identity::OPAQUE_ID_LEN`] and
/// exactly the width of the `u128` these fields hold, so the mapping is
/// `u128::to_be_bytes` with nothing invented. The codec's scalar trait is
/// sealed at 64 bits and deliberately admits no `u128`; an identity is not a
/// number to it, and encoding one as a pair of scalars would have been a
/// worse fit than the opaque id the codec already defines for this.
///
/// ```text
/// intent_run                16 bytes
/// producer                  7 x 16 bytes, in IndependenceDimension::ALL order:
///                             workspace, credentials, model_harness,
///                             context, oracle, sponsor, human
/// evidence                  u32 count, then per record:
///                             u16 class code point
///                             16 bytes artifact id
/// requirement_dispositions  u32 count, then per requirement:
///                             u8  0x00 = no disposition
///                                 0x01 = present, followed by u16 code point
/// non_claims                u32 count, then 16 bytes each
/// verifiers                 u32 count, then per attestation:
///                             16 bytes verifier id
///                             7 x 16 bytes facts, same order as producer
///                             u8 upheld (0x00 / 0x01)
/// ```
///
/// # Why the dispositions keep their `None`
///
/// §10.2 says a missing requirement "cannot disappear from a generated
/// summary". An absent disposition is therefore encoded as a present option
/// tag, not by shortening the sequence: the count is the number of acceptance
/// requirements, and a bundle that forgot one round-trips as a bundle that
/// forgot one. Dropping the empty slots would make the wire form of an
/// incomplete change indistinguishable from a complete shorter one, which is
/// the exact failure §10.2 names.
impl CanonicalBody for EvidenceCarryingChange {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/evidence-carrying-change/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("evidence-carrying-change");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(&self.intent_run.to_be_bytes());
        write_party_facts(out, &self.producer);

        out.write_sequence("evidence", &self.evidence, |out, record| {
            out.write_scalar(record.class.code_point());
            out.write_opaque_id(&record.artifact.to_be_bytes());
            Ok(())
        })?;

        out.write_sequence(
            "requirement_dispositions",
            &self.requirement_dispositions,
            |out, disposition| {
                out.write_option(disposition.as_ref(), |out, disposition| {
                    out.write_scalar(disposition.code_point());
                    Ok(())
                })
            },
        )?;

        out.write_sequence("non_claims", &self.non_claims, |out, non_claim| {
            out.write_opaque_id(&non_claim.to_be_bytes());
            Ok(())
        })?;

        out.write_sequence("verifiers", &self.verifiers, |out, attestation| {
            out.write_opaque_id(&attestation.verifier.to_be_bytes());
            write_party_facts(out, &attestation.facts);
            out.write_bool(attestation.upheld);
            Ok(())
        })
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let intent_run = read_identity(input, "intent_run")?;
        let producer = read_party_facts(input, "producer")?;

        let evidence = input.read_sequence("evidence", |input| {
            let offset = input.offset();
            let code = input.read_scalar::<u16>("evidence.class")?;
            let class = EvidenceClass::from_code_point(code).ok_or_else(|| {
                CodecRefusal::VariantUnknown {
                    field: "evidence.class",
                    observed: u32::from(code),
                    offset,
                }
            })?;
            Ok(EvidenceRecordRef {
                class,
                artifact: read_identity(input, "evidence.artifact")?,
            })
        })?;

        let requirement_dispositions =
            input.read_sequence("requirement_dispositions", |input| {
                input.read_option("requirement_dispositions", |input| {
                    let offset = input.offset();
                    let code = input.read_scalar::<u16>("requirement_dispositions.disposition")?;
                    RequirementDisposition::from_code_point(code).ok_or_else(|| {
                        CodecRefusal::VariantUnknown {
                            field: "requirement_dispositions.disposition",
                            observed: u32::from(code),
                            offset,
                        }
                    })
                })
            })?;

        let non_claims =
            input.read_sequence("non_claims", |input| read_identity(input, "non_claims"))?;

        let verifiers = input.read_sequence("verifiers", |input| {
            Ok(VerifierAttestation {
                verifier: read_identity(input, "verifiers.verifier")?,
                facts: read_party_facts(input, "verifiers.facts")?,
                upheld: input.read_bool("verifiers.upheld")?,
            })
        })?;

        Ok(Self {
            intent_run,
            producer,
            evidence,
            requirement_dispositions,
            non_claims,
            verifiers,
        })
    }
}

/// Writes the seven identities of a party in `IndependenceDimension::ALL` order.
///
/// Driven from `ALL` rather than field by field, so a dimension added to the
/// enum is encoded rather than silently dropped from the wire form while the
/// classifier still compares it.
fn write_party_facts(out: &mut Encoder, facts: &PartyFacts) {
    for dimension in IndependenceDimension::ALL {
        out.write_opaque_id(&facts.on(*dimension).to_be_bytes());
    }
}

fn read_party_facts(
    input: &mut Decoder<'_>,
    field: &'static str,
) -> Result<PartyFacts, CodecRefusal> {
    Ok(PartyFacts {
        workspace: read_identity(input, field)?,
        credentials: read_identity(input, field)?,
        model_harness: read_identity(input, field)?,
        context: read_identity(input, field)?,
        oracle: read_identity(input, field)?,
        sponsor: read_identity(input, field)?,
        human: read_identity(input, field)?,
    })
}

fn read_identity(input: &mut Decoder<'_>, field: &'static str) -> Result<u128, CodecRefusal> {
    Ok(u128::from_be_bytes(input.read_opaque_id(field)?))
}
