//! Authority-head-bound verified reads served by [`super::OneNode`].
//!
//! The response is deliberately built from one [`MaterializedAdmission`] rather
//! than a current-head read followed by a convenient lookup.  A later read can
//! observe a different authority generation and create a proof whose answer and
//! root describe different repository moments.  Snapshot reads take an issued
//! head receipt, authenticate it again against this node's authority store, and
//! materialize precisely that authenticated body.

use core::fmt;

use fgit_authority::{
    AsyncAuthorityStore, AuthorityFailure, HeadBodyRefusal, HeadReadReceipt, OutcomeFailure,
    RepositoryIncarnationConfigurationEvidence, TerminalOutcome, authority_head_identity,
    next_batch_to_replay, outcome_index_proof, outcome_index_root, read_authority_head_body_async,
    read_decision_batch_body_async, read_repository_configuration_async,
    read_repository_incarnation_configuration_evidence_async,
};
use fgit_chronicle::PublicationBasis;
use fgit_crypto::{
    ObjectClosureNonMembershipProof, object_closure_membership_proof,
    object_closure_non_membership_proof, ref_state_membership_proof,
    ref_state_non_membership_proof,
};
use fgit_types::cell::{CellRefusal, ReadLabel, ReadMode, ServingCell, admits_read};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::GitOid;
use fgit_types::{Digest, RefName, TxId};
use fgit_verified_read::{
    ObjectDisclosurePolicy, ReadResponse, RefDisclosurePolicy, UnprovenReadAnswer,
    VerifiedReadAnswer, VerifiedReadCapability, VerifiedReadConfiguration, VerifiedReadEnvelope,
    VerifiedReadRefusal, authorize_object_absence, authorize_ref_absence, negotiate_response_mode,
};
use fgit_wire::visibility::RefVisibility;

use super::{AdmissionMaterializationRefusal, MaterializedAdmission, NodeRequestContext, OneNode};

/// One question that the [`OneNode`] verified-read serving path understands.
///
/// Forge-position questions remain intentionally absent: forge-position proof
/// generation is gated on canonical forge Merkle materialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedReadQuery {
    /// Answer one ref membership or authorization-gated absence question.
    Ref(RefName),
    /// Answer one terminal outcome membership question.
    Outcome(TxId),
    /// Answer one object membership or authorization-gated absence question.
    Object(GitOid),
}

/// A read response with the exact authority body and serving label used for it.
///
/// `authority_head` is response data, not permission for the server to choose
/// a client pin.  A client obtains and authenticates its own head, then passes
/// that independent body to `fgit_verified_read::verify_envelope`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServedVerifiedRead {
    authority_head: fgit_codec::RepositoryAuthorityHeadBody,
    label: ReadLabel,
    served_by: ServingCell,
    response: ReadResponse,
}

impl ServedVerifiedRead {
    const fn new(
        authority_head: fgit_codec::RepositoryAuthorityHeadBody,
        label: ReadLabel,
        served_by: ServingCell,
        response: ReadResponse,
    ) -> Self {
        Self {
            authority_head,
            label,
            served_by,
            response,
        }
    }

    /// The exact authority head whose projections supplied this response.
    #[must_use]
    pub const fn authority_head(&self) -> &fgit_codec::RepositoryAuthorityHeadBody {
        &self.authority_head
    }

    /// The serving mode attached to this exact response.
    #[must_use]
    pub const fn label(&self) -> ReadLabel {
        self.label
    }

    /// The cell that served the answer; it authorizes nothing.
    #[must_use]
    pub const fn served_by(&self) -> ServingCell {
        self.served_by
    }

    /// The representation selected by verified-read capability negotiation.
    #[must_use]
    pub const fn response(&self) -> &ReadResponse {
        &self.response
    }
}

/// A typed refusal from the verified-read serving path.
#[derive(Debug)]
pub enum VerifiedReadServingRefusal {
    /// The cell may not serve the label's read mode in its current state.
    State(CellRefusal),
    /// The current-read endpoint received a non-current label.
    CurrentLabelRequired { observed: ReadMode },
    /// The snapshot endpoint received a label other than an exact snapshot.
    SnapshotLabelRequired { observed: ReadMode },
    /// The authority store did not authenticate the supplied snapshot receipt.
    SnapshotAuthentication(Box<AuthorityFailure>),
    /// An authenticated receipt did not decode to one cross-checked head body.
    HeadBody(Box<HeadBodyRefusal>),
    /// An exact authority-selected admission projection could not materialize.
    Materialization(Box<AdmissionMaterializationRefusal>),
    /// The exact selected head or outcome stream was invalid or unavailable.
    Outcome(Box<OutcomeFailure>),
    /// The selected configuration did not make ref Merkle proofs available.
    RefLayoutUnavailable { layout: RootLayoutVersion },
    /// The selected configuration did not make object closure Merkle proofs available.
    ObjectLayoutUnavailable { layout: RootLayoutVersion },
    /// The head's exact incarnation-configuration minor has no envelope variant
    /// that can carry it without changing its canonical identity.
    ConfigurationMinorUnrepresentable {
        /// The schema minor that decoded but cannot be carried exactly.
        minor: u16,
    },
    /// A disclosure gate or proof constructor refused the request.
    VerifiedRead(Box<VerifiedReadRefusal>),
    /// The reconstructed terminal-outcome leaves did not reproduce the head's
    /// exact `outcome_index_root`.
    OutcomeRootMismatch,
    /// A terminal-outcome inclusion proof cannot answer an undecided query.
    OutcomeProofUnavailable,
}

impl fmt::Display for VerifiedReadServingRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(refusal) => write!(formatter, "verified read state refusal: {refusal}"),
            Self::CurrentLabelRequired { observed } => {
                write!(
                    formatter,
                    "current verified read requires a current label, got {observed:?}"
                )
            }
            Self::SnapshotLabelRequired { observed } => write!(
                formatter,
                "snapshot verified read requires a snapshot label, got {observed:?}"
            ),
            Self::SnapshotAuthentication(refusal) => {
                write!(
                    formatter,
                    "snapshot receipt authentication refused: {refusal}"
                )
            }
            Self::HeadBody(refusal) => {
                write!(formatter, "verified-read head body refused: {refusal}")
            }
            Self::Materialization(refusal) => {
                write!(
                    formatter,
                    "verified-read materialization refused: {refusal}"
                )
            }
            Self::Outcome(refusal) => write!(formatter, "verified-read outcome refused: {refusal}"),
            Self::RefLayoutUnavailable { layout } => write!(
                formatter,
                "the selected {layout:?} layout does not admit ref membership proofs"
            ),
            Self::ObjectLayoutUnavailable { layout } => write!(
                formatter,
                "the selected {layout:?} layout does not admit object closure membership proofs"
            ),
            Self::ConfigurationMinorUnrepresentable { minor } => write!(
                formatter,
                "the head's incarnation-configuration schema 2.{minor} decodes but no verified-read \
                 envelope variant carries it exactly, so its canonical identity cannot be rebuilt"
            ),
            Self::VerifiedRead(refusal) => write!(formatter, "verified-read refused: {refusal}"),
            Self::OutcomeRootMismatch => formatter.write_str(
                "the exact head outcome root does not match its reconstructed terminal decisions",
            ),
            Self::OutcomeProofUnavailable => {
                formatter.write_str("an undecided outcome has no membership proof")
            }
        }
    }
}

impl std::error::Error for VerifiedReadServingRefusal {}

/// The intersection of the snapshot's authenticated hide policy and the
/// currently enforced serving policy.
///
/// An exact historical snapshot may preserve a less restrictive policy than
/// the policy now applied at the serving boundary.  Treating the current policy
/// as an additional deny-only filter ensures that serving an old projection can
/// never re-expose a ref the current boundary hides; the snapshot policy still
/// prevents a newer caller policy from un-hiding a ref hidden at that basis.
struct DisclosureScope<'a> {
    snapshot: &'a RefVisibility,
    current: &'a RefVisibility,
    snapshot_refs: &'a std::collections::BTreeMap<RefName, GitOid>,
}

impl RefDisclosurePolicy for DisclosureScope<'_> {
    fn permits_ref_disclosure(&self, name: &RefName) -> bool {
        !self.snapshot.hides(name.as_bytes()) && !self.current.hides(name.as_bytes())
    }
}

impl ObjectDisclosurePolicy for DisclosureScope<'_> {
    fn permits_object_disclosure(&self, oid: &GitOid) -> bool {
        let mut pointed_to_by_hidden = false;
        let mut pointed_to_by_visible = false;
        for (name, target) in self.snapshot_refs {
            if target == oid {
                if self.permits_ref_disclosure(name) {
                    pointed_to_by_visible = true;
                } else {
                    pointed_to_by_hidden = true;
                }
            }
        }
        if pointed_to_by_hidden && !pointed_to_by_visible {
            return false;
        }
        true
    }
}

impl OneNode {
    /// Serves one verified read from the authority head current for this call.
    ///
    /// Only [`ReadLabel::current`] is accepted here.  An exact historical
    /// answer must go through [`Self::serve_snapshot_verified_read_in`], which
    /// authenticates the caller-supplied receipt before materializing it.
    ///
    /// `current_visibility` is a deny-only serving policy supplied by the
    /// transport/authorization boundary.  It is intersected with the
    /// authority-selected snapshot policy before any ref lookup.
    pub async fn serve_current_verified_read_in(
        &self,
        request: &NodeRequestContext,
        current_visibility: &RefVisibility,
        label: ReadLabel,
        capability: VerifiedReadCapability,
        query: VerifiedReadQuery,
    ) -> Result<ServedVerifiedRead, VerifiedReadServingRefusal> {
        if label.mode() != ReadMode::Current {
            return Err(VerifiedReadServingRefusal::CurrentLabelRequired {
                observed: label.mode(),
            });
        }
        admits_read(self.cell_state(), label.mode()).map_err(VerifiedReadServingRefusal::State)?;
        let materialized = self
            .materialize_admission_in(request)
            .await
            .map_err(|refusal| VerifiedReadServingRefusal::Materialization(Box::new(refusal)))?;
        self.serve_materialized_verified_read_in(
            request,
            materialized,
            current_visibility,
            label,
            capability,
            query,
        )
        .await
    }

    /// Serves one verified read from a caller-named, independently issued
    /// historical authority receipt.
    ///
    /// This endpoint admits only [`ReadLabel::snapshot`].  It re-authenticates
    /// the receipt against this node's store and then materializes exactly its
    /// body, so a response cannot silently drift to whichever head is current
    /// while the request awaits storage.
    pub async fn serve_snapshot_verified_read_in(
        &self,
        request: &NodeRequestContext,
        receipt: &HeadReadReceipt,
        current_visibility: &RefVisibility,
        label: ReadLabel,
        capability: VerifiedReadCapability,
        query: VerifiedReadQuery,
    ) -> Result<ServedVerifiedRead, VerifiedReadServingRefusal> {
        if label.mode() != ReadMode::Snapshot {
            return Err(VerifiedReadServingRefusal::SnapshotLabelRequired {
                observed: label.mode(),
            });
        }
        admits_read(self.cell_state(), label.mode()).map_err(VerifiedReadServingRefusal::State)?;
        let authenticated = AsyncAuthorityStore::authenticate_head_receipt(
            &self.authority,
            request.authority(),
            receipt,
        )
        .await
        .map_err(|refusal| VerifiedReadServingRefusal::SnapshotAuthentication(Box::new(refusal)))?;
        let body = authenticated
            .body()
            .map_err(|refusal| VerifiedReadServingRefusal::HeadBody(Box::new(refusal)))?;
        let head_id = authority_head_identity(&body)
            .map_err(|refusal| VerifiedReadServingRefusal::Outcome(Box::new(refusal)))?;
        let basis = PublicationBasis::new(head_id, body);
        let is_cancelled = || false;
        let materialized = self
            .admission_materializer
            .materialize_exact_in(
                &self.authority,
                request.authority(),
                self.repository_id,
                &basis,
                &authenticated,
                &is_cancelled,
            )
            .await
            .map_err(|refusal| VerifiedReadServingRefusal::Materialization(Box::new(refusal)))?;
        self.serve_materialized_verified_read_in(
            request,
            materialized,
            current_visibility,
            label,
            capability,
            query,
        )
        .await
    }

    async fn serve_materialized_verified_read_in(
        &self,
        request: &NodeRequestContext,
        materialized: MaterializedAdmission,
        current_visibility: &RefVisibility,
        label: ReadLabel,
        capability: VerifiedReadCapability,
        query: VerifiedReadQuery,
    ) -> Result<ServedVerifiedRead, VerifiedReadServingRefusal> {
        let head = materialized.basis().body().clone();
        let scope = DisclosureScope {
            snapshot: &materialized.snapshot().hidden_refs,
            current: current_visibility,
            snapshot_refs: &materialized.snapshot().refs,
        };
        let response = match query {
            VerifiedReadQuery::Ref(name) => {
                self.serve_ref_verified_read_in(request, &materialized, &scope, capability, name)
                    .await?
            }
            VerifiedReadQuery::Outcome(tx_id) => {
                self.serve_outcome_verified_read_in(request, &head, capability, tx_id)
                    .await?
            }
            VerifiedReadQuery::Object(oid) => {
                self.serve_object_verified_read_in(request, &materialized, &scope, capability, oid)
                    .await?
            }
        };
        Ok(ServedVerifiedRead::new(
            head,
            label,
            self.serving_cell,
            response,
        ))
    }

    async fn serve_ref_verified_read_in(
        &self,
        request: &NodeRequestContext,
        materialized: &MaterializedAdmission,
        scope: &DisclosureScope<'_>,
        capability: VerifiedReadCapability,
        name: RefName,
    ) -> Result<ReadResponse, VerifiedReadServingRefusal> {
        // Membership is a disclosure too.  Check the scope before reading the
        // map, just as `authorize_ref_absence` does for a negative answer.
        if !scope.permits_ref_disclosure(&name) {
            return Err(VerifiedReadServingRefusal::VerifiedRead(Box::new(
                VerifiedReadRefusal::RefNotFoundOrUnauthorized,
            )));
        }

        let entries = materialized
            .snapshot()
            .refs
            .iter()
            .map(|(name, oid)| (name.clone(), *oid))
            .collect::<Vec<_>>();
        let head = materialized.basis().body().clone();
        match materialized.snapshot().refs.get(&name).copied() {
            Some(oid) => match negotiate_response_mode(capability) {
                fgit_verified_read::VerifiedReadResponseMode::Unproven => {
                    Ok(ReadResponse::Unproven(Box::new(UnprovenReadAnswer::Ref {
                        name,
                        oid: Some(oid),
                    })))
                }
                fgit_verified_read::VerifiedReadResponseMode::EnvelopeV1 => {
                    let configuration = self
                        .verified_read_configuration_in(request, &head.configuration_root)
                        .await?;
                    ensure_ref_proof_layout(&configuration)?;
                    let (bound_oid, proof) =
                        ref_state_membership_proof(&entries, &name).map_err(|refusal| {
                            VerifiedReadServingRefusal::VerifiedRead(Box::new(
                                VerifiedReadRefusal::RefLayout(Box::new(refusal)),
                            ))
                        })?;
                    if bound_oid != oid {
                        return Err(VerifiedReadServingRefusal::VerifiedRead(Box::new(
                            VerifiedReadRefusal::ProofRejected,
                        )));
                    }
                    Ok(ReadResponse::Verified(Box::new(
                        VerifiedReadEnvelope::new_with_exact_configuration(
                            head,
                            Some(configuration),
                            VerifiedReadAnswer::RefMembership {
                                name,
                                oid,
                                proof: Box::new(proof),
                            },
                        ),
                    )))
                }
            },
            None => {
                let absence = authorize_ref_absence(scope, name, |requested| {
                    materialized.snapshot().refs.contains_key(requested)
                })
                .map_err(|refusal| VerifiedReadServingRefusal::VerifiedRead(Box::new(refusal)))?;
                match negotiate_response_mode(capability) {
                    fgit_verified_read::VerifiedReadResponseMode::Unproven => {
                        Ok(ReadResponse::Unproven(Box::new(UnprovenReadAnswer::Ref {
                            name: absence.name().clone(),
                            oid: None,
                        })))
                    }
                    fgit_verified_read::VerifiedReadResponseMode::EnvelopeV1 => {
                        let configuration = self
                            .verified_read_configuration_in(request, &head.configuration_root)
                            .await?;
                        ensure_ref_proof_layout(&configuration)?;
                        let proof = ref_state_non_membership_proof(&entries, absence.name())
                            .map_err(|refusal| {
                                VerifiedReadServingRefusal::VerifiedRead(Box::new(
                                    VerifiedReadRefusal::RefLayout(Box::new(refusal)),
                                ))
                            })?;
                        Ok(ReadResponse::Verified(Box::new(
                            VerifiedReadEnvelope::new_with_exact_configuration(
                                head,
                                Some(configuration),
                                VerifiedReadAnswer::AuthorizedRefAbsence {
                                    absence,
                                    proof: Box::new(proof),
                                },
                            ),
                        )))
                    }
                }
            }
        }
    }

    async fn serve_outcome_verified_read_in(
        &self,
        request: &NodeRequestContext,
        head: &fgit_codec::RepositoryAuthorityHeadBody,
        capability: VerifiedReadCapability,
        tx_id: TxId,
    ) -> Result<ReadResponse, VerifiedReadServingRefusal> {
        let entries = self.outcome_entries_at_head_in(request, head).await?;
        let root = outcome_index_root(&entries)
            .map_err(|refusal| VerifiedReadServingRefusal::Outcome(Box::new(refusal)))?;
        if root != head.outcome_index_root {
            return Err(VerifiedReadServingRefusal::OutcomeRootMismatch);
        }
        let outcome = entries
            .iter()
            .find(|(candidate, _)| *candidate == tx_id)
            .map(|(_, outcome)| *outcome);
        match (negotiate_response_mode(capability), outcome) {
            (fgit_verified_read::VerifiedReadResponseMode::Unproven, outcome) => Ok(
                ReadResponse::Unproven(Box::new(UnprovenReadAnswer::Outcome {
                    tx_id,
                    outcome: outcome.map(Box::new),
                })),
            ),
            (fgit_verified_read::VerifiedReadResponseMode::EnvelopeV1, Some(outcome)) => {
                let proof = outcome_index_proof(&entries, tx_id, &outcome)
                    .map_err(|refusal| VerifiedReadServingRefusal::Outcome(Box::new(refusal)))?;
                Ok(ReadResponse::Verified(Box::new(VerifiedReadEnvelope::new(
                    head.clone(),
                    None,
                    VerifiedReadAnswer::OutcomeMembership {
                        tx_id,
                        outcome: Box::new(outcome),
                        proof: Box::new(proof),
                    },
                ))))
            }
            (fgit_verified_read::VerifiedReadResponseMode::EnvelopeV1, None) => {
                Err(VerifiedReadServingRefusal::OutcomeProofUnavailable)
            }
        }
    }

    async fn verified_read_configuration_in(
        &self,
        request: &NodeRequestContext,
        configuration_root: &Digest,
    ) -> Result<VerifiedReadConfiguration, VerifiedReadServingRefusal> {
        match read_repository_incarnation_configuration_evidence_async(
            &self.authority,
            request.authority(),
            configuration_root,
        )
        .await
        {
            // The EXACT body, not the normalized projection. A verified read is
            // checked against `head.configuration_root`, and that digest names
            // one canonical body; handing the envelope a projection would let it
            // recompute an identity the head never committed to.
            Ok(RepositoryIncarnationConfigurationEvidence::V2_0(body)) => {
                Ok(VerifiedReadConfiguration::RepositoryIncarnationV2(body))
            }
            // Schema 2.1 decodes here, but `VerifiedReadConfiguration` has no
            // variant that carries it exactly. Narrowing it into the 2.0 variant
            // would compile and would be wrong: 2.0 and 2.1-with-`policy_root:
            // None` are different canonical bodies with different identities, so
            // the envelope would recompute a root the head does not bind and the
            // two minors would alias. Refusing is the typed answer until
            // `fgit-verified-read` carries an exact 2.1 variant.
            Ok(RepositoryIncarnationConfigurationEvidence::V2_1(_)) => {
                Err(VerifiedReadServingRefusal::ConfigurationMinorUnrepresentable { minor: 1 })
            }
            Err(OutcomeFailure::Codec(fgit_codec::CodecRefusal::SchemaMajorUnsupported {
                observed: 1,
                ..
            })) => read_repository_configuration_async(
                &self.authority,
                request.authority(),
                configuration_root,
            )
            .await
            .map(VerifiedReadConfiguration::RepositoryV1)
            .map_err(|refusal| VerifiedReadServingRefusal::Outcome(Box::new(refusal))),
            Err(refusal) => Err(VerifiedReadServingRefusal::Outcome(Box::new(refusal))),
        }
    }

    async fn outcome_entries_at_head_in(
        &self,
        request: &NodeRequestContext,
        selected_head: &fgit_codec::RepositoryAuthorityHeadBody,
    ) -> Result<Vec<(TxId, TerminalOutcome)>, VerifiedReadServingRefusal> {
        let mut head = selected_head.clone();
        let mut walked = 0_usize;
        let mut entries = Vec::new();
        while let Some(batch_id) = next_batch_to_replay(&head, &mut walked)
            .map_err(|refusal| VerifiedReadServingRefusal::Outcome(Box::new(refusal)))?
        {
            let batch =
                read_decision_batch_body_async(&self.authority, request.authority(), batch_id)
                    .await
                    .map_err(|refusal| VerifiedReadServingRefusal::Outcome(Box::new(refusal)))?;
            entries.extend(batch.decisions.iter().map(|decision| {
                (
                    decision.tx_id,
                    TerminalOutcome {
                        decision_sequence: decision.decision_sequence,
                        outcome: decision.outcome,
                    },
                )
            }));
            head = read_authority_head_body_async(
                &self.authority,
                request.authority(),
                batch.predecessor_head_id,
            )
            .await
            .map_err(|refusal| VerifiedReadServingRefusal::Outcome(Box::new(refusal)))?;
        }
        Ok(entries)
    }

    async fn serve_object_verified_read_in(
        &self,
        request: &NodeRequestContext,
        materialized: &MaterializedAdmission,
        scope: &DisclosureScope<'_>,
        capability: VerifiedReadCapability,
        oid: GitOid,
    ) -> Result<ReadResponse, VerifiedReadServingRefusal> {
        // Membership is a disclosure too. Check the scope before reading the
        // closure, just as `authorize_object_absence` does for a negative answer.
        if !scope.permits_object_disclosure(&oid) {
            return Err(VerifiedReadServingRefusal::VerifiedRead(Box::new(
                VerifiedReadRefusal::ObjectNotFoundOrUnauthorized,
            )));
        }

        let objects = materialized
            .selected_closure()
            .closure()
            .objects()
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let head = materialized.basis().body().clone();
        let is_present = materialized
            .selected_closure()
            .closure()
            .objects()
            .contains(&oid);

        if is_present {
            match negotiate_response_mode(capability) {
                fgit_verified_read::VerifiedReadResponseMode::Unproven => {
                    Ok(ReadResponse::Unproven(Box::new(
                        UnprovenReadAnswer::Object { oid, present: true },
                    )))
                }
                fgit_verified_read::VerifiedReadResponseMode::EnvelopeV1 => {
                    let configuration = self
                        .verified_read_configuration_in(request, &head.configuration_root)
                        .await?;
                    ensure_object_proof_layout(&configuration)?;
                    let proof =
                        object_closure_membership_proof(&objects, &oid).map_err(|refusal| {
                            VerifiedReadServingRefusal::VerifiedRead(Box::new(
                                VerifiedReadRefusal::ObjectLayout(Box::new(refusal)),
                            ))
                        })?;
                    Ok(ReadResponse::Verified(Box::new(
                        VerifiedReadEnvelope::new_with_exact_configuration(
                            head,
                            Some(configuration),
                            VerifiedReadAnswer::ObjectMembership {
                                oid,
                                proof: Box::new(proof),
                            },
                        ),
                    )))
                }
            }
        } else {
            let absence = authorize_object_absence(scope, oid, |requested| {
                materialized
                    .selected_closure()
                    .closure()
                    .objects()
                    .contains(requested)
            })
            .map_err(|refusal| VerifiedReadServingRefusal::VerifiedRead(Box::new(refusal)))?;
            match negotiate_response_mode(capability) {
                fgit_verified_read::VerifiedReadResponseMode::Unproven => Ok(
                    ReadResponse::Unproven(Box::new(UnprovenReadAnswer::Object {
                        oid: *absence.oid(),
                        present: false,
                    })),
                ),
                fgit_verified_read::VerifiedReadResponseMode::EnvelopeV1 => {
                    let configuration = self
                        .verified_read_configuration_in(request, &head.configuration_root)
                        .await?;
                    ensure_object_proof_layout(&configuration)?;
                    let proof = object_closure_non_membership_proof(&objects, absence.oid())
                        .map_err(|refusal| {
                            VerifiedReadServingRefusal::VerifiedRead(Box::new(
                                VerifiedReadRefusal::ObjectLayout(Box::new(refusal)),
                            ))
                        })?;
                    authorize_disclosed_neighbours(scope, &proof)?;
                    Ok(ReadResponse::Verified(Box::new(
                        VerifiedReadEnvelope::new_with_exact_configuration(
                            head,
                            Some(configuration),
                            VerifiedReadAnswer::AuthorizedObjectAbsence {
                                absence,
                                proof: Box::new(proof),
                            },
                        ),
                    )))
                }
            }
        }
    }
}

const fn ensure_ref_proof_layout(
    configuration: &VerifiedReadConfiguration,
) -> Result<(), VerifiedReadServingRefusal> {
    let layout = configuration.root_layout();
    if layout.admits_ref_state_membership_proof() {
        Ok(())
    } else {
        Err(VerifiedReadServingRefusal::RefLayoutUnavailable { layout })
    }
}

const fn ensure_object_proof_layout(
    configuration: &VerifiedReadConfiguration,
) -> Result<(), VerifiedReadServingRefusal> {
    let layout = configuration.root_layout();
    if layout.admits_object_closure_membership_proof() {
        Ok(())
    } else {
        Err(VerifiedReadServingRefusal::ObjectLayoutUnavailable { layout })
    }
}

/// Every object identity an ordered absence proof would put on the wire.
///
/// The match is exhaustive with no wildcard so that a new proof variant fails
/// to compile here, beside the authorization it has to pass, rather than
/// silently disclosing a neighbour this function never learned about.
fn disclosed_absence_neighbours(proof: &ObjectClosureNonMembershipProof) -> Vec<GitOid> {
    match proof {
        // An empty closure names no object but the one that was queried.
        ObjectClosureNonMembershipProof::EmptyClosure => Vec::new(),
        ObjectClosureNonMembershipProof::BeforeFirst { first } => vec![*first.oid()],
        ObjectClosureNonMembershipProof::AfterLast { last } => vec![*last.oid()],
        ObjectClosureNonMembershipProof::Between {
            predecessor,
            successor,
        } => vec![*predecessor.oid(), *successor.oid()],
    }
}

/// Authorizes the bracketing objects an absence proof discloses.
///
/// [`authorize_object_absence`] authorizes the object that was *asked about*.
/// An ordered non-membership proof additionally serialises the neighbours that
/// bracket the gap, and those identities were never offered to the disclosure
/// policy — so a caller authorized for one object could learn two others by
/// asking about a gap beside them. AGENTS.md §8 puts the authorization filter
/// before disclosure of neighbours specifically, so they are authorized here,
/// before the answer is constructed rather than after it is sent.
///
/// # Why the refusal is the not-found one
///
/// A denied neighbour yields exactly
/// [`VerifiedReadRefusal::ObjectNotFoundOrUnauthorized`], the same refusal an
/// unauthorized query receives. A distinct code would itself be the leak: it
/// would tell a caller that the gap it asked about is bracketed by objects it
/// may not see, which is most of what the neighbour identities would have told
/// it. Refusing is also the only honest option — the proof cannot be served
/// without its neighbours, and serving a partial one would be a verification
/// nobody can complete.
fn authorize_disclosed_neighbours<P>(
    policy: &P,
    proof: &ObjectClosureNonMembershipProof,
) -> Result<(), VerifiedReadServingRefusal>
where
    P: ObjectDisclosurePolicy + ?Sized,
{
    for neighbour in disclosed_absence_neighbours(proof) {
        if !policy.permits_object_disclosure(&neighbour) {
            return Err(VerifiedReadServingRefusal::VerifiedRead(Box::new(
                VerifiedReadRefusal::ObjectNotFoundOrUnauthorized,
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use fgit_admission::{CanonicalRefState, PermittedObjectClosure};
    use fgit_authority::{
        HeadRead, collect_cumulative_outcomes_async,
        stage_repository_incarnation_configuration_async,
    };
    use fgit_chronicle::{PublicationPlan, PublicationVerdict, ResultingRoots};
    use fgit_codec::{
        CryptoBodyIdentity, RepositoryIncarnationConfigurationBody, decode_body,
        harness::{commit_record, digest_of},
    };
    use fgit_crypto::{
        MerkleProof, ObjectClosureNeighbour, ObjectClosureNonMembershipProof,
        object_closure_merkle_root,
    };
    use fgit_git_object::ObjectType;
    use fgit_types::cell::{CellState, CellTransitionCause, ReadLabel};
    use fgit_types::identity::RepositoryIncarnationId;
    use fgit_types::layout::RootLayoutVersion;
    use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
    use fgit_types::{RefName, RepositoryId, TenantId};
    use fgit_verified_read::{
        ObjectDisclosurePolicy, PinnedAuthorityHead, ReadResponse, UnprovenReadAnswer,
        VerifiedMembership, VerifiedReadEnvelope, VerifiedReadRefusal, verify_envelope,
    };
    use fgit_wire::WireLimits;
    use fgit_wire::visibility::RefVisibility;

    use super::{
        DisclosureScope, OneNode, VerifiedReadCapability, VerifiedReadQuery,
        VerifiedReadServingRefusal, authorize_disclosed_neighbours,
    };
    use crate::{
        NodeConfig, PublicationBasis, authority_head_id, genesis_head,
        initialize_embedded_repository,
    };

    static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct ScratchDirectory(PathBuf);

    impl ScratchDirectory {
        fn new() -> Self {
            let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "frankengit-o5zy-verified-read-{}-{sequence}",
                std::process::id()
            )))
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn config(root: PathBuf) -> NodeConfig {
        NodeConfig::new(
            root,
            TenantId::from_bytes([0x31; 16]),
            RepositoryId::from_bytes([0x32; 16]),
        )
    }

    /// Initializes an actual `OneNode` authority store with the V2 incarnation
    /// configuration that commits to the V1 ref Merkle layout.  `OneNode::init`
    /// intentionally retains the legacy default for ordinary compatibility
    /// nodes, so this is a real opt-in repository fixture rather than a test
    /// pretending every existing repository has proofs.
    fn proof_capable_node(scratch: &ScratchDirectory) -> OneNode {
        let node = OneNode::open_components(config(scratch.0.clone()))
            .expect("components open before authoritative genesis");
        let request = node.request_context();
        let configuration = RepositoryIncarnationConfigurationBody {
            root_layout: RootLayoutVersion::RefStateMerkleV1,
            object_format: GitHashAlgorithm::Sha1,
            repository_incarnation_id: RepositoryIncarnationId::from_bytes(
                *node.repository_incarnation_id.as_bytes(),
            ),
        };
        let configuration_root = node
            .runtime()
            .block_on(stage_repository_incarnation_configuration_async(
                &node.authority,
                request.authority(),
                &configuration,
            ))
            .expect("the selected incarnation configuration stages");
        let ref_root = node
            .runtime()
            .block_on(node.admission_materializer.stage_ref_state_for_layout_in(
                &node.authority,
                request.authority(),
                node.repository_id(),
                RootLayoutVersion::RefStateMerkleV1,
                CanonicalRefState::default(),
            ))
            .expect("the empty canonical ref state stages");
        node.runtime()
            .block_on(
                node.admission_materializer
                    .stage_permitted_object_closure_in(
                        &node.authority,
                        request.authority(),
                        node.repository_id(),
                        PermittedObjectClosure::default(),
                    ),
            )
            .expect("the empty canonical closure stages");
        let genesis = genesis_head(node.repository_id(), ref_root, configuration_root)
            .expect("the exact V2 configuration can initialize a head");
        initialize_embedded_repository(
            node.runtime(),
            &node.authority,
            request.authority(),
            &node.head_key,
            &genesis,
        )
        .expect("the proof-capable genesis publishes");
        node
    }

    fn publish_member_and_outcome(node: &OneNode) -> (RefName, fgit_types::TxId, GitOid) {
        let request = node.request_context();
        let stored = node
            .put_git_object(ObjectType::Blob, b"verified-read fixture".to_vec())
            .expect("the selected blob enters immutable fabric");
        let name = RefName::try_new(b"refs/heads/proven").expect("fixed fixture ref name is valid");
        let refs = BTreeMap::from([(name.clone(), stored.identity())]);
        let ref_root = node
            .runtime()
            .block_on(node.admission_materializer.stage_ref_state_for_layout_in(
                &node.authority,
                request.authority(),
                node.repository_id(),
                RootLayoutVersion::RefStateMerkleV1,
                CanonicalRefState::new(refs),
            ))
            .expect("the successor ref state stages before publication");
        let closure_root = node
            .runtime()
            .block_on(
                node.admission_materializer
                    .stage_permitted_object_closure_in(
                        &node.authority,
                        request.authority(),
                        node.repository_id(),
                        PermittedObjectClosure::new(BTreeSet::from([stored.identity()])),
                    ),
            )
            .expect("the successor object closure stages before publication");
        let HeadRead::Present(receipt) = node
            .runtime()
            .block_on(node.read_authority_head_in(&request))
            .expect("the genesis head reads")
        else {
            panic!("proof-capable genesis is present");
        };
        let body = decode_body(receipt.body(), fgit_codec::DecodeLimits::DEFAULT)
            .expect("the authenticated genesis body decodes");
        let basis = PublicationBasis::new(
            authority_head_id(&body).expect("the genesis head re-identifies"),
            body,
        );
        let mut record = commit_record();
        record.repository_id = node.repository_id();
        record.resulting_ref_root = ref_root;
        record.object_closure_root = closure_root;
        record.resulting_forge_position_root = basis.body().forge_position_root;
        record.policy_epoch = basis.body().policy_epoch;
        let mut roots = ResultingRoots::carried_forward(&basis);
        roots.ref_root = ref_root;
        let mut plan = PublicationPlan::open(basis).expect("the current head opens a plan");
        plan.commit(record);
        let outcomes = node
            .runtime()
            .block_on(collect_cumulative_outcomes_async(
                &node.authority,
                request.authority(),
                &node.head_key,
            ))
            .expect("the empty outcome index collects from the exact current head");
        let publication = plan
            .seal(&CryptoBodyIdentity, roots, &outcomes, receipt.token())
            .expect("the committed ref transition verifies as a publication");
        let tx_id = publication
            .batch()
            .decisions
            .first()
            .expect("a committed publication has one terminal decision")
            .tx_id;
        let verdict = node
            .runtime()
            .block_on(node.publish_decisions_in(&request, &publication))
            .expect("the verified publication replaces the exact predecessor head");
        assert!(matches!(verdict, PublicationVerdict::Published(_)));
        (name, tx_id, stored.identity())
    }

    #[test]
    fn ordinary_client_verifies_served_ref_membership_absence_and_outcome_and_rejects_tampering() {
        let scratch = ScratchDirectory::new();
        let mut node = proof_capable_node(&scratch);
        let (present, committed_tx, _) = publish_member_and_outcome(&node);
        let missing =
            RefName::try_new(b"refs/heads/missing").expect("fixed fixture ref name is valid");
        node.transition_cell_state(
            CellState::VerifiedReadOnly,
            CellTransitionCause::AuthorityObservation,
            fgit_types::HeadGeneration::try_new(2)
                .expect("the published successor is generation 2"),
        )
        .expect("the observed cell may enter verified-read serving");

        // The client obtains this head independently.  The serving calls below
        // receive no pin and must merely return an answer that verifies under
        // the client-selected body.
        let independently_fetched = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .expect("the ordinary client fetches an authentic authority head")
            .body()
            .expect("the independently authenticated body decodes");
        let pin = PinnedAuthorityHead::new(independently_fetched.clone());

        let unproven = node
            .runtime()
            .block_on(node.serve_current_verified_read_in(
                &node.request_context(),
                &RefVisibility::new(),
                ReadLabel::current(),
                VerifiedReadCapability::Unproven,
                VerifiedReadQuery::Ref(missing.clone()),
            ))
            .expect("an ordinary client can decline proofs");
        assert_eq!(unproven.authority_head(), &independently_fetched);
        assert_eq!(
            unproven.response(),
            &ReadResponse::Unproven(Box::new(UnprovenReadAnswer::Ref {
                name: missing.clone(),
                oid: None,
            })),
            "capability negotiation retains the valid ordinary response mode"
        );

        let member = node
            .runtime()
            .block_on(node.serve_current_verified_read_in(
                &node.request_context(),
                &RefVisibility::new(),
                ReadLabel::current(),
                VerifiedReadCapability::EnvelopeV1,
                VerifiedReadQuery::Ref(present),
            ))
            .expect("a proof-capable client receives a ref envelope");
        let ReadResponse::Verified(member_envelope) = member.response() else {
            panic!("proof negotiation must select an envelope");
        };
        assert_eq!(
            verify_envelope(&pin, member_envelope),
            Ok(VerifiedMembership::Ref)
        );

        let absence = node
            .runtime()
            .block_on(node.serve_current_verified_read_in(
                &node.request_context(),
                &RefVisibility::new(),
                ReadLabel::current(),
                VerifiedReadCapability::EnvelopeV1,
                VerifiedReadQuery::Ref(missing),
            ))
            .expect("a visible absent ref has an authorized non-membership proof");
        let ReadResponse::Verified(absence_envelope) = absence.response() else {
            panic!("proof negotiation must select an envelope");
        };
        assert_eq!(
            verify_envelope(&pin, absence_envelope),
            Ok(VerifiedMembership::RefAbsence)
        );

        let outcome = node
            .runtime()
            .block_on(node.serve_current_verified_read_in(
                &node.request_context(),
                &RefVisibility::new(),
                ReadLabel::current(),
                VerifiedReadCapability::EnvelopeV1,
                VerifiedReadQuery::Outcome(committed_tx),
            ))
            .expect("a committed terminal decision has an outcome inclusion proof");
        let ReadResponse::Verified(outcome_envelope) = outcome.response() else {
            panic!("proof negotiation must select an envelope");
        };
        assert_eq!(
            verify_envelope(&pin, outcome_envelope),
            Ok(VerifiedMembership::Outcome)
        );

        let mut tampered_head = member_envelope.head().clone();
        tampered_head.ref_root = digest_of(0xA7);
        let tampered = VerifiedReadEnvelope::new_with_exact_configuration(
            tampered_head,
            member_envelope.exact_configuration().cloned(),
            member_envelope.answer().clone(),
        );
        assert_eq!(
            verify_envelope(&pin, &tampered),
            Err(VerifiedReadRefusal::PinnedHeadMismatch),
            "a response whose served head was tampered after transport cannot replace the independent pin"
        );
        node.shutdown()
            .expect("the serving cell closes to quiescence");
    }

    #[test]
    fn snapshot_proof_binds_its_receipt_and_current_visibility_cannot_expand_it() {
        let scratch = ScratchDirectory::new();
        let mut node = proof_capable_node(&scratch);
        node.transition_cell_state(
            CellState::VerifiedReadOnly,
            CellTransitionCause::AuthorityObservation,
            fgit_types::HeadGeneration::FIRST,
        )
        .expect("the observed cell may serve an exact snapshot");
        let request = node.request_context();
        let HeadRead::Present(receipt) = node
            .runtime()
            .block_on(node.read_authority_head_in(&request))
            .expect("the snapshot client fetches a receipt")
        else {
            panic!("proof-capable genesis is present");
        };
        let independently_fetched = node
            .runtime()
            .block_on(node.authenticate_authority_head_in(&request))
            .expect("the independent snapshot pin authenticates")
            .body()
            .expect("the independent snapshot body decodes");
        let missing = RefName::try_new(b"refs/heads/snapshot-missing")
            .expect("fixed fixture ref name is valid");
        let snapshot = node
            .runtime()
            .block_on(node.serve_snapshot_verified_read_in(
                &request,
                &receipt,
                &RefVisibility::new(),
                ReadLabel::snapshot(),
                VerifiedReadCapability::EnvelopeV1,
                VerifiedReadQuery::Ref(missing.clone()),
            ))
            .expect("the authentic receipt selects an exact snapshot proof");
        assert_eq!(snapshot.authority_head(), &independently_fetched);
        let ReadResponse::Verified(envelope) = snapshot.response() else {
            panic!("the negotiated snapshot uses an envelope");
        };
        assert_eq!(
            verify_envelope(&PinnedAuthorityHead::new(independently_fetched), envelope),
            Ok(VerifiedMembership::RefAbsence),
            "the proof binds exactly the head selected by the snapshot receipt"
        );

        let mut now_hides_the_name = RefVisibility::new();
        now_hides_the_name
            .push_rule(missing.as_bytes(), &WireLimits::default())
            .expect("the exact missing name is a valid hide rule");
        let refusal = node
            .runtime()
            .block_on(node.serve_snapshot_verified_read_in(
                &request,
                &receipt,
                &now_hides_the_name,
                ReadLabel::snapshot(),
                VerifiedReadCapability::EnvelopeV1,
                VerifiedReadQuery::Ref(missing),
            ));
        assert!(matches!(
            refusal,
            Err(VerifiedReadServingRefusal::VerifiedRead(refusal))
                if refusal.as_ref() == &VerifiedReadRefusal::RefNotFoundOrUnauthorized
        ));
        node.shutdown()
            .expect("the serving cell closes to quiescence");
    }

    #[test]
    fn ordinary_client_verifies_served_object_membership_absence_and_unproven() {
        let scratch = ScratchDirectory::new();
        let mut node = proof_capable_node(&scratch);
        let (present_ref, _, present_oid) = publish_member_and_outcome(&node);
        node.transition_cell_state(
            CellState::VerifiedReadOnly,
            CellTransitionCause::AuthorityObservation,
            fgit_types::HeadGeneration::try_new(2)
                .expect("the published successor is generation 2"),
        )
        .expect("the observed cell may enter verified-read serving");

        let independently_fetched = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .expect("the ordinary client fetches an authentic authority head")
            .body()
            .expect("the independently authenticated body decodes");

        let absent_oid = GitOid::Sha1(fgit_types::native::GitOidSha1::from_bytes([0x99; 20]));
        let closure_root = object_closure_merkle_root(&[present_oid]).expect("closure root");
        let pin = PinnedAuthorityHead::new_with_object_closure(
            independently_fetched.clone(),
            closure_root,
        );

        // Unproven query
        let unproven = node
            .runtime()
            .block_on(node.serve_current_verified_read_in(
                &node.request_context(),
                &RefVisibility::new(),
                ReadLabel::current(),
                VerifiedReadCapability::Unproven,
                VerifiedReadQuery::Object(present_oid),
            ))
            .expect("unproven object read succeeds");
        assert_eq!(
            unproven.response(),
            &ReadResponse::Unproven(Box::new(UnprovenReadAnswer::Object {
                oid: present_oid,
                present: true,
            }))
        );

        // Verified member query
        let member = node
            .runtime()
            .block_on(node.serve_current_verified_read_in(
                &node.request_context(),
                &RefVisibility::new(),
                ReadLabel::current(),
                VerifiedReadCapability::EnvelopeV1,
                VerifiedReadQuery::Object(present_oid),
            ))
            .expect("verified object read succeeds");
        let ReadResponse::Verified(member_envelope) = member.response() else {
            panic!("expected envelope");
        };
        assert_eq!(
            verify_envelope(&pin, member_envelope),
            Ok(VerifiedMembership::Object)
        );

        // Verified absence query
        let absence = node
            .runtime()
            .block_on(node.serve_current_verified_read_in(
                &node.request_context(),
                &RefVisibility::new(),
                ReadLabel::current(),
                VerifiedReadCapability::EnvelopeV1,
                VerifiedReadQuery::Object(absent_oid),
            ))
            .expect("verified object absence succeeds");
        let ReadResponse::Verified(absence_envelope) = absence.response() else {
            panic!("expected envelope");
        };
        assert_eq!(
            verify_envelope(&pin, absence_envelope),
            Ok(VerifiedMembership::ObjectAbsence)
        );

        // Disclosure gate: if the only ref pointing to present_oid is hidden, object query is denied
        let mut hides_ref = RefVisibility::new();
        hides_ref
            .push_rule(present_ref.as_bytes(), &WireLimits::default())
            .expect("hide rule");
        let denied = node.runtime().block_on(node.serve_current_verified_read_in(
            &node.request_context(),
            &hides_ref,
            ReadLabel::current(),
            VerifiedReadCapability::EnvelopeV1,
            VerifiedReadQuery::Object(present_oid),
        ));
        assert!(matches!(
            denied,
            Err(VerifiedReadServingRefusal::VerifiedRead(refusal))
                if refusal.as_ref() == &VerifiedReadRefusal::ObjectNotFoundOrUnauthorized
        ));

        node.shutdown().expect("clean shutdown");
    }
    /// A neighbour is a second object identity, and it needs its own permission.
    ///
    /// `authorize_object_absence` gates the object that was *asked about*. An
    /// ordered absence proof then serialises the objects bracketing the gap, so
    /// without this guard a caller authorized for one object learns up to two
    /// others by asking about a gap beside them.
    ///
    /// The policy here is the production [`DisclosureScope`], not a stand-in:
    /// an object is disclosable unless every ref pointing at it is hidden. The
    /// first two assertions establish that the policy actually discriminates
    /// between these two objects, because a guard tested against a policy that
    /// permits everything would pass while checking nothing.
    #[test]
    fn absence_proof_neighbours_are_authorized_before_they_are_disclosed() {
        fn oid(seed: u8) -> GitOid {
            GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
        }
        fn name(text: &str) -> RefName {
            RefName::try_new(text.as_bytes()).expect("an admissible ref name")
        }
        fn neighbour(seed: u8, index: usize) -> Box<ObjectClosureNeighbour> {
            Box::new(ObjectClosureNeighbour::new(
                oid(seed),
                MerkleProof::new(index, 2, Vec::new()),
            ))
        }

        let open = oid(0x20);
        let closed = oid(0x30);
        let mut refs = BTreeMap::new();
        refs.insert(name("refs/heads/open"), open);
        refs.insert(name("refs/secret/closed"), closed);

        let mut snapshot = RefVisibility::new();
        snapshot
            .push_rule(b"refs/secret/closed", &WireLimits::default())
            .expect("an exact name is a valid hide rule");
        let current = RefVisibility::new();
        let scope = DisclosureScope {
            snapshot: &snapshot,
            current: &current,
            snapshot_refs: &refs,
        };

        // The policy discriminates. Without this the rest proves nothing.
        assert!(
            scope.permits_object_disclosure(&open),
            "an object reachable by a visible ref is disclosable"
        );
        assert!(
            !scope.permits_object_disclosure(&closed),
            "an object reachable only by a hidden ref is not"
        );

        let denied = |proof: &ObjectClosureNonMembershipProof| {
            matches!(
                authorize_disclosed_neighbours(&scope, proof),
                Err(VerifiedReadServingRefusal::VerifiedRead(refusal))
                    if matches!(*refusal, VerifiedReadRefusal::ObjectNotFoundOrUnauthorized)
            )
        };

        // Every arm that carries a neighbour, so no position is left unguarded.
        assert!(
            denied(&ObjectClosureNonMembershipProof::BeforeFirst {
                first: neighbour(0x30, 0),
            }),
            "a hidden first neighbour must not be disclosed"
        );
        assert!(
            denied(&ObjectClosureNonMembershipProof::AfterLast {
                last: neighbour(0x30, 1),
            }),
            "a hidden last neighbour must not be disclosed"
        );
        assert!(
            denied(&ObjectClosureNonMembershipProof::Between {
                predecessor: neighbour(0x20, 0),
                successor: neighbour(0x30, 1),
            }),
            "one authorized neighbour does not license the other"
        );

        // The permitted twins. A guard that refused everything would satisfy
        // every assertion above and still be wrong.
        assert!(
            authorize_disclosed_neighbours(
                &scope,
                &ObjectClosureNonMembershipProof::Between {
                    predecessor: neighbour(0x20, 0),
                    successor: neighbour(0x20, 1),
                }
            )
            .is_ok(),
            "an absence bracketed by disclosable objects is still servable"
        );
        assert!(
            authorize_disclosed_neighbours(&scope, &ObjectClosureNonMembershipProof::EmptyClosure)
                .is_ok(),
            "an empty closure names no object but the one queried"
        );
    }
}
