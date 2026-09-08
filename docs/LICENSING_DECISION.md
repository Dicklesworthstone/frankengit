# FrankenGit Licensing Decision

<!-- fgit-license-decision: LicenseRef-MIT-OpenAI-Anthropic-Rider -->
<!-- fgit-license-osi: no -->

**Status:** RESOLVED by repository owner Jeffrey Emanuel on 2026-08-23 (D14).
**Decision:** retain `LicenseRef-MIT-OpenAI-Anthropic-Rider`, the MIT licence
plus the OpenAI/Anthropic rider already present in this repository. The
owner's decision ratified those terms; it did not replace the licence text.
**OSI-approved:** no. Describe the repository as source-available under this
exact identifier, rather than calling it OSI-approved open source or merely
“source-available” without identifying the terms.

## Binding consequences

The rider withholds rights from named parties and their affiliates or agents.
AGENTS.md §10 therefore forbids an open-source claim while those restrictions
hold. Naming the licence precisely and recording its non-OSI status are both
required. This document does not reopen the owner's choice.

`LICENSE` is the authoritative grant text. This decision, `README.md`,
`CONTRIBUTING.md`, Cargo metadata, source bundles, installers, SBOMs, release
assets and public descriptions must consistently identify the adopted terms.
A future component split or licence replacement requires a new owner decision
and coordinated metadata/gate changes; no implementation task may infer one.
The superseded proposal to remove the rider before the first release is not
an active requirement.

## Provenance

The owner decision was relayed on `frankengit-fg062-license-decision-cr5e` by
BatchOrchestrator at 2026-08-23 04:56 UTC. The owner identified MIT plus the
Anthropic/OpenAI rider as the already-decided standard and instructed agents
to correct vague licence wording. `LICENSE` already contained those terms.
The decision records that existing choice and supplies its exact identifier.

## Machine enforcement

The two HTML markers above are the single machine-readable decision consumed
by [`scripts/license_gate.sh`](../scripts/license_gate.sh). The first gives
the exact adopted identifier; the second records `no` for OSI approval.
The gate checks the named source/metadata surfaces and the absence of
inconsistent open-source claims. A successful licence check alone does not
establish a releasable binary, target matrix or completed release.

The gate retains its explicit refusal for `UNRESOLVED` and malformed or
inconsistent markers. That mechanism supports future audited changes; it does
not mean D14 is currently unresolved. Any future owner-authorized change must
update every affected surface together, preserve inbound/outbound consistency
and keep the gate aligned with the actual grant. Do not alter the gate merely
to make contradictory prose pass.

## Historical alternatives — not adopted

Before the 2026-08-23 ruling, the design considered:

- an AGPL community server with a separate commercial licence;
- an Apache-2.0 core with commercial hosted differentiation;
- an MIT core without the rider;
- an AGPL server with permissive clients, schemas and conformance kits;
- a time-delayed source-available model.

The comparison considered ecosystem adoption, hosted competition, proprietary
modifications, patents, contributor terms, sibling licensing and generated
artifacts. None of those alternatives was selected by D14. The former
instructions to select an open-source model, replace `LICENSE` wholesale and
remove its rider were pre-decision proposals, superseded by the recorded
owner ruling. They are retained here as historical context, not release gates
or authority for an agent to change the licence.
