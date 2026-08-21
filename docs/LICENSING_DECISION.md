# FrankenGit Licensing Decision

<!-- fgit-license-decision: UNRESOLVED -->

The HTML comment above is the single machine-readable form of this decision and
the only thing `scripts/license_gate.sh` reads. While it says `UNRESOLVED`,
`./scripts/verify.sh release` refuses with exit 3. To record the decision,
replace `UNRESOLVED` with the exact SPDX expression being adopted (for example
`Apache-2.0`, or `AGPL-3.0-only`), or with a named non-OSI model identifier for
a source-available outcome. The gate then requires that same string to appear in
`LICENSE`, `README.md`, and `CONTRIBUTING.md`, and to match root `Cargo.toml`'s
`license` field if one is set.

Nothing in this document decides D14. **The choice is the repository owner's.**
This document stops at assembling the options, the criteria, and the machinery
that makes deferral visible instead of silent.

**Status:** launch-blocking decision; no automatic license change has been made.  
**Current truth:** source-available under the repository's custom MIT-style rider, not OSI-approved open source.

## The inconsistency

FrankenGit is intended to become an open-source, self-hostable forge and also support a paid hosted service. The repository currently inherits a custom MIT-style license with an OpenAI/Anthropic exclusion. Because the rider denies rights to named parties and classes of use, it is not an OSI-approved open-source license. The code may be publicly readable and self-hostable by many users, but the current repository must be described as **source-available under a custom license**, not unqualifiedly as open source.

This affects adoption, Linux-distribution packaging, cloud marketplaces, enterprise procurement, contributor expectations, foundation eligibility, protocol neutrality, and whether competing hosted services may legally operate.

## Viable strategies

### Option A: AGPL-3.0-only community server plus commercial license

- Strong network copyleft: operators who modify and provide the service over a network must offer corresponding source.
- A separate commercial license can permit proprietary embedding or modifications.
- Good fit when the hosted service funds development and service-side improvements should flow back.
- Costs: some enterprises prohibit AGPL dependencies; contributor assignment or an explicit contributor agreement may be needed for clean dual licensing.

### Option B: Apache-2.0 core, commercial hosted/enterprise differentiation

- Broad adoption, explicit patent grant, easy enterprise consumption.
- Monetization comes from hosted operations, support, compliance, federation management, premium runners, global placement, and agent resources.
- Costs: competitors may host the same core; product execution and operational excellence must be the moat.

### Option C: MIT core

- Maximum simplicity and ecosystem compatibility.
- Weakest control over competing hosted offerings and proprietary derivatives.
- Appropriate only if broad protocol adoption matters more than protecting hosted differentiation.

### Option D: AGPL server with permissive clients, SDKs, schemas, and conformance kits

- Server remains reciprocal.
- Git clients, migration tools, SDKs, protocol schemas, compatibility fixtures, and verification utilities use Apache-2.0 or MIT to maximize interoperability.
- Often the strongest fit for an open forge that wants a commercial hosted service without making integrations legally awkward.

### Option E: time-delayed source-available license

- A Business Source License or Functional Source License can restrict competing production use and later convert to an open-source license.
- This is not open source during the restriction period and must be marketed honestly.
- It may reduce community trust for infrastructure intended as a neutral development substrate.

## Decision criteria

1. Is OSI-open-source status constitutional, or is public source sufficient?
2. Must third parties be free to run a competing public FrankenGit service?
3. Are proprietary enterprise modifications acceptable?
4. Which components need permissive licensing for ecosystem adoption?
5. What inbound contributor terms preserve the selected outbound model?
6. Is a patent grant required?
7. How should FrankenSuite sibling code with different terms be consumed?
8. What license applies to generated protocol corpora, conformance fixtures, and evidence schemas?

## Required process

1. Record the final choice in a superseding ADR.
2. Replace the provisional license before the first implementation release.
3. Define contributor inbound terms before accepting code from third parties.
4. License protocol specifications and conformance fixtures permissively unless an explicit contrary decision is made.
5. Add license-header, dependency-license, artifact-license, and source-bundle checks to local DSR release lanes.
6. Ensure installers, SBOMs, package metadata, websites, and README badges use the exact selected terms.

## Recording the decision (what "landing it" requires)

The decision is not landed when it is chosen; it is landed when every surface
states it. All of the following change in ONE commit, because a release shipping
a `LICENSE` and a `README` that disagree about the terms is worse than one that
has not decided:

| Surface | What must change |
|---|---|
| `docs/LICENSING_DECISION.md` | the `fgit-license-decision:` marker, plus rationale and the exact adopted texts |
| `LICENSE` | replaced wholesale with the adopted text; the rider is removed, not amended |
| `README.md` | the `## License` section states the adopted terms and drops the provisional wording |
| `CONTRIBUTING.md` | inbound contributor terms, which must be settled before third-party code is accepted |
| root `Cargo.toml` | `license` (SPDX) or a `license-file` pointing at the adopted `LICENSE` |
| release lane | nothing: `scripts/license_gate.sh` starts passing on its own once the above agree |

If the adopted model differs per component — option D splits a reciprocal server
from permissive clients, SDKs, schemas, and conformance kits — each component's
`Cargo.toml` carries its own `license` and this document records the split
explicitly. The gate checks the root expression; a per-component split requires
extending it in the same commit that introduces the split, which is part of
landing the decision rather than a follow-up.

## Why deferral is enforced rather than remembered

`./scripts/verify.sh release` already refuses today, but only because no
releasable binary exists. That refusal disappears the moment FG-035/FG-091 make
releases real. A launch-blocking requirement riding on an unrelated temporary
refusal is not enforced — it has merely never been tested. The D14 gate is
therefore separate and runs first, so lifting the dormancy refusal cannot
silently lift this one with it.

## Provisional documentation rule

Until that decision lands:

- say **public, self-hostable, source-available architecture**;
- say the project **intends to select a genuine open-source model**;
- do not use an OSI badge;
- do not claim the current custom rider is ordinary MIT;
- do not accept outside code without explicit inbound terms;
- do not let dependency metadata silently imply a different license.
