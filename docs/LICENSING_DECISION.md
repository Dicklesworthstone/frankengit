# FrankenGit Licensing Decision

**Status:** Launch-blocking decision; no automatic license change has been made.

## The inconsistency

FrankenGit is intended to become an open-source, self-hostable forge and also support a paid hosted service. The repository currently inherits a custom MIT-style license with an OpenAI/Anthropic exclusion. Because the rider denies rights to named parties and classes of use, it is not an OSI-approved open-source license. The code can be publicly readable and self-hostable by many users, but it should be described as **source-available under a custom license**, not unqualifiedly as open source.

This affects adoption, Linux-distribution packaging, cloud marketplaces, enterprise procurement, contributor expectations, foundation eligibility, and whether competing hosted services may legally operate.

## Viable strategies

### Option A: AGPL-3.0-only community server plus commercial license

- Strong network copyleft: operators who modify and provide the service over a network must offer corresponding source.
- A separate commercial license can permit proprietary embedding or modifications.
- Good fit when the hosted service funds development and service-side improvements should flow back.
- Costs: some enterprises prohibit AGPL dependencies; contributor agreement or copyright assignment may be needed for clean dual licensing.

### Option B: Apache-2.0 core, commercial hosted/enterprise differentiation

- Broad adoption, explicit patent grant, easy enterprise consumption.
- Monetization comes from hosted operations, support, compliance, federation management, premium runners, or separately licensed enterprise modules—not exclusionary core licensing.
- Costs: competitors may host the same core; product execution and operational excellence must be the moat.

### Option C: MIT core

- Maximum simplicity and ecosystem compatibility.
- Weakest control over competing hosted offerings and proprietary derivatives.
- Appropriate only if broad protocol adoption matters more than protecting hosted differentiation.

### Option D: AGPL core with an Apache/MIT client and protocol SDK

- Server remains reciprocal.
- Git clients, migration tools, SDKs, schemas, and conformance kits use a permissive license to maximize interoperability.
- Often the strongest fit for an open forge that wants a commercial hosted service without making integrations legally awkward.

### Option E: Time-delayed source-available license

- A Business Source License or Functional Source License can restrict competing production use and later convert to an open-source license.
- This is not open source during the restriction period and must be marketed honestly.
- It may reduce community trust for infrastructure intended as a neutral development substrate.

## Recommended decision process

1. Decide whether “open source” in the product thesis is a constitutional requirement or a looser synonym for public source.
2. Decide whether third parties must be allowed to run a competing public FrankenGit service.
3. Decide whether proprietary enterprise modifications are acceptable.
4. Choose contributor inbound terms compatible with the outbound model.
5. License protocol specifications and conformance fixtures permissively even if the server uses copyleft.
6. Record the choice in an ADR and replace the current temporary license before the first code release.
7. Add automated license-header, dependency-license, and release-artifact checks.

## Provisional documentation rule

Until that decision lands:

- say **public, self-hostable, source-available architecture**;
- say the project **intends to select a genuine open-source model**;
- do not use an OSI badge;
- do not claim the current custom rider is ordinary MIT;
- do not accept contributions without making inbound licensing expectations explicit.