# D3 — SHA-256 Repository Support

Architecture decision record for plan decision **D3**: whether native SHA-256
repository creation and import are in v1, or a follow-on.

**Status:** DECIDED — SHA-256 native repositories are **in v1**.
**Bead:** `frankengit-fg058-sha256-repos-8td`.
**Recorded by:** ChartreuseHorizon, 2026-08-24, under the GoldLotus ruling on that bead.

## Decision

1. **Native SHA-256 repositories are v1 scope.** A repository is created in one
   object format and stays in it. Both formats are first-class: neither is
   emulated in terms of the other.
2. **Transition mappings are in scope only where upstream Git defines them.**
   Where Git specifies a mapping between formats, FrankenGit may implement it and
   must verify it differentially against the pinned oracle. Where Git defines no
   mapping, FrankenGit **invents none** — no cross-format object equality, no
   synthesized correspondence table, no "best effort" translation. The unsupported
   case is a typed refusal.
3. **Mixed-format traffic fails closed.** A SHA-1 object or pack offered to a
   SHA-256 repository is refused during bounded validation, and the reverse
   likewise. Refusal happens before any bytes become retention roots.

### Why not defer to a follow-on

The type boundaries already exist — `fg002b` made SHA-1 and SHA-256 distinct OID
types and the compatibility matrix bans digest-byte aliasing. So the remaining
work is *format plumbing*, not a new identity model. Deferring would leave the
plumbing half-built behind types that already claim to distinguish the formats,
which is the "convenient early abstraction that contradicts the final system"
that `AGENTS.md` §1 names as the principal risk.

## Collision-defense asymmetry

The sha1cd-style collision-detection path applies to **SHA-1 repositories only**.
SHA-256 repositories skip it. This is deliberate and is recorded here because the
asymmetry looks like a missing control when read from the SHA-256 side:
collision detection exists to defend a hash whose collision resistance is broken,
and applying it to SHA-256 would cost work while defending nothing.

Consequence for evidence: any claim of the form "the collision-defense profile is
uniform across formats" is false by construction, and a test asserting uniformity
would be asserting a defect.

## Evidence plan

Per `AGENTS.md` §16.3, each line below names what would falsify it. Differential
lanes use the pinned, sandboxed upstream oracle only — never a production path
(§3.1).

| # | Claim | Evidence | Status |
|---|---|---|---|
| 1 | This decision is recorded | this document | done |
| 2 | Mixed-format objects/packs are refused, typed, both directions | format-matrix tests, each paired with a permitted twin in the matching format | pending |
| 3 | init / hash / pack round-trip natively in SHA-256 | library-level round-trips over `OneNode` configured for SHA-256 | pending |
| 4 | clone / fetch match upstream Git byte-for-byte | `oracle.sh clone-loopback` against a pinned Git that supports SHA-256 repositories | pending |
| 5 | push round-trips | **blocked** — object-bearing push needs a production quarantine validator (`frankengit-production-quarantine-validator-n6kg`) | pending, gated |

Line 5 is recorded as pending rather than narrowed away. The bead stays open
until it lands; closing it earlier would be scope-narrowing while claiming
success, which §16.3 forbids.

**Every "pass" or "verified" recorded against these lines must name the commit
SHA it was observed at** (§16.2). Unbound claims are unsupported.

### A permitted twin is required, not optional

Refusal-only evidence is explicitly the weakest acceptable outcome (§16.3), so
each mixed-format refusal is paired with a near-identical permitted case in the
matching format. Without the twin, a refusal test passes just as well against
code that refuses *everything*, and proves nothing about format discrimination.

## Known gap in the delivery path

Measured at `acff002`: the `fg` command-line surface cannot create a SHA-256
repository. `crates/fgit-cli/src/lib.rs:314` constructs object identities with
`GitHashAlgorithm::Sha1` and the CLI exposes no object-format option.

`OneNode` itself does support both formats — `crates/fgit-node/src/lib.rs:3618`
provides `with_object_format`, exercised today only from tests.

This splits evidence lines 3 and 4:

- **Library-level round-trips are reachable now**, through the node configuration
  API.
- **End-to-end lanes are not**, because the e2e suites drive the assembled `fg`
  binary, and no invocation of it produces a SHA-256 repository. Line 4 needs
  either an object-format option on `fg init` — a public-surface change to
  `fgit-cli`, owned elsewhere under §16.1 — or a differential lane driven from a
  test binary rather than the CLI.

Recording this in the ADR rather than only on the bead, because it is a
structural property of the delivery path and the next person to pick up a
SHA-256 lane will hit it in the same place.

## What this decision does not settle

- Which pinned upstream Git versions carry SHA-256 support. `registries/` and
  `scripts/e2e/oracle/pins.tsv` own that, and the differential lane must read the
  pin rather than assume a version.
- Whether transition mappings are implemented in v1 — only that if they are, they
  follow Git's definition and nothing else. No mapping is authorized by this
  document.
- Anything about fetch-versus-push capability symmetry. Those are separate
  service matrices (§6). There is no standardized "protocol v2 push", and this
  decision relies on no such thing; push compatibility means `git-receive-pack`.
