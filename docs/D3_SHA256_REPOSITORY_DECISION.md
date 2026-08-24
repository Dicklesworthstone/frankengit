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
| 2 | Mixed-format objects/packs are refused, typed | covered in `fgit-atp-git` (both raise sites, each naming the rejected identity), `fgit-admission`, `fgit-authority`, and `fgit-pack`'s commit-graph site (`05421c9`) | done, except 3 of 5 `fgit-pack` raise sites: `writer.rs:775`, `midx.rs:263`, `midx.rs:413` |
| 3 | init / hash round-trip natively in SHA-256 | `fgit-node/tests/sha256_format_matrix.rs`, 5 tests, observed passing at `72edf46` | done (`b14c901`) |
| 4 | clone / fetch match upstream Git byte-for-byte | `oracle.sh clone-loopback` against a pinned Git that supports SHA-256 repositories | **blocked** on `lozg` (format not persisted, so `serve` opens SHA-256 as SHA-1) |
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

**Resolved in part, and the remainder is deeper than first recorded.**

The original gap was that the `fg` command line could not create a SHA-256
repository at all. That is fixed: `fg init <root> <tenant> <repo> [sha1|sha256]`
selects the format, and an unrecognised token is a typed refusal rather than a
silent default (commit `9c901cd`).

What remains is the reason the end-to-end differential lane is still unreachable,
and it is not a missing command-line flag:

> **A repository's object format is never recorded.** `NodeConfig`'s
> `object_format` is config-only — nothing persists or validates it — so
> `OneNode::open_existing` takes the format from whatever `NodeConfig` the caller
> hands it. Every command that opens an existing repository therefore
> reconstructs it from the default, and a SHA-256 repository is opened, served
> and advertised as SHA-1, silently.

That is the same defect class as `fg058.1` (the git-daemon omitting
`object-format` for SHA-256 repositories), one layer down: there the format was
known and not advertised; here it is not known at all.

**The correct fix is persistence, not more arguments.** The vehicle already
exists — `RepositoryConfigurationBody` in `fgit-codec`, a persisted canonical
body whose sibling field `root_layout` already carries exactly this discipline:
it "refuses a code point this build does not know rather than falling back to a
default", because reading it wrong "would produce a confident wrong answer about
what the repository contains". Both fields are permanent, per-repository, and
catastrophic to default.

This is why no format argument was added to `serve`, `doctor`, `export` or
`import`. Threading the format through five commands would be the convenient
early abstraction §1 warns about: the final system *reads* the format from the
repository rather than being told it, so those arguments would exist only to be
removed. Tracked as `frankengit-lozg`, which also records that adding a field to
a v1 canonical body is a §5.2 schema question requiring an owner ruling, and
that it should sequence after `ls44` rather than race it.

**Consequence for evidence line 4:** the clone/fetch differential stays blocked
until the format is persisted, because the lane must `serve` a SHA-256
repository and have it advertise `object-format=sha256`.

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
