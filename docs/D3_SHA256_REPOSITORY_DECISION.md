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
| 2 | Mixed-format objects/packs are refused, typed | every raise site asserted, each with a permitted twin: `fgit-atp-git` (2), `fgit-admission`, `fgit-authority`, `fgit-pack` (5, closed by `05421c9`, `8133809`, `7e28acd`, `f174ec9`) | **done** |
| 3 | init / hash round-trip natively in SHA-256 | `fgit-node/tests/sha256_format_matrix.rs`, 5 tests, observed passing at `72edf46` | done (`b14c901`) |
| 4 | a pinned upstream Git clones a served SHA-256 repository, receiving the exact tip and a pack | `oracle.sh clone-loopback` with `git-2.54.0` in `scripts/e2e/suites/node/sha256_repo_roundtrip.sh`, 26 assertions | **done** (`20c2742`) |
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

**Both are now resolved.** `lozg` landed the persistence, and `fg serve` adopts
the stored format rather than being told it. Evidence line 4 is delivered
(`20c2742`).

## What the differential found: no HEAD symref

The clone lane immediately surfaced a compatibility gap, which is what a
differential exists for. A pinned `git-2.54.0` clone of an fg-served repository
exits 0 and receives everything — the correct tip as a remote-tracking ref, and
the object pack — but produces **no checked-out worktree**, leaving `HEAD`
dangling at the init default. The daemon advertises no `symref=HEAD:...`
capability, so Git cannot decide which branch to check out.

**This is not a SHA-256 defect.** A SHA-1 repository imported and served the
same way advertises no symref either — `ls-remote --symref` returns only
`refs/heads/main` in both cases. It is a Git-compatibility gap in its own right,
tracked as `frankengit-head-symref-canonical-state-iahh`.

It is recorded here because it bounds what line 4's evidence means: the
differential pins that content crosses the wire intact — tip identity and pack
arrival — and deliberately does **not** assert a checked-out worktree. Asserting
one would be asserting a capability this server does not claim, for either
format, which is the "test that asserts a defect" shape §16.3 warns about.

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
