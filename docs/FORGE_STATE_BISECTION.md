# Find the first matching published forge state

`fg bisect` answers historical questions about native forge state without checking
out source, running tests, executing a predicate command, or changing repository
state. It is not a replacement for source-code `git bisect`.

```sh
fg --timeout-secs 120 bisect ./fgit-data \
  11111111111111111111111111111111 \
  22222222222222222222222222222222 \
  --trusted-local --issue 17 --state closed
```

The default inclusive range is decision `1` through the latest decision in one
authenticated authority observation. `--start` and `--end` narrow it. They must
name **published batch endpoints**: an atomic batch with multiple decisions has
one externally observable resulting state, not a sequence of intermediate states.
The command searches the actual endpoints, not every integer in the interval.
A start/end inside an atomic batch refuses instead of inventing a snapshot.

## Predicates

Choose exactly one selector, using the same storage/tenant/repository prefix:

```text
--ref refs/heads/main --equals <native-object-id>
--ref refs/heads/main --absent
--policy-at-least 4
--issue 17 --state open
--issue 17 --state closed
--pull 23 --state open
--pull 23 --state closed
--pull 23 --state merged
```

Native object IDs use the opened repository's SHA-1 or SHA-256 domain. Zero IDs
are invalid: use `--absent`. Issue/PR histories use their native event owners and
exact version transitions. An issue or PR not yet created does not match any
state. Legacy or unsupported PR events refuse rather than silently evaluating
as false. Native fast-forward and merge events count as merged states.

Refs and lifecycle states may change repeatedly. Their search is exhaustive and
bounded, so a temporary match between two nonmatching states is not skipped.
For example, open/closed/open/closed returns the first closed publication, even
though the state was subsequently reopened. `--start` can select the later one.

Policy thresholds use logarithmic search probes **only after** the complete
loaded history is checked for nondecreasing policy epochs. History acquisition,
authentication and folding remain linear work; the command does not claim
logarithmic physical I/O. There is no CLI option to assume arbitrary monotonicity.
The lower-level forge engine's legacy monotone contract remains explicitly
conditional on the caller supplying a true shape guarantee.

## Pins, limits and failures

`--expected-head` accepts the exact `source_head` token from a prior receipt,
including algorithm and codec version. `--expected-incarnation` fences the
repository instance. The current head is compared both before the search and at
the end; movement refuses instead of combining observations. This final read is
not a lock against a write occurring afterward.

One finite command request context covers all reads, folding and revalidation.
`fg --timeout-secs ... bisect ...` sets that existing command timeout.
`--max-probes` accepts 1 through 4096, default 4096. Exhaustion yields a refused,
incomplete receipt, never a complete no-match result.

The profile admits at most 4096 decision batches and 65536 events **after** the
existing bounded native history reader loads them. That reader retains its own
65536-edge ceiling and runtime limits. This is not a streaming-memory guarantee.
Missing, pruned, corrupt or incomplete history refuses; offline capsules and
partial-history recovery are not supported by this profile. CLI output is capped
at 2 MiB. No completed output is written before node shutdown succeeds; write
and flush failures produce a nonzero exit.

Exit codes are `0` for a match, `1` for a complete no-match result, and `2` for an
invalid, refused, incomplete, unavailable or output-failure result. A diagnostic
error before a search receipt is available goes to stderr with `complete:false`.

## Diagnostic receipt

JSON records the exact query, native format, tenant/repository/incarnation,
observed authority and policy epoch, publication-domain digest, resource limits,
strategy, status and every evaluated probe. Decision sequences and other u64
coordinates are decimal strings to avoid JavaScript numeric rounding.
`first_match` is meaningful only when `complete` is true.

`receipt_sha256` hashes the exact UTF-8 JSON object **before** that final field is
added. To verify a preserved output line, remove the final
`,"receipt_sha256":"<hex>"` field, restore the closing `}`, and hash those exact
bytes, without the output newline. Do not parse and reserialize first: whitespace
and field order are part of the diagnostic format. The binary regression helper
independently checks this procedure on every search receipt.

This digest is not a signature, remote attestation, authority capability or
retention pin. The command requires explicit whole-repository **trusted local**
operator access, including hidden refs. It authenticates stored history, not a
remote caller identity; it must not be exposed remotely as a disclosure bypass.

## Verification

```sh
cargo test -p fgit-forge --test forge_bisection
cargo test -p fgit-node --lib source_retrieval::bisection:: -- --test-threads=2
cargo test -p fgit-cli --bin fg bisect_command::
FG_BIN=/path/to/prebuilt/fg bash scripts/e2e/suites/forge/bisection.sh
```

The binary campaign creates isolated SHA-1 and SHA-256 nodes, publishes native
issue/ref/PR/policy changes, fast-forwards a real descendant commit, checks
transient first matches, pairs failures with successful queries, independently
verifies receipt hashes, and repeats queries in fresh processes after the source
path is removed from its original location. It uses no system Git. Tests do not
establish a full-workspace, remote-disclosure or offline-recovery conformance gate.
