# Sponsored agent credentials for source reads and forge metadata

This profile gives an agent its own repository-scoped principal and records its
human or service sponsor in canonical admission evidence. It supports the native
HTTP current-source browsing and context, separately granted source history and
reference comparison, issue, pull-request metadata and
conversation, standalone discussion, and single-transaction outcome endpoints,
plus the explicit MCP source and metadata profile. Each request creates a real bounded
`IntentRun`; the bearer alone is not an execution or publication capability.

## Issue and use a credential

The local operator generates the secret into a new private file. Neither command
arguments nor JSON receipts carry the secret:

```sh
fg agent-credential generate-token --output ./agent.token
```

Issue an immutable grant with explicit repository incarnation, agent, sponsor,
times, and scopes. Replace the example IDs and Unix timestamps with the intended
values. Keep the timestamps, token and key unchanged on an exact retry.

```sh
fg agent-credential issue ./repository TENANT_ID REPOSITORY_ID \
  --trusted-local --incarnation INCARNATION_ID \
  --principal SPONSOR_ID --agent AGENT_ID --sponsor-kind human \
  --token-file ./agent.token --issued-at ISSUED_UNIX_SECONDS \
  --expires-at EXPIRES_UNIX_SECONDS \
  --operations issues-read,issues-write,pulls-read,pulls-write,outcomes-read \
  --idempotency-key issue-agent-credential-1
```

`--principal` is the issuer and sponsor at issuance. This is an explicit
trusted-local operator assertion of the sponsor's identity and kind, not remote
human authentication. Before a review-protection policy is installed, the local
operator owns bootstrap administration. Once one exists, issuance and revocation
require its current administrator set. An administrator may revoke another
sponsor's grant. HTTP, SSH and agent sessions cannot issue or revoke credentials.

An issued token is exactly `fgagent_` followed by 64 lowercase hexadecimal digits.
Use it in the native HTTP `Authorization: Bearer ...` header. Existing server
feature switches, route grammars, body limits, quotas, exact predecessor checks,
and idempotency-key requirements continue to apply. There is no additional
credential-file row to configure for an issued agent. The server reads the
canonical grant for every request, without a cached-grant fallback.

Authentication and scope refusals retain each native API's JSON error contract
and Bearer-only challenge. Recovery refusals explicitly preserve unknown outcome
status; a rejected lookup never proves that the original mutation failed.

The Node operators `scripts/remote_issue.mjs` and `scripts/remote_pull.mjs` also
accept this private token file. Use the agent ID as `scope.principal_id` and the
grant's exact repository incarnation in the saved input. Follow the existing
[issue](REMOTE_ISSUES.md) and [pull-request](REMOTE_PULL_REQUESTS.md) preparation,
inspection, send and original-key recovery commands. The PR operator accepts an
agent credential for `open`, `update`, `close`, `reopen` and `comment`; it refuses
code-publication and review actions with that credential before networking.
Browser forms retain their existing ordinary-token profile.
The protection-admin operator and browser protection client accept optional
ordinary principal evidence in native recovery replies without changing their
policy-administration grants, exact saved keys or seal checks. Agent credentials
remain unavailable for policy administration.

Preparation fingerprints every token byte, including `fgagent_`. Sending still
requires the original token and saved key. Recovery may use a newly authorized
credential for the same agent after rotation or revocation. The shared outcome
reader retains and checks the native optional principal-provenance fields,
including the original sponsor, credential and run witness. It does not replace
that witness with the credential used for recovery. Optional evidence
unavailability does not erase an established terminal decision. Legacy
64-hexadecimal-token inputs and retained outcomes remain readable.
Outcome JSON refuses duplicate keys, including escaped-equivalent spellings,
before interpreting principal evidence. Parsing remains bounded to 16 KiB and
16 nesting levels.
Native source-import recovery also validates the CLI's optional principal
evidence, including exact u64 witness times, while retaining its existing local
observation schema. This grants no agent source-import capability.

| Explicit scope | Available operations |
| --- | --- |
| `issues-read` | Issue listing, history and search |
| `issues-write` | Supported native issue commands and append intents |
| `pulls-read` | Pull-request metadata and conversation reads |
| `pulls-write` | Pull-request lifecycle metadata and conversation commands |
| `discussions-read` | Standalone discussion reads |
| `discussions-write` | Standalone discussion commands |
| `outcomes-read` | Own principal's single-transaction recovery by original key |
| `source-read` | Bounded current source, reference listing, tag inspection, search, context and agent-context reads |
| `source-history-read` | Bounded visible-ref commit history, blame, historical trees/files and reference diffs |

Scopes are independent: write does not imply read. Unknown scopes are rejected.
Current-source reads require an explicit `source-read` grant; history and
comparison reads require `source-history-read`. Both require the HTTP server's
source-read feature switch or the MCP launch ceilings described below.
Metadata scopes, including all seven previously
available flags, grant no source access. The HTTP adapter admits a closed set of
current-source and history routes; it does not interpret arbitrary GET requests or the
ordinary token's broader `read` scope as agent permission. Source selection and
disclosure retain the existing canonical hidden-ref and visibility checks.

Git upload-pack/receive-pack, verified-blob streaming, bundles,
candidate preparation or inspection, PR-specific diffs,
reviews, checks, merges, queue operations, milestones, notifications, policy
administration, workflow and artifact access, process execution, secrets and
external effects are outside this profile. MCP offers the closed sponsored
source and metadata tools described below and keeps its existing trusted-local
profile. Its source ceiling does not include the operator profile's candidate
or bundle tools. History tools require their independent credential scope.

A separate source-only credential can be issued with `--operations source-read`.
Combine it with a metadata scope only when both capabilities are intended. Source
requests use the same per-request canonical authentication, revocation checks,
finite IntentRun and input/output envelopes as the metadata routes. They do not
publish repository state or create a durable autonomous execution run.

### Independently grant history and comparison

Use `--operations source-history-read` to grant read-only historical analysis.
Use `--operations source-read,source-history-read` when an agent needs both the
current-source tools and the history tools. Neither flag grants the other
operation family, and existing credentials gain no new permission when a node
is upgraded. A sponsor must issue a new credential to change an immutable grant.

These are independent API permissions, not a secrecy boundary between current
and older source bytes. Historical selection may name the current ref tip, and
blame and comparison also disclose current-tip content. A history grant does
not enable current-source search, indexes, retrieval or agent-context tools.

The HTTP service requires its existing `--allow-source` switch and authenticates
the new operation on each of these POST routes:

| Route suffix under `/api/v1/source/` | Selection |
| --- | --- |
| `log` | Bounded commit-DAG, exact-path or first-parent history of a visible ref |
| `blame` | Bounded line ancestry for a file selected through a visible ref |
| `historical-tree`, `historical-blob` | A tree or file in a commit proven reachable from the selected visible ref |
| `diff` | Direct or merge-base comparison of two currently visible references |

Each route uses the existing form grammar, snapshot/commit pins, traversal and
response limits. The grant does not authorize an arbitrary object ID or a hidden
reference. Current canonical hidden-ref policy still applies to historical
selection. Native author and committer fields are untrusted source metadata,
not an authenticated human identity. The PR-specific diff route remains outside
this scope; a reference comparison does not disclose PR metadata.

In sponsored MCP mode, `--allow-source` exposes the corresponding closed set:
`frankengit_source_log`, `frankengit_source_blame`,
`frankengit_source_historical_tree`, `frankengit_source_historical_blob`, and
`frankengit_source_compare`. Calls require `source-history-read` independently of
the launch ceiling. History access does not enable search, agent context, source
publication, candidate preparation, reviews, or Git transport. Native work and
response disclosure share the originally authenticated request deadline;
entering a history, blame or diff phase does not renew it.

### Current-source routes and authenticated context

The `source-read` route set consists of the following POST queries under the
repository's `/api/v1/source/` route. All use the existing bounded form grammar.

| Route suffix | Read surface |
| --- | --- |
| `commit` | Exact current visible commit body, at most 64 KiB; parent identities only, without ancestry traversal |
| `tree`, `blob` | Selected current visible tree and exact file bytes |
| `refs`, `tags/inspect` | Current visible references and selected tag target/annotation inspection |
| `search`, `search-batch`, `search-regex` | Bounded native literal and byte-regex source search |
| `search-index`, `search-symbols`, `search-symbols-index` | Lexical index and Rust declaration search with current source checks |
| `search-initial`, `context-initial`, `agent-context` | Generation-bound retrieval, source context and Agent Protocol context documents |

The [current-commit route](HTTP_SOURCE_API.md#selected-current-commit) lets a
source-only agent acquire [portable source packages](SELECTED_SOURCE_PACKAGE_OPERATOR.md),
[context byte proofs](SPARSE_SOURCE_PROOFS.md), and
[verified source archives](VERIFIED_SOURCE_ARCHIVE.md) using pinned commit/tree/blob
reads. It accepts only the current ref and optional head/commit comparisons;
it cannot select a historical or arbitrary object. The package command's optional
`--native-fg` authority-proof mode rejects sponsored tokens before acquisition
because `verified-blob` remains outside this grant. No new MCP tool is introduced.

A source grant covers the repository's visible current source. Path selectors
and query limits narrow an individual request; they are not a stored sparse-path
capability. Read-only route classification alone does not grant access: history
requires its separate scope, while bundle export and candidate preparation
remain excluded even where their native HTTP operation does not publish a
transaction. Read queries reject an
`Idempotency-Key`; the transport's internal request key never seals a write.

An agent-context response uses the
`agent-context-http-sponsored-agent-v1` profile. Its `sponsor.principal_id` is the
grant's authenticated human or service sponsor, while
`agent_authentication.principal_id` is the agent. The retained witness also names
the sponsor kind, credential ID, immutable grant root, original request-run
commitment, authentication time and bounded request expiry. The same witness is
bound into `request.agent_authentication`. None of these fields contains the
bearer or gives the document reusable authority. Caller-selected principal,
sponsor and run-ID fields are rejected.

The context run's expiry is bounded by the original authenticated request's
absolute wall-clock expiry and monotonic deadline. Parsing, index lookup and
source hydration cannot renew that lifetime. Retrieved text remains explicitly
untrusted source data, including any embedded instruction. Ordinary operator HTTP
credentials retain the existing `agent-context-http-credential-v1` profile.

## Use the credential with MCP

Launch either `fg mcp` or the standalone `fg-mcp` with the private credential
file and the exact repository incarnation. Select each desired tool ceiling
explicitly:

```sh
fg mcp ./repository TENANT_ID REPOSITORY_ID \
  --agent-token-file ./agent.token --expected-incarnation INCARNATION_ID \
  --allow-issues --allow-issue-writes \
  --allow-pulls --allow-pull-writes --allow-outcomes
```

`--agent-token-file` and `--trusted-local` are mutually exclusive. Agent mode
rejects `--principal`: the canonical credential supplies the agent and sponsor.
The file is read once at launch using the same bounded private-file reader as
credential issuance. Its contents are never accepted in tool arguments, printed
in receipts, or included in debug formatting. Replacing the file cannot retarget
an already running process; restart it to select a replacement credential.

The selected launch flags are ceilings, independently intersected with the
canonical credential on every tool call. Listing a tool does not authorize it.
A write-only launch exposes writes without read or recovery tools, and a
credential with only a write scope cannot use a separately selected read ceiling.
Discussion reads and writes use `--allow-discussions` and
`--allow-discussion-writes`. No metadata grant exposes the operator profile's
additional milestone, notification, check, review, event-feed, source, queue,
artifact, agent-context or administration tools. An unknown or unsupported tool
is refused before credential or repository lookup.

`--allow-pull-writes` with a canonical `pulls-write` scope admits the exact
metadata tools `frankengit_pull_open`, `frankengit_pull_update`,
`frankengit_pull_close`, `frankengit_pull_reopen`, `frankengit_pull_comment` and
`frankengit_pull_append_comment`. Reopening uses the existing native command:
an exact positive closed-PR version, full metadata and current source/target
tips on the original branches. It may refresh the explicit tips and title/body;
it cannot restore branches, reopen a merged PR or grant a review/merge operation.
Each retry reauthenticates the current credential, while a terminal retry after
credential rotation preserves the original agent/sponsor evidence. PR reads and
outcome queries retain their independent scopes.

For current-source access, issue a credential with `--operations source-read`
and select one or both independent source ceilings. Add `source-history-read`
to the credential when historical analysis is required:

```sh
fg mcp ./repository TENANT_ID REPOSITORY_ID \
  --agent-token-file ./agent.token --expected-incarnation INCARNATION_ID \
  --allow-source --allow-agent-context
```

| MCP launch ceiling | Required canonical scope | Exact sponsored tools |
| --- | --- | --- |
| `--allow-source` | `source-read` | `frankengit_source_tree`, `frankengit_source_blob`, `frankengit_source_search`, `frankengit_source_search_batch`, `frankengit_source_search_index`, `frankengit_source_symbols`, `frankengit_ref_list`, `frankengit_source_initial`, `frankengit_source_context` |
| `--allow-source` | `source-history-read` | `frankengit_source_log`, `frankengit_source_blame`, `frankengit_source_historical_tree`, `frankengit_source_historical_blob`, `frankengit_source_compare` |
| `--allow-agent-context` | `source-read` | `frankengit_agent_context` |

Each call requires its listed canonical scope. Neither launch flag implies the
other, and a metadata-only credential cannot use either. Source
search retains its existing bounded literal and regex operations. Structured
Initial, source-context and agent-context retrieval require existing current
indexes; reads do not create or rebuild them. Current visible-source filtering
and exact snapshot preconditions remain enforced by the native readers.
Credential issuance, revocation or other metadata changes advance the selected
authority head, so the default strict indexed tools return `source_index_stale`
until indexes cover that head, even when the Git commit is unchanged. Select
`index_source: "current-native-v1"` in Initial, source-context or agent-context
arguments to reuse existing generations after these metadata-only changes.
Current visible commit/tree identity must still match, and the response preserves
both current disclosure and original index provenance. Actual source movement,
visibility failure, missing required indexes and stale current-head pins refuse.
This mode grants no additional operation and does not rebuild indexes.

Dedicated persisted reads use the same verified source authority:
`frankengit_source_search_index` supports content/path pages with `source_mode`
`exact` or `revalidated`, and `frankengit_source_symbols` supports
`indexed-exact` or `indexed-current` alongside its default scan. Revalidated
modes retain current disclosure coordinates and original index provenance
separately. Continuation pages require the original source and generation pins
and independently authenticate the credential; a cursor cannot survive source
movement or revocation by granting access itself. Both handlers verify an active
source-read request before parsing or native reads, including direct dispatch.
An authentic metadata request, an expired request, or a completed response
reservation cannot substitute. Source/index budgets and whole-repository
omission coverage are unchanged; query path prefixes only narrow matching.

Sponsored MCP agent-context documents use
`agent-context-mcp-sponsored-agent-v1` with
`mcp-sponsored-agent-source-read-credential` authorization. The sponsor remains
the canonical grant's human or service sponsor. The top-level and request-bound
`agent_authentication` witnesses retain the actual agent, credential, grant root,
request-run commitment and original lifetime. A caller cannot substitute a
principal, sponsor or run ID. The host bridge verifies tenant, repository,
incarnation and Git object format before attaching source authority, and refuses
an expired or missing active request. Trusted-local MCP retains its existing
operator-asserted document profile and encoding.

Each call authenticates the current canonical grant and constructs a fresh
`IntentRun` bound to the complete canonical MCP tool name and arguments, its
single operation scope, and the original durable key. JSON-RPC IDs are transport
identifiers; retry an identical mutation with a new JSON-RPC ID and the same
`idempotency_key`. Reads use a fixed non-publication key. Writes and outcome
recovery receive the verified agent session, original key and monotonic deadline;
no caller field can replace them. Native admission still revalidates the grant
at publication. Own-principal outcome recovery retains the original decision
and sponsored principal evidence after rotation; another agent cannot read that
key. Existing metadata response schemas are unchanged.

The request reserves the transport's 256 KiB framing ceiling and 8 MiB response
ceiling plus its final LF; ordinary metadata JSON still has the existing 64 KiB
parser limit. Its deadline is bounded by credential expiry, 300 seconds, and any
shorter command timeout. Awaited node work uses the remaining deadline. The
completed reservation survives result construction and response encoding, and
stdio checks its deadline and emitted bytes before and after each write of at
most 16 KiB and around the final flush. Expiry or output failure closes the
session before another request executes. A blocking stdio write is cooperative:
bytes already handed to the operating system cannot be withdrawn, and the
checks do not promise preemption of that write. A partial reply or expired
response never proves that a submitted mutation did not commit.

## Inspect, revoke and rotate

```sh
fg agent-credential show ./repository TENANT_ID REPOSITORY_ID \
  --trusted-local --incarnation INCARNATION_ID

fg agent-credential revoke ./repository TENANT_ID REPOSITORY_ID \
  --trusted-local --incarnation INCARNATION_ID --principal ADMINISTRATOR_ID \
  --credential-id CREDENTIAL_SHA256_HEX --expected-version 1 \
  --idempotency-key revoke-agent-credential-1
```

The credential ID is the SHA-256 digest of the exact token bytes. The token file
may end in one LF, which the CLI removes before hashing. On Unix it must be a
private regular file without group/world permissions; generated files use 0600,
are created exclusively, and are synced before success is reported.

Issuance has aggregate version 1. Revocation has version 2 and retains the full
original grant. Revocation is permanent; rotating a credential requires a new
token and issuance. Multiple credentials for one agent must keep the same sponsor
and sponsor kind. Agents and sponsors cannot exchange roles, including after
revocation. The bounded registry retains at most 256 grants, including revoked
ones, and refuses further issuance at that limit. This initial profile does not
garbage-collect identity declarations.

Credential declarations stay out of scoped HTTP/MCP event feeds and repository
webhook deliveries, including wildcard and explicit event-kind subscriptions.
The trusted-local complete-history reader remains available to the operator.

## Publication and retry guarantees

Both issuance and revocation use the ordinary sealed metadata transaction and the
single `RepositoryAuthorityHead` CAS. An immutable grant body is inactive until
the authenticated forge frontier selects it. No Git reference moves when a
credential is issued or revoked.

Agent writes recheck the exact current grant at each candidate CAS basis. A
revocation that wins first invalidates a competing write when it replans. The
same check verifies agent, sponsor, sponsor kind, original grant root, tenant,
repository, incarnation, operation and validity interval. A retained agent
declaration also prevents an ordinary HTTP token, SSH key, operator assertion or
missing legacy authentication from treating that principal as a non-agent for a
new publication. This principal-kind rule is repository scoped.

Each HTTP request derives an `IntentRun` from the authenticated authority receipt,
credential, agent, sponsor, selected route operation, retry key and request-header
commitment. It reserves the actual bounded HTTP input/output envelopes. Metadata
requests permit one operation class. A `source-history-read` request permits
only `ReadCanonicalObject`. A `source-read` request permits exactly
`ReadCanonicalObject` and `ReadDerivedGeneration` so the same bounded run can
read native source and its authenticated search generations.
It grants no write, process or publication class. Every request lasts at most
300 seconds and never past the grant's expiry. The response writer measures
emitted bytes; source work and metadata publication retain the original
monotonic deadline and wall-clock validity ceiling. These are
request-envelope reservations, not measurements of whole-process CPU, RSS or
storage charges. Grants have a maximum lifetime of 30 days and use a half-open
`[issued_at, expires_at)` interval.

Terminal recovery precedes new-publication authorization in the canonical
drivers. A changed current grant cannot replace the original receipt. A revoked
or expired token cannot authenticate a new request, but a newly authorized
credential for the same agent, or a trusted-local operator recovering that exact
principal's key, can inspect the original decision. Neither an absent key nor a
timeout proves non-commit.

## Canonical formats and retained evidence

| Representation | New value |
| --- | --- |
| Forge aggregate discriminant | 13: sponsored agent credential |
| Forge event kind | 25: native credential change |
| Reference trace forge-event tag | 14: credential change |
| Principal snapshot | Schema 1.2: full agent authentication witness |
| Authentication policy evidence | Schema 1.5: full witness binding |

The required operation mask remains a canonical `u16`. `source-read` occupies
bit 7 (`0x0080`) and `source-history-read` occupies bit 8 (`0x0100`); the original
seven flags retain bits 0 through 6 and their exact encodings. A stored `0x007f`
grant still grants only the original metadata and outcome operations. A stored
`0x00ff` grant adds current-source access but grants no history operation. Issuing
either source capability requires an explicit new grant, and revocation must
retain the exact original operation mask. Bits 9 through 15 remain unknown and
refuse decoding or authentication. Upgrade every repository reader before
issuing a grant with a newly supported bit: an older reader fails closed on its
unknown flag; it must not strip the flag or fall back to another credential
profile. Existing grant bytes, event discriminants, request identities and
revocation semantics are unchanged.

The forge stream label is `agent/` plus 52 unpadded lowercase RFC 4648 base32
characters. This preserves all 256 digest bits within the 64-byte slug bound;
noncanonical case, padding and unused bits are refused. CLI IDs remain lowercase
hexadecimal.

The principal snapshot retains the agent, sponsor, attested sponsor kind,
credential ID, issuance root, run commitment, authentication time and request
expiry. Policy evidence compares the full witness, not merely an authentication
tag or strength. Principal snapshots 1.0/1.1 and policy schemas 1.0 through 1.4 keep
their historical bytes and semantics. A naked agent-method tag in an old schema
is rejected. Existing authentication predicates see single-factor strength;
this profile adds no human-kind, sponsor, membership, MFA or hardware policy
predicate. Ordinary HTTP and SSH credentials never imply a human principal.

This implements bounded current-source/history reads and metadata operations within
`frankengit-root-doctrine-x2mv.4.34`, and provides source access needed by the
agent-day integration in `frankengit-root-doctrine-x2mv.4.24`. Sponsored code
publication, policy-visible sponsor selectors, human-review requirements for
agent-produced code, broader agent runtime capabilities, and durable autonomous
execution remain separate work. The request-run commitment is provenance, not a
durable execution journal.

## Validation status and focused commands

The implementation adds canonical codec/lifecycle, authentication, policy replay,
legacy-method downgrade, real-node restart/revocation, private-token CLI, and real
TCP HTTP regression tests. The MCP extension adds real persisted-node tests for
all seven independent scopes, issue/PR/discussion publication, current-request
revocation, expiry, repository/incarnation binding, restart, credential rotation,
own-principal recovery, and retained sponsor evidence in both Git object formats.
Deterministic protocol writers cover expiry before disclosure, partial writes,
interrupted writes, flush, byte ceilings, and response-reservation cleanup. Their
presence is a coverage inventory, not a passing test result.

The sponsored MCP source tests use real persisted native source and lexical and
symbol indexes in both Git object formats. They cover the complete ten-tool
allowlist, independent launch ceilings, source-only and metadata-only scope
isolation, exact sponsor provenance, missing indexes without implicit rebuilding,
snapshot mismatch, revocation and rotation in the same process and after reopen,
and original request expiry through response disclosure. Persisted-index cases
also cover exact/current modes, content/path pagination, generation floors,
metadata-only movement with retained provenance, changed or deleted source,
direct-handler metadata-scope substitution and missing indexes without builds.
Node bridge tests
separately reject namespace, object-format, operation and lifetime substitution.
Existing trusted-local document fields remain absent where no canonical agent
witness exists; they are not replaced with synthetic null provenance.

Source-read regressions additionally freeze the historical seven-bit grant,
exercise source-only and combined operation masks, preserve issue/revoke codec
round trips, reject unknown operation bits and grant changes during revocation,
and require current lifetime and revocation evidence for source authentication.
The native HTTP fixtures import real SHA-1 and SHA-256 repositories and build
persisted lexical and symbol indexes. They exercise current-source reads and
agent-context documents, exact binary/untrusted bytes, distinct agent/sponsor
provenance, old-grant refusal, expired and revoked credentials, stale snapshots,
identity injection, output limits, service disablement and pool reopen. A
colliding ordinary credential cannot repair a revoked canonical agent token.
The route and credential unit tests separately freeze the closed source allowlist
and prevent a source scope from granting Git transport. Canonical hidden-ref
visibility continues through the existing native readers and its separate
integration tests. These tests must compile and pass at the candidate revision
before they establish a verified end-to-end claim.

`tests/operator/sponsored_metadata_credentials.test.mjs` covers both private
token spellings, exact fingerprints, closed provenance shapes and u64 times,
witness substitution, and real Node CLI send/rotated-recovery flows against a
controlled HTTP schema peer. That peer is not the native Rust server and does
not qualify native issuance, revocation or authorization.

At source revision `a5808f474637f68d5182f5d8c08da804beeb34c7`, the reference/CALM
suites completed with 176 passes, no failures, and one existing ignored test.
Pinned rustfmt and whitespace checks passed. Compilation of dependent crates was blocked before
first-party diagnostics by Asupersync being killed under the shared 8 GiB memory
limit. Serial metadata-only compilation, disabled debug symbols, bounded compiler
threads, and allocator-retention controls were attempted without changing
dependency source. The forge/identity/admission/node/CLI integration therefore
still requires a successful native compile and execution of its new tests.

A later strict remote release build at
`bafa9a87d4dfa43350c09ccaf9abd00a2964847e` reached first-party diagnostics and
failed with `E0004` in `fgit-txn::write_forge_event`: the new credential event
was missing from transaction canonicalization. The repair adds the already
specified tag 14 and exact entity encoding, with a literal shared by the
independent reference-trace regression, deterministic folding and entity
separation checks. The failed build produced no native image or operator-suite
result; the added transaction test still requires compiled execution.

At `8b3b6fdb61bf2339675f853ff55c3f9aba2f6e96`, the transaction crate's
offloaded `cargo check --all-targets` completed, including compilation of that
test. The native CLI build then reached three `E0277` errors in principal
recovery: concrete engine methods shadowed the `AsyncAuthorityStore` methods.
The repair explicitly selects the existing authority adapter for head reads,
receipt authentication and immutable reads, preserving its retry and typed
failure semantics. This second failed build also produced no native image or
operator-suite result. Test compilation is not test execution.

On a host with sufficient build memory, the focused follow-up is:

```sh
cargo check --locked -p fgit-forge -p fgit-identity -p fgit-admission -p fgit-node -p fgit-cli --all-targets -j 1
cargo test --locked -p fgit-forge -p fgit-identity agent -j 1
cargo test --locked -p fgit-admission agent -j 1
cargo test --locked -p fgit-node --lib agent_credentials -j 1 -- --test-threads=1
cargo test --locked -p fgit-node --lib socket_authority_expiry_survives_report_restart_and_cannot_be_extended -j 1
cargo test --locked -p fgit-cli agent_credentials -j 1
cargo test --locked -p fgit-cli --bin fg-mcp mcp::backend::agent::tests -j 1 -- --test-threads=1
cargo test --locked -p fgit-cli --bin fg-mcp agent_response_tests -j 1
cargo test --locked -p fgit-cli --bin fg-mcp agent_grant_tests -j 1
```

No bead completion or dependent build success is claimed by this profile's
initial handoff. Preserve the historical-schema and original-outcome tests when
extending its authority surface.
