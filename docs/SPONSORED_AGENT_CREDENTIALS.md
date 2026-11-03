# Sponsored agent credentials for forge metadata

This profile gives an agent its own repository-scoped principal and records its
human or service sponsor in canonical admission evidence. It supports the native
HTTP issue, pull-request metadata and conversation, standalone discussion, and
single-transaction outcome endpoints. Each request creates a real bounded
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

| Explicit scope | Available operations |
| --- | --- |
| `issues-read` | Issue listing, history and search |
| `issues-write` | Supported native issue commands and append intents |
| `pulls-read` | Pull-request metadata and conversation reads |
| `pulls-write` | Pull-request lifecycle metadata and conversation commands |
| `discussions-read` | Standalone discussion reads |
| `discussions-write` | Standalone discussion commands |
| `outcomes-read` | Own principal's single-transaction recovery by original key |

Scopes are independent: write does not imply read. Unknown scopes are rejected.
Source/Git access, candidate preparation, reviews, checks, merges, queue operations,
milestones, notifications, policy administration, artifact access, process
execution, secrets and external effects are outside this profile. MCP continues
to use its existing trusted-local operator profile.

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
commitment. The run permits one operation class and reserves the actual bounded
HTTP input/output envelopes. It lasts at most 300 seconds and never past the
grant's expiry. The response writer measures emitted bytes; metadata publication
checks both a monotonic deadline and the grant's wall-clock validity. These are
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

This implements the bounded metadata part of
`frankengit-root-doctrine-x2mv.4.34`. Sponsored code publication, policy-visible
sponsor selectors, human-review requirements for agent-produced code, broader
agent runtime capabilities, and durable autonomous execution remain separate
work. The request-run commitment is provenance, not a durable execution journal.

## Validation status and focused commands

The implementation adds canonical codec/lifecycle, authentication, policy replay,
legacy-method downgrade, real-node restart/revocation, private-token CLI, and real
TCP HTTP regression tests. Their presence is a coverage inventory, not a passing
test result.

During the implementation session, the reference/CALM suites completed with
176 passes, no failures, and one existing ignored test. Pinned rustfmt and
whitespace checks passed. Compilation of dependent crates was blocked before
first-party diagnostics by Asupersync being killed under the shared 8 GiB memory
limit. Serial metadata-only compilation, disabled debug symbols, bounded compiler
threads, and allocator-retention controls were attempted without changing
dependency source. The forge/identity/admission/node/CLI integration therefore
still requires a successful native compile and execution of its new tests.

On a host with sufficient build memory, the focused follow-up is:

```sh
cargo check --locked -p fgit-forge -p fgit-identity -p fgit-admission -p fgit-node -p fgit-cli --all-targets -j 1
cargo test --locked -p fgit-forge -p fgit-identity agent -j 1
cargo test --locked -p fgit-admission agent -j 1
cargo test --locked -p fgit-node --lib agent_credentials -j 1 -- --test-threads=1
cargo test --locked -p fgit-node --lib socket_authority_expiry_survives_report_restart_and_cannot_be_extended -j 1
cargo test --locked -p fgit-cli agent_credentials -j 1
```

No bead completion or dependent build success is claimed by this profile's
initial handoff. Preserve the historical-schema and original-outcome tests when
extending its authority surface.
