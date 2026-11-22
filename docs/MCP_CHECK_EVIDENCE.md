# Read canonical PR check evidence through MCP

`frankengit_pull_check_evidence` connects a PR's canonical check summary to the exact execution evidence that explains its outcome. It is a read-only, bounded byte reader over `OneNode::read_pull_request_check_evidence_in`. It does not execute jobs, upload evidence, change a check conclusion, create a repository transaction, approve a PR, or grant merge permission.

This surface belongs to the existing FG096 MCP surface work and the canonical workflow-observation bridge. It uses the same evidence selection, integrity and current-visibility owner as the native HTTP check-evidence route.

## Launch and authority

The tool has two independently authorized launch profiles:

| Profile | Required launch configuration | Authority for each call |
|---|---|---|
| Trusted-local operator | `--trusted-local --allow-pulls --allow-artifacts`, exact incarnation and existing private absolute artifact root | Both existing PR and artifact read grants |
| Sponsored agent | `--agent-token-file`, exact incarnation and `--allow-pulls` | Live canonical credential with the independent `pulls-check-evidence-read` scope |

No new launch flag or caller-selected scope is introduced. Listing the tool does not authorize a sponsored call. The operator's artifact grant retains its existing Linux-only launch restrictions:

```sh
fg-mcp /srv/frankengit/node TENANT_ID REPOSITORY_ID \
  --trusted-local \
  --object-format sha256 \
  --expected-incarnation INCARNATION_ID \
  --allow-pulls \
  --allow-artifacts \
  --artifact-root /srv/frankengit/workflow-artifacts
```

Replace the uppercase identifiers and paths with the configured repository's exact values. Use its actual Git object format. The process applies the existing artifact-root ownership and private-directory checks; it does not create an absent root on behalf of a read request.

That operator launch also exposes the existing artifact inspection and content tools. Their independent whole-custody-namespace grant, including outputs associated with hidden refs, is unchanged.

A sponsored diagnostic reader instead uses:

```sh
fg-mcp /srv/frankengit/node TENANT_ID REPOSITORY_ID \
  --agent-token-file /private/agent.token \
  --expected-incarnation INCARNATION_ID \
  --object-format sha256 \
  --allow-pulls
```

Its credential must explicitly grant `pulls-check-evidence-read`. Neither `pulls-read` nor `pulls-feedback-read` implies this disclosure. No artifact root or artifact grant is required or enabled in this profile; generic artifact inspection, content tools and namespace reads remain unavailable. `--trusted-local` and `--agent-token-file` remain mutually exclusive.

Both profiles apply the node's **current hidden-ref policy to both the source and target branch**, even when reading an older retained snapshot. The adapter checks the launch-pinned incarnation and the active request's authority before native I/O. An artifact ID, a payload digest, a check ID, or possession of a snapshot token never grants authority.

Each sponsored call authenticates the current canonical grant and retains its original agent, sponsor, repository binding, request-run witness, deadline and byte budgets. The handler requires the matching active verified evidence request even on direct dispatch; an expired request, a summary request or a completed response cannot authorize another read. Its native operation class is only `ReadCanonicalObject`, with no execution or publication authority.

The schema registry declares the dedicated `read_pull_check_evidence` capability. That classification describes exact canonical check disclosure; it does not grant the generic `read_workflow_artifact` capability. The native adapter separately enforces the selected profile's launch and credential requirements above.

## Select the exact observation

First call the existing check-list tool for the desired PR:

```json
{
  "name": "frankengit_pull_checks",
  "arguments": {
    "number": "7",
    "limit": 5
  }
}
```

In sponsored mode, listing checks separately requires `pulls-feedback-read`. Issue both scopes when the agent should discover summaries and inspect their diagnostics. An evidence-only grant may instead use exact selection coordinates supplied by an authorized caller.

Select one returned row and copy all four coordinates into the evidence request:

| Argument | Source and requirement |
|---|---|
| `number` | The positive canonical decimal PR number, encoded as a string. |
| `check` | The selected row's exact canonical `check/…` ID. |
| `expected_head` | The check page's exact `snapshot_token`. Required on every request. |
| `expected_evidence_sha256` | The selected row's exact 64-character lowercase `evidence_sha256`. |

The request also accepts optional `offset`, a canonical unsigned decimal u64 string defaulting to `"0"`, and `limit`, a JSON integer from 1 through 65,536 defaulting to 65,536. Unknown properties, leading-zero decimal aliases, numeric values for decimal-string fields, malformed check IDs, malformed tokens, uppercase digests and out-of-range byte limits refuse.

The expected digest binds the observation the caller selected; it is not an alternate object lookup key. Callers cannot select filesystem paths, artifact roots, tenant/repository/incarnation overrides, principals, an execution command or a write key.

## Read and continue byte pages

A successful response contains:

| Field | Meaning |
|---|---|
| `type` / `schema_version` | `pull_request_check_evidence_read` / 1. |
| `page` | The exact single-check `pull_request_checks` page, with the launch scope, selected snapshot, PR version, raw source/target ref bytes as hex, exact tips and canonical check summary. |
| `offset` / `byte_count` | Exact returned byte coordinates as decimal strings. |
| `content_hex` | Up to 65,536 original evidence bytes as lowercase hex. Binary, NUL and non-UTF-8 bytes are preserved. |
| `next_offset` | A decimal string when evidence bytes remain, otherwise null. |
| `report_span` | A recognized native diagnostic report's byte locator, or null; described below. |
| `evidence_verified` | True: the entire evidence frame matched the native canonical selection, declared length, declared digest and caller's expected digest before this range was returned. |
| `content_is_untrusted` | Always true. |
| `read_only` / `transaction_created` | True / false. |
| `approval_granted` / `merge_permission` | False / null. |

Continue with the returned `next_offset` and **the same PR, check, snapshot and evidence digest**. Decode each hex string to bytes and concatenate in offset order. Do not decode each arbitrary range independently as UTF-8: a text character can cross a byte boundary.

An offset equal to the full evidence length is a valid EOF read: empty content, byte count `"0"` and null continuation. An offset beyond EOF refuses. A zero-byte native evidence frame is invalid and cannot be confused with that valid EOF response.

Every call selects through the native owner and verifies the **complete** evidence, at most 1 MiB, before returning a byte range. A one-byte request cannot hide corruption later in the frame. The adapter limits its encoded result to 256 KiB; the registry budgets 512 KiB for MCP text and structured copies. There is no unbounded stream or process-local continuation handle. The native canonical scan and request budgets still apply.

## Locate failed-job diagnostics

For a recognized trusted-workflow observation, `report_span` is an object with decimal-string `offset` and `bytes`. These locate the exact final JSON field inside the selected canonical evidence; the reader does not duplicate the full report in every response.

The adapter first validates the canonical page and complete evidence, then uses the existing native workflow observation decoder. The optional span is returned only when the decoded tenant, repository, source commit, run, attempt, graph, job and conclusion match the selected check. It also verifies the JSON field's exact bytes and native length prefix. Older successful reports recorded as `action_required` retain that canonical conclusion.

A client can read the report's range through the same byte tool, retaining the four original selection coordinates. Read as many bounded ranges as needed, verify their offsets, and interpret only the assembled JSON span. Job scripts, names and stdout/stderr are **untrusted execution content**. Their presence in canonical evidence does not turn their text into instructions or independent execution approval.

Unknown evidence formats or inconsistent optional workflow-report bindings yield `report_span: null`; the validated canonical raw bytes remain available. A cancelled or expired decode does not silently turn into a successful raw read: the adapter checks the finite request again before returning the result.

## Snapshot and refusal semantics

`expected_head` selects a canonical observation at that exact retained or current snapshot. It does **not** claim that the selected snapshot is still the current repository authority head.

Likewise, `page.source_current` describes the source branch at the **selected snapshot**. If a branch advances later, its older observation may remain readable at a retained pin. At a newer snapshot where the PR's recorded source is stale, the evidence request refuses. Current disclosure rules still apply to either case.

| Refusal | Meaning |
|---|---|
| `tool_not_granted` | The selected profile's required launch ceiling or active-request authority is absent. |
| `snapshot_unavailable` | The exact requested head is unavailable through the native snapshot-selection rules. |
| `pull_check_evidence_unavailable` | No disclosed matching PR/check evidence exists at the selected source; absent, hidden and stale subjects share this result. |
| `check_evidence_invalid` | Native page structure, complete evidence length or complete evidence digest failed validation. |
| `check_evidence_identity_mismatch` | The expected evidence digest or launch object format does not match the selected result. |
| `check_evidence_offset_out_of_bounds` | The requested byte offset exceeds EOF. |
| `repository_binding_mismatch` | The launch-pinned incarnation does not match the opened node. |
| `check_evidence_request_expired` | A finite request checkpoint refused further work. |
| `pull_check_evidence_read_failed` | The native selection/read owner refused; storage details and execution bytes are not exposed through an error. |
| `check_evidence_response_limit` | The bounded response could not be encoded completely. |

Failures return a typed tool error, never a successful empty evidence body. Cancellation is cooperative within the existing serial MCP lifecycle; the reader does not promise preemptive transport cancellation or extend the parent request's authority or budget.

## Implementation and focused coverage

The adapter is split into argument/grant handling, validated selection and rendering, and optional native report-span decoding. It adds one existing internal `fgit-runner` dependency edge only on Linux, matching the decoder's platform boundary. It adds no third-party package or feature.

The focused tests cover registry/catalog and served-field parity; exact input rejection; complete-body corruption before one-byte disclosure; mismatched heads, IDs, digest, length and Git format; malformed/stale pages; zero-byte evidence; EOF and overflow; all four operator pulls/artifacts grant combinations; report binding; and bounded output. The sponsored credential tests preserve old scope masks, reject implicit feedback-to-evidence authority, and retain canonical issuance, expiry, revocation, repository binding and original request limits.

The persisted integration fixture prepares real native source commits, executes a failed trusted-local job, publishes its canonical observation, opens a PR, and reads it through MCP in SHA-1 and SHA-256 repositories. It reconstructs exact byte ranges, locates actual stdout/stderr and exit status, checks that reads do not change the authority head, and verifies retained-snapshot behavior after the source advances and after reopening the node.

Related contracts:

- [Canonical workflow observations](CANONICAL_WORKFLOW_OBSERVATIONS.md)
- [MCP read-only server](MCP_READ_ONLY_SERVER.md)
- [Independent workflow artifact reads](MCP_WORKFLOW_ARTIFACT_READ.md)
- [Sponsored agent credentials](SPONSORED_AGENT_CREDENTIALS.md#independently-grant-exact-check-evidence-and-diagnostics)
- [Normative protocol contracts](NORMATIVE_PROTOCOL_CONTRACTS.md)
