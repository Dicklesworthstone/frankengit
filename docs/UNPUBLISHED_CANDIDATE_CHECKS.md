# Verified checks for unpublished PR candidates

A prepared PR candidate can pass required CI without first publishing a CI
branch. The trusted publisher verifies a completed job from its original local
journal, validates the real candidate bundle and exact current PR coordinates,
then records a canonical candidate observation. Protected PR and queue landing
can require that observation through explicit `required_candidate_checks`.

The candidate stays unpublished until a separately authorized merge or queue
landing succeeds. Check publication changes canonical metadata only: it does
not stage the candidate objects, move a ref, approve a review, run a script or
acknowledge a delivery. Required reviews, queue restrictions and ordinary
branch-based checks continue to apply independently.

## One exact subject

Every observation retains all of these coordinates:

| Coordinate | Meaning |
|---|---|
| PR number and version | The existing, open native PR selected for the candidate. |
| Source/target refs and tips | Original canonical branch names and native commits, with exact raw ref bytes. |
| Policy epoch | The protection epoch selected for this preparation and publication. |
| Merge base and candidate commit | The actual inspected native result, in the repository's SHA-1 or SHA-256 domain. |
| Bundle SHA-256 | An independently retained pin for the exact supplied artifact bytes. |
| Publisher, graph and job | The authenticated reporting principal, full workflow graph commitment and exact job name. |
| Original job evidence | The original run, attempt, source provenance and terminal job result verified from durable custody. |

The candidate inspector supports its existing two-parent merge, squash and
fast-forward shapes. It verifies the shape from actual objects; the publisher
does not accept a caller-selected method shortcut. A fast-forward candidate is
the original source tip. A merge or squash candidate is the prepared commit.
A source-tip check cannot substitute for a different merged tree.

The embedded check uses the original target ref as an anchor. This is distinct
from asserting that the target currently names the candidate. The execution's
original authority head remains provenance. Unrelated metadata publication,
including reviews or another check, can advance the current head without
invalidating an otherwise exact subject. Changes to PR version, branch tips,
policy epoch, merge base or candidate make an old subject inapplicable.

This remains the existing trusted-host execution and reporting profile. Select
the publisher deliberately; the feature provides no independent remote runner
attestation. Review and trust the actual candidate scripts before running them.

## Configure candidate requirements

Install or replace policy before preparing the subject whose epoch will be
checked. Policy replacement advances the epoch and invalidates earlier subjects.
Every policy replacement is complete: retain all administrators, review rules,
ordinary checks, candidate checks, queue flags and DSL snapshots intended to
remain.

The CLI adds a repeated four-part selector:

```sh
fg protection set "$STORAGE" "$TENANT" "$REPOSITORY" \
  --trusted-local --principal "$ADMIN" \
  --idempotency-key "$POLICY_KEY" \
  --expected-version "$POLICY_VERSION" --expected-epoch "$POLICY_EPOCH" \
  --admin "$ADMIN" \
  --require-candidate-check "refs/heads/main:$PUBLISHER:$GRAPH_ROOT:build"
```

This is a minimal candidate-check-only example. Replace every variable with
actual inspected repository, policy and trusted publisher coordinates. Retain
other required policy fields when adapting it. Splitting stops before the job,
so a job such as `test:linux` remains exact. Use `--require-reviewer`,
`--require-approvals`, `--require-check` and `--require-merge-queue` to preserve
the independent requirements of the actual policy.

The HTTP protection form adds:

```text
required_candidate_check=TARGET_REF_HEX:PUBLISHER:GRAPH_ROOT:JOB_UTF8_HEX
```

Repeat the field for additional selectors. The existing canonical administrator,
`protection-write` credential, exact predecessor and policy epoch still govern
replacement. See [HTTP protection](HTTP_PROTECTION_API.md).

The MCP branch object adds:

```json
{
  "reference_hex": "726566732f68656164732f6d61696e",
  "required_reviewers": [],
  "required_checks": [],
  "required_candidate_checks": [
    {
      "publisher": "33333333333333333333333333333333",
      "graph_root": "4444444444444444444444444444444444444444444444444444444444444444",
      "job": "build"
    }
  ]
}
```

This is a field-shape example, not an executable policy or an attestation about
those placeholder IDs. Supply the actual publisher and graph. MCP permits an
omitted candidate array for compatibility; **omission removes candidate
requirements in a complete replacement**. Reads return the array explicitly.
Preserve it when editing unrelated fields. Ordinary `required_checks` remains
mandatory in the MCP branch shape. See [MCP administration](MCP_REVIEW_PROTECTION.md).

Selectors are sorted and unique. Ordinary plus candidate checks share one
32-check branch limit; jobs retain the 1,024-byte UTF-8, nonempty, no-control
bound. A candidate-only rule has no reviewers and zero required approvals.
Both browser policy editors preserve observed candidate selectors during
unrelated edits, display them read-only, and show their removal in the complete
replacement preview. Change selectors through the CLI, HTTP/MCP API or remote
operator's complete JSON policy. Removing a branch rule removes all its
requirements.

## Execute the actual candidate and keep its custody

Use the existing PR or queue-head preparation interface and retain its exact
bundle, original subject and SHA-256 independently. The bundle used for this
publication must advertise the original target, as the existing candidate
inspector requires.

For a merge or squash, the existing
`fg workflow run-merge-candidate` or
`fg workflow dispatch-merge-candidate` executes workflow scripts and selected
inputs from the actual verified candidate. The explicit execution command
pins both original branches. See
[trusted candidate execution](TRUSTED_CANDIDATE_WORKFLOW_CLI.md) and each
command's `--help`. A fast-forward may execute its exact canonical source
commit through the ordinary trusted workflow runner; publication still
validates the complete PR candidate and target ancestry.

Retain the original private run directory, its independent `journal_id`,
original delivery batch, fact index and any minimum pin. These select one real
completed job. The journal's proposal can remain `action_required` after a
successful execution: canonical publication re-verifies the retained evidence
and derives `success` without rewriting the journal. Skipped or unsuccessful
jobs cannot become success. Do not rerun a job merely because check publication
had an uncertain response.

## Publish one retained job

The Linux trusted-local CLI accepts a complete original subject and an
independent bundle pin:

```sh
fg workflow publish-candidate "$STORAGE" "$TENANT" "$REPOSITORY" "$TARGET_REF" \
  --trusted-local --expected-incarnation "$INCARNATION" \
  --object-format "$OBJECT_FORMAT" \
  --run-directory "$RUN_DIRECTORY" --journal-id "$JOURNAL_ID" \
  --batch "$BATCH_ID" --fact-index "$FACT_INDEX" \
  --principal-id "$PUBLISHER" --idempotency-key "$ORIGINAL_KEY" \
  --pull-request "$PR_NUMBER" --expected-pull-request-version "$PR_VERSION" \
  --expected-policy-epoch "$SUBJECT_POLICY_EPOCH" \
  --source-ref "$SOURCE_REF" \
  --expected-source-tip "$SOURCE_TIP" --expected-target-tip "$TARGET_TIP" \
  --merge-base "$MERGE_BASE" --candidate-commit "$CANDIDATE_COMMIT" \
  --bundle "$CANDIDATE_BUNDLE" --bundle-sha256 "$BUNDLE_SHA256"
```

Every variable is an actual retained coordinate; this example does not select
defaults, refresh a stale subject or claim execution. Non-UTF-8 source refs use
`--source-ref-hex` instead; `--ref-hex` interprets the target positional argument
as exact hex. `--minimum-pin BYTES:TAIL` can retain a known journal prefix.
The default pre-admission read timeout is 30 seconds and `--timeout-ms` accepts
1–60,000. Native admission and shutdown keep their existing separate budgets.

The command verifies the saved journal marker, prefix pin, batch, fact and
actual job evidence. It requires the selected evidence to name the candidate
commit. For a fresh publication it reads a stable, operator-controlled regular
bundle of at most 128 MiB, checks the SHA-256 with cancellation checkpoints and
uses native admission to verify actual object closure and current subject.
There is no actor, conclusion, graph or success override.

Stdout is one `candidate_workflow_check_publication` JSON receipt after node
shutdown. It includes the exact subject, candidate, bundle pin, check identity,
canonical terminal and `outcome_recovered`; `refs_changed`,
`objects_staged` and `execution_retried` remain false. The command exits
0 for canonical commit, 3 for canonical refusal and 2 for input, unavailable
outcome, cleanup or receipt-output failure. A successful check publication
does not itself mean the merge is authorized.

## Retry and then land with the original guards

The publisher looks up an exact original terminal before opening the bundle or
rechecking current eligibility. A committed or refused check remains recoverable
after the local bundle disappears, its source moves or policy changes, provided
the original journal evidence and all request coordinates are retained. Keep
the same principal, key, journal marker, batch, fact, subject and bundle digest.
An undecided lookup creates no new seal or observation; absence is not proof
that another attempt did not commit. Never replace the key merely to hide an
uncertain outcome.

After canonical check success, obtain any independently required reviews and
submit the original prepared candidate through the existing guarded PR merge or
queue `land-candidate` operation. The landing revalidates current policy,
original subject, real candidate and every independent requirement at its
authenticated publication basis. A later exact non-success check from the same
configured publisher/graph/job supersedes earlier success. A deliberate new
successful execution can satisfy it again; an earlier refused landing retains
its refusal under its original key.

Candidate and ordinary observations share the same immutable
publisher/run/attempt/job identity. Publishing the same execution under a
different profile or changed subject conflicts instead of creating another
check stream. Choose the intended profile for the original execution and retain
that decision on retry.

## Compatibility and scope

Required forge kind 20 records candidate observations; required policy kind 21
carries candidate selectors. Historical ordinary observation and policy bytes
remain unchanged. All readers and writers must understand the new required
kinds before activation. The webhook event family is
`candidate_workflow_check` (or explicit `kind:20`); ordinary
`workflow_check` subscriptions do not silently opt in.

A native merge or queue landing supplies validated PR candidate authority.
Generic direct ref writes cannot satisfy candidate-check protection. The
feature does not grant atomic multi-PR prefix landing: prefix preparation
still has its separately documented original subjects and projected steps,
and no prefix publication template. Existing automatic CI-ref watchers retain
their ordinary branch-check behavior; they do not switch reporting profiles
implicitly.

Normative ownership and exact encoding are in
[NORMATIVE_PROTOCOL_CONTRACTS.md §20.5](NORMATIVE_PROTOCOL_CONTRACTS.md#205-verified-unpublished-candidate-workflow-checks).
Codec, policy, native publication/landing and parser tests cover this boundary;
browser/operator tests cover exact requirement preservation and retry identity.
A listed test describes its assertion, not a claim that a build ran.
