# Read native source context for an authenticated agent run

`OneNode::retrieve_agent_context_local_in` connects native indexed retrieval and
TreeFS hydration to `fgit-agent::ContextPacket`. A caller no longer has to acquire
an unbound context and only afterwards discover that it cannot belong to its run.
The method uses the existing `context_packet_for_run` bridge; there is no second
packet format, source engine, index or authority store.

## Host interface

A trusted embedding supplies an already authenticated `IntentRun`, its current
`SourceReadContext`, an explicit branch/query, index checkpoints, finite retrieval
and hydration limits, and `ContextControl`. It also supplies a monotone logical
clock in the same domain as the run's expiry and authenticated receipt.

```rust,ignore
use fgit_node::source_retrieval::agent_context::AgentContextRead;

let result = node
    .retrieve_agent_context_local_in(
        &request,
        AgentContextRead {
            run: &authenticated_run,
            authorization: &source_read_authorization,
            reference: &selected_branch,
            query: &initial_query,
            checkpoints: &retained_index_checkpoints,
            retrieval_limits,
            context_limits,
            control: trusted_context_control,
        },
        &logical_clock,
    )
    .await?;

// Preserve this evidence, including deliberate omissions and source lineage.
let native_context = result.context();
// Repository excerpts remain ContextSource::untrusted_bytes(), not controls.
let packet = result.packet();
```

These values must come from the host's existing authentication and run-control
boundary. Supplying a run ID or a saved context JSON cannot create either the run
receipt or source-read authorization. The native API now also has an explicit
trusted-local [`fg agent context` adapter](AGENT_CONTEXT_COMMAND.md). That command
authenticates the current head and opens one read-only invocation under the
operator's source grant and asserted sponsor. It does not add an MCP or HTTP
endpoint, remotely authenticated agent principal, or persistent run controller.

## Enforced behavior

Before source acquisition, both native limit sets are validated and the method
requires a complete authenticated run receipt, the node's repository, a committed
RCR, and both `ReadCanonicalObject` and `ReadDerivedGeneration` operation classes.
The control scope may only narrow the run. The existing host authorization is
checked independently; the run does not manufacture whole-repository permission.

Retrieval selects the run receipt's exact authority head. Native channel joins
retain one source and generation vector and their existing minimum checkpoints.
Before hydration, repository/head/RCR/forge-position equality is checked again.
Hydration uses the same host authorization, verifies the exact current source
paths and object bytes, and does not substitute arbitrary object-ID reads. A
changed source, missing index, invalid proof or failed required channel refuses;
the operation does not rebuild, refresh, widen a budget or retry automatically.

The result retains BOTH the `InitialContext` and the existing `ContextPacket`.
Native paths, byte spans, source IDs, authorization lineage, unavailable optional
channels, generation positions and omitted-file counts are therefore not lost
when excerpts enter the packet. Control commitments remain the host's explicit
inputs; neither retrieval ranking nor a packet hash attests the host's claims.

The logical clock is checked before retrieval, between retrieval and hydration,
between hydration and packet construction, and before returning. Time cannot
precede the receipt or move backwards within an invocation. Expiry is half-open:
`now == expiry` refuses. Request cancellation is checked before AND after every
clock callback. Failure discards the entire result, never a successful prefix.

The native request region owns cancellation, deadlines and work accounting
inside each phase. The host must arrange its request lifetime consistently with
the run's lifetime; a logical clock probe is not an interrupt mechanism. This API
does not replace sponsorship, current revocation, path-capability admission,
cumulative run-budget reservations, evidence retention or an effect broker.
It makes no publication attempt and does not execute repository instructions.

## Tests and verification boundary

`cargo test -p fgit-node --test agent_source_context` exercises the native node,
authenticated authority, persisted lexical index and TreeFS source readers using
the existing `source_http/support.rs` real-object fixture. Tests cover both Git
hash domains, exact source bytes and independent commitment goldens, stable
packet identity, scope/control refusals, foreign node authorization, lifetime
boundaries, backwards time, cancellation including the final callback, visible
omissions/optional-channel failures and explicit source advancement/reindexing.
The tests do not use a mock retrieval service or an external Git subprocess.

At the original native-API implementation, Rust/Cargo/rustfmt were unavailable
in the implementation environment. Those native tests had been added but had
NOT been executed there; that historical implementation claimed no compiler,
formatter, native test, whole-workspace or release pass. Existing
pure packet binding semantics and canonical packet bytes are unchanged by the
shared-preflight refactor. The broader agent execution work remains incomplete.

The CLI adapter adds `cargo test -p fgit-cli --test agent_context_cli`: actual
`fg` subprocesses over persisted SHA-1/SHA-256 nodes, nonempty untrusted source
and binary excerpts, authority preconditions, missing indexes, bounded-output
and hydration refusals, partial selection, and explicit local-grant checks.
The shared-host cases cover request cancellation and foreign namespace refusal.
Test definitions alone are not a claim that these commands have passed.

The shared document implementation now lives in
`fgit_node::source_retrieval::agent_context::document`, with the original CLI API
retained as a trusted-local wrapper. The authenticated HTTP
`source/agent-context` route and the in-process `source_agent_context_json` host
entry point construct the same receipt, run, packet and omission commitments.
HTTP sponsorship is fixed to the checked source-read credential principal;
operator assertions remain explicit on trusted-local hosts. The transport does
not turn either attribution into canonical IAM or durable agent execution.

`cargo test -p fgit-node --test agent_context_http` defines production TCP tests
for SHA-1 and SHA-256, authenticated sponsor/source evidence, raw binary and
prompt-injection-shaped excerpts, fresh run identity, exact-head preconditions,
partial selection, serialized-byte limits, source-grant separation, next-request
credential revocation, and absence of authority changes. Native document tests
also exercise cancellation, foreign namespace refusal and missing-index refusal
beside an explicitly built index. These are test definitions, not a recorded
whole-system verification result. See [the command and HTTP contract](AGENT_CONTEXT_COMMAND.md).
