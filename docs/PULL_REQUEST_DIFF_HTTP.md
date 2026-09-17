# Recorded pull-request diffs over HTTP

`POST {repository-route}/api/v1/pulls/{number}/diff` exposes the production
native PR comparison used by `fg pr diff`. It is a body-bearing read, not a
review submission, merge preparation, approval, or repository transaction.

Enable the native PR API. The SAME credential must carry both `read` and
`pulls-read`; neither PR metadata permission alone nor source permission alone
suffices. `pulls-write`, review-write and merge-write do not imply either read
grant. As with existing PR preparation, this route is governed by the PR API
switch and does not require enabling the separate source-browser routes.

Authentication, route binding and these grants are checked before body intake,
including before `100 Continue`. An `Idempotency-Key` is rejected. The internal
read sentinel is never submitted to admission, seal creation or key binding.

## Selection and preconditions

Use an `application/x-www-form-urlencoded` body, with ordinary Content-Length
or bounded chunked framing:

```text
object_format=sha256&expected_version=1&mode=merge-base
```

The URL supplies the positive canonical PR number. `object_format` is required
and must match the repository. `expected_version` is optional and, when present,
must match the PR's actual aggregate version. `expected_head` optionally pins
the complete read to a previously returned `snapshot_token`.

The native reader selects the PR event, its recorded target/source tips,
canonical hidden-ref policy and admitted object history from ONE authenticated
head. It does not read the PR at one head and then look up current branch tips
at another. An ordinary branch push, advance, or deletion does not silently
refresh the recorded comparison. Updating the PR explicitly can change its
recorded tips; the returned aggregate version identifies that data. Closed and
merged native PRs retain their recorded comparison coordinates.

`expected_before` checks the recorded target tip and `expected_after` checks
the recorded source tip. They are comparisons, not object selectors. Ref-name,
PR-number and arbitrary-object overrides in the form are rejected. Hidden PR
selections and nonexistent PRs have the same 404 response. Missing required
object history is an unavailable operation, never an empty successful diff.

## Comparison and output

The default is `mode=merge-base`: compare the unique best common ancestor of
the recorded tips to the recorded source tip. `mode=direct` compares the recorded
trees directly. Ambiguous or absent ancestry is a 409 response, not a guessed
base. This is not GitHub API compatibility or a promise of rename detection.

Path-prefix fields, context, downward resource limits, lossless hunk encoding,
span conventions, binary/mode/gitlink distinctions and response buffering are
the same as [native source diffs](SOURCE_DIFF_HTTP.md). Path filters narrow the
requested comparison; they are not a path authorization mechanism.

The response uses `type:source_diff` and includes a non-null
`pull_request:{number,version}`, exact before/after reference bytes, original
recorded tips, actual compared base, root trees, authority head and snapshot
token. `complete:true` covers the requested comparison, not unrelated paths.
No approval, transaction or repository publication is created.

A moved head yields `source_snapshot_moved`; a moved PR version yields
`pull_request_version_moved`; a mismatched recorded tip yields
`source_commit_moved`. All are 409 responses. None authorizes retrying a write
or proves a pending mutation's outcome. Credential rotation and listener
lifecycle use the existing server mechanisms unchanged.

## Regression coverage

`pull_request_diff_http` exercises the production TCP listener, real imported
objects, durable PR creation/closure and native branch admission in both hash
formats. It checks that recorded comparisons survive target advancement,
source deletion and restart while live-ref comparisons change. It also covers
head/version/tip mismatches, byte-path filtering, missing PRs, conjunctive
credential scopes, withheld-body rejection, response bounds, rotation and
absence of read-created canonical transactions. Router and parser tests cover
closed route shapes and attempts to replace recorded selectors.

These tests were added in an editing environment without Cargo, rustc or
rustfmt. They were not executed there. Compilation, formatting, Clippy and
repository verification gates require execution in the pinned build environment;
no runtime or release certification is asserted by this document.
