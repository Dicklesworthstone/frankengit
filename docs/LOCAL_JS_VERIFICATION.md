# Native JavaScript verification

The test runtime identity is pinned once in `tests/node-version`. This is a
verification profile for the existing JavaScript modules; it does not resolve
owner decision D10 or admit JavaScript as a production implementation platform.
The live-`fg` operator lane in `x2mv.4.59` must reuse this identity rather than
introducing another Node pin. Rust verification remains separate.

On macOS or Linux, with that exact Node executable on PATH:

```sh
node scripts/verify_js.mjs browser
node scripts/verify_js.mjs operator
node scripts/verify_js.mjs scripts
```

Each invocation discovers all `.test.mjs` files in the selected directory and
runs TAP with two concurrent files, a five-minute per-test bound, and a ten-minute
campaign bound. The 101-publication bootstrap test performs hundreds of durable
filesystem operations. An exploratory 30-second bound timed it out on macOS;
the unchanged test subsequently passed all five lifecycle cases in 172 seconds
under an external 180-second campaign bound. The per-test limit matches the
operator's existing five-minute operation budget, rather than that exploratory
short limit. The earlier draft 120-second profile is not a passing result.
The profile does not remove any test or relax any product assertion. A timeout
fails. A skip remains a skip in TAP and provides no coverage credit.

The runner creates its own private temporary root under the canonical host temp
directory and supplies it to fixture processes. On macOS, `/var` commonly aliases
`/private/var`. Only fixture-owned paths are canonicalized; production custody
checks still reject an explicitly aliased, replaced, public or unowned parent.
The root is removed on success and retained on failure. Cancellation terminates
the owned process group and escalates after five seconds. Descendants that
deliberately detach from this group are outside this test-runner boundary; this
is not hostile-code isolation.

Patch encoder tests retain ordinary worktree application, byte/mode assertions,
and reverse application. Arbitrary non-UTF-8 filename cases use independently
constructed Git objects and indexes on every host, apply the actual browser
patch, compare complete native tree IDs, reverse the patch and check wrong-base
refusal. These cases never pass raw names through the host filesystem, decode
or normalize them, or skip them on APFS. Git is a test-only oracle here; these
observations are not pinned-upstream compatibility or native Rust proof.

The header records the source revision and dirty flag (using bounded, test-only
Git metadata commands). For revision-bound results, require `dirty=false`,
retain the complete TAP and profile header, and record the exit status.
Module tests using DOM/fetch doubles or HTTP schema peers remain module/peer
tests, even when all pass. A browser suite pass does not prove real-browser or
live-node operation; full/release gates and D10 remain separate obligations.
