# Restartable GitHub PR request preparation

FG-049: prepare an ordinary GitHub PR import job in bounded offline invocations,
without abandoning its request identities when preparation is paused. Existing
one-shot preparation and completed import jobs remain unchanged. This is local
request custody, not Git validation, authorization, publication or a new retry
protocol. The existing native sender remains the only execution path.

## Library workflow

```js
import { beginGithubPullPreparation, resumeGithubPullPreparation,
  inspectGithubPullPreparation } from './scripts/lib/github-pull-preparation.mjs';

const draft = await beginGithubPullPreparation({
  workdir: '/srv/import/preparation',
  captureFile: '/srv/import/github-pulls.json',
  captureConfirm: independentlyRetainedCaptureSha256,
  selection: destinationSelection,
  tokenFile: '/srv/import/native-writer.token'
});
// Independently retain draft.preparation_sha256 before continuing.
const progress = await resumeGithubPullPreparation({
  workdir: draft.workdir, confirm: draft.preparation_sha256, maxRequests: 100
});
const status = await inspectGithubPullPreparation({
  workdir: draft.workdir, confirm: draft.preparation_sha256
});
```

The destination selection and captured data use the existing shapes documented
in `GITHUB_PULL_MIGRATION.md`. All native title/body/form limits, exact u64
numbering, historical branch requirements, SHA-1 domain, and explicit consent
for merged/draft conversions remain in the original compiler. All commands are
offline. No source endpoint, alternate sender or native mutation is accepted.

Beginning fully validates the capture and compiles the complete request sequence.
It checks actual serialized native intent bytes, including encoding/metadata
rather than just form bodies, before creating any output directory. It then
selects one random 256-bit nonce seed, copies the source into private custody,
and writes `preparation.json` last. That independently pinned record commits the
source, destination choices, original credential fingerprint, nonce seed and
expected ordinary import manifest, including every expected request hash.

The original native request codec derives each request from those fixed inputs.
A versioned HMAC-SHA-256 domain and exact zero-based step index derive its 128-bit
nonce. This does not change `fgp1` key encoding or the native transaction seal.
The seed is not a credential and is never printed. Separate newly begun drafts
have independently selected identities; never start a replacement draft to
escape uncertainty about an already submitted request.

`resumeGithubPullPreparation` prepares at most `maxRequests` request slots
(default 100, range 1–8,192). Each invocation first revalidates the source, plan,
and every existing request. Saved requests are neither rewritten nor assigned
new nonces. A complete request staged just before interruption is checked against
its original expected bytes and moved into place. Final slots are published as
complete nonempty directories; competing preparers cannot replace them. A
concurrent loser may refuse and can retry explicit preparation later.

After all requests validate, the ordinary `import/manifest.json` is written last.
`preparation_complete:true` means that `import_workdir` and `plan_sha256` can now
be passed to the existing `migrate_github_pulls.mjs inspect`, `run`, `recover`, and
`status` commands. It does **not** mean a destination operation was executed.
The preparation pin and resulting import-plan pin are different commitments.
`execution_complete:false` and `mutation_submitted:false` make this distinction
explicit. Git objects and branches must still be provisioned separately.

Resume and preparation status need neither the original capture path nor any
credential. They reconstruct offline bytes from the retained fingerprint, not a
bearer. Actual submission still requires the original bearer and the server's
independent authorization. A completed draft can be inspected after native
execution; preparation status does not inspect or interpret the execution
journal. Use the original import `status` command for authoritative observations
of execution progress.

## Custody and limits

```
preparation.json           # immutable identity and expected manifest, <= 1 MiB
import/capture.json        # original capture, <= 1 MiB
import/requests/step-000001/intent.json ...
import/journal/            # must remain empty until final preparation
import/manifest.json       # ordinary v1 root, published only when complete
pending/request/intent.json # at most one complete staged original request
```

The original capture ceiling is 100 PRs / 2,000 records / 1 MiB. Native preparation
retains at most 8,192 requests and 64 MiB of request bytes, or the selected lower
bounds. The single pending request adds at most 1 MiB of temporary custody. The
1–300,000 ms invocation deadline includes preflight/readback; a started bounded
local write drains before cancellation is observed. Files must be owner-private,
single-link regular files, and directories must be outside Git worktrees with
no symlink aliases. Existing outputs and completed requests are not overwritten.

This profile resumes drafts created by `beginGithubPullPreparation`, not
arbitrary partial old one-shot jobs. Missing initialization, changed pins, gaps,
unknown files, corrupted/torn records or incomplete staged requests refuse in
place. No automatic repair, deletion, snapshot refresh, token substitution or
stale-lock stealing occurs. In particular, a SIGKILL inside the creation of a
staging file can leave an incomplete file that refuses; a complete staged file
is recoverable. Initialization and final-root writes are not a physical
power-loss guarantee. Never execute individual requests or an unfinished child
manually while its preparer is active.

## Verification

```
bash scripts/verify_github_pull_preparation.sh
```

Tests exercise the actual capture compiler, native request codec and private-file
helpers, including both hash domains and candidate actions in the codec. They
check bounded resumptions, exact original bytes, staged-request adoption,
concurrent preparers, source/credential removal, full u64 destination numbering,
encoded-capacity preflight, corruption and explicit noncompletion. Source test
captures come from the existing loopback response-schema peer, not live GitHub.
No Rust/native admission, deployed-server, hardware durability or full-workspace
verification is implied. FG-049 remains partial.
