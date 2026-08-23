# Pinned upstream-Git oracle

`oracle.sh` is a development/conformance-only command boundary for upstream
Git. It is never called by FrankenGit production code. Every invocation uses
one checked-in row in `pins.tsv`, binding the release version, annotated tag,
tag commit, canonical release URL, and source SHA-256.

Set `FGIT_ORACLE_ROOT` to a dedicated absolute directory outside this checkout
(the default is `$HOME/.cache/frankengit/git-oracle`). The command refuses a
root inside the repository, an unpinned identity, receipt drift, a wrong
binary version, a missing Bubblewrap sandbox, or path/config/credential escape
arguments. It creates no fallback to a host `git` binary.

For a network-free build, place the independently verified release archive at
`$FGIT_ORACLE_ROOT/downloads/<archive-name>` and run:

```bash
scripts/e2e/oracle/oracle.sh build git-2.54.0
```

`build` never downloads. Only `fetch-source` uses the network; without an
archive it reports `FGIT_ORACLE_UNAVAILABLE` and exits 69. To attest an
already-built installation, use `record-installed <pin> <prefix>
<source-archive> <build-flags-fingerprint>`; the prefix must contain both
`bin/git` and `libexec/git-core`, and the supplied source archive must match
the pin. That path records operator-attested source-to-binary provenance.

Differential suites create an isolated run with `create-run`, then use
`capture` to retain exact stdout bytes, stderr bytes, and exit code under its
external run directory. `compare` prints one NDJSON verdict with exactly one
of `byte_equal`, `semantically_equal_declared`, or `divergent`. Suites source
`../lib.sh` for their own step-level NDJSON evidence; the oracle itself never
mutates the shared E2E harness.

## Constrained loopback clone mode

`clone-loopback` is the one deliberate exception to the ordinary runner's
file-only transport policy. It exists solely for the FG-028b FIRST CLONE E2E
case, where a pinned upstream Git client must clone from the live local
`fgit-node` git-daemon. It is not a generic networked Git runner:

```bash
scripts/e2e/oracle/oracle.sh clone-loopback \
  git-2.54.0 <run-directory> <label> \
  127.0.0.1:<port> /<32-lower-hex-repository-id>.git <new-relative-destination>
```

The command accepts no caller-provided Git arguments. It fixes the remote to
the numeric loopback `git://` URL, accepts only the `git` transport, clears
ambient configuration and credentials, and keeps Bubblewrap mount/process
isolation. Its transcript receipt binds the oracle pin/version/binary digest,
the `loopback-git-only` profile, the sole endpoint, repository path,
destination, output digests, and exit status. `--share-net` is used only for
this closed command so the host-side E2E node listener is reachable; every
other oracle command remains network-unshared and file-only.

`../suites/oracle/oracle_selftest.sh` is a discovered E2E suite that exercises
planted refusals for an unknown pin, missing source input, wrong binary version,
caller configuration leakage, sandbox path escape, and the loopback-only clone
boundary. Its fake Git/Bubblewrap fixtures prove harness mechanics only, not
Git conformance.
