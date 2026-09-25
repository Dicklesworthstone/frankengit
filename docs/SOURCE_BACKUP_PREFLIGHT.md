# Source backup preflight

`fg-repository-backup verify` checks a source recovery archive before committing
storage and time to payload restoration. It uses the existing source archive
reader, FrankenSQLite portable-import verifier, authority materializer and native
object graph audit. It does not substitute a second parser or a mock store.

```sh
fg-repository-backup verify source.fg /trusted/parent/new-verification-scratch \
  --trusted-local \
  --expected-sha256 <independently-saved-64-character-lowercase-checksum> \
  --verification-instance 991 \
  --max-archive-bytes 1073741824 --timeout-secs 300
```

The archive is the only recovery input. The original node and Git directory may
be unavailable. The scratch root must not exist, and its parent must be stable
and trusted. The instance identifier is a fresh positive SQL-range identifier,
not the source store's identifier. There is no resume or overwrite mode.

## What is checked

The original checksum is checked before decoding the authority transport or
creating scratch state. Framing, exact EOF, sorted native identities and original
independent payload commitments are checked on the same open archive. Every
later pass rechecks that pin, so pathname replacement cannot switch the input and
in-place changes cannot pass as the original file.

Only bounded authority metadata is imported into
`<scratch>/.verify-quarantine`. The real backend checks the portable image and
remints local CAS tokens; exact source head key, bytes and generation are retained.
The node authenticates that head, materializes its selected refs and cumulative
object closure, and checks the archive's exact inventory and required-kind graph
against those canonical selections. A valid checksum over an archive that omits
an authority-selected object is not sufficient.

Preflight is a third mode of the same graph routine used to install objects and
read them back during restore. It calls neither payload placement nor final
publication. No `authority.fsqlite` is installed at the scratch root, no restore
intent is created, and no routing or outbox effects are activated.

## Bounds, cleanup and outcome

All passes share one cooperative deadline. Archive, authority metadata, object,
reference and edge limits remain the existing recovery profile's independent
bounds. Payload memory stays bounded by the streaming reader's one-object buffer;
Git payloads are not copied into scratch storage. Metadata backend/runtime limits
can refuse earlier than the archive-byte ceiling.

Success requires explicit store/node closure and removal of the scratch tree.
The JSON receipt is then emitted and flushed. Exit 0 means complete preflight and
cleanup; exit 2 includes invalid inputs, incomplete verification, cleanup failure
and output failure. Output failure after success names the verified/cleaned state.
A failure after scratch creation retains that private tree for diagnosis and
never grants permission to reuse it. Existing directories are never removed.

The receipt deliberately distinguishes verified source inputs from a completed
restore: destination disk readback, newest-checkpoint selection, signatures,
external artifacts, routing and permission to replay external effects are NOT
established. A later restore must reverify the archive and its actual destination.

This is a bounded implementation slice related to
`frankengit-root-doctrine-x2mv.4.11`; it does not close that bead or establish a
release gate. The normative authority/root-last rules remain in
[NORMATIVE_PROTOCOL_CONTRACTS.md](NORMATIVE_PROTOCOL_CONTRACTS.md).
