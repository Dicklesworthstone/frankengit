# Hand-constructed upload-pack packet transcripts

These packet streams are checked-in byte fixtures, built from the packet
length and command grammars in the pinned Git protocol documentation.  They
are deliberately small: the `111...` identity is an advertised want and the
`222...` identity is a common have in the test repository.  They are local
parser/state-machine evidence, not a differential claim against an upstream
Git executable (FG-018c owns that evidence).

The source files retain the customary final text-file LF after the final
`0000` marker.  Tests strip that container-only LF before presenting bytes to
the pkt-line decoder; it is not part of the protocol transcript.

- `v1-advertisement.pkt` is a v0/v1 ref advertisement followed by a flush.
- `v1-fetch-request.pkt` has a `want` with `multi_ack_detailed` and
  `side-band-64k`, then flush, common `have`, and `done`.
- `v2-ls-refs.pkt` is a complete `ls-refs` command request with a ref prefix.
- `v2-fetch.pkt` is a complete `fetch` command request with an advertised
  client capability, want/have negotiation, a filter, `done`, and flush.
