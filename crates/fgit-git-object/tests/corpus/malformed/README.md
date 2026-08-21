# FG-015a planted malformed corpus

Each fixture has a near-identical permitted input in
`planted_malformed_corpus_maps_to_typed_refusals`. The hex fixtures are raw
bytes written as lowercase hexadecimal so NUL-bearing Git bytes remain visible
and reviewable in source control.

- `loose-trailing.hex`: declared blob length is one, but has two payload bytes.
- `tree-truncated-reference.hex`: tree entry has only three bytes of its
  required twenty-byte SHA-1 reference.
- `commit-malformed-date.body`: its author timestamp is non-decimal under the
  strict creation profile.
