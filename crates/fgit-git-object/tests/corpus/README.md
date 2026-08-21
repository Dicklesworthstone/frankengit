# FG-015a object corpus

These bodies are promoted to real native loose-object bytes by
`emit_loose_framed` in the `checked_in_corpus_round_trips` unit test. They use
ordinary Git header/message grammar and deliberately include multiple parents,
a continued `mergetag`, a continued `gpgsig`, an encoding header, an extension
header, and an annotated tag. Binary tree
objects remain constructed from raw native reference bytes in the same test;
no text encoding is passed to the production parser.

`blob-hello.zlib.hex` is the complete checked-in RFC 1950/1951 member for the
native loose bytes `blob 5\0hello`. It uses a stored DEFLATE block and an
independently calculated Adler-32 trailer; the zlib integration test decodes
the hex text before passing those literal compressed bytes to the production
decoder.
