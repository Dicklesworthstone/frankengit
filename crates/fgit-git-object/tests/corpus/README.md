# FG-015a object corpus

These bodies are promoted to real native loose-object bytes by
`emit_loose_framed` in the `checked_in_corpus_round_trips` unit test. They use
ordinary Git header/message grammar and deliberately include multiple parents,
an encoding header, an extension header, and an annotated tag. Binary tree
objects remain constructed from raw native reference bytes in the same test;
no text encoding is passed to the production parser.
