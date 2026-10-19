# Native workflow script block forms

The native workflow scanner accepts folded `>` scripts and literal `|` scripts
with explicit chomping or indentation indicators. The same scanner feeds
`WorkflowPlan` and native workflow execution; this does not add another YAML
implementation or execution adapter.

```yaml
name: build
on: push
jobs:
  build:
    runs-on: fgit-trusted-local
    steps:
      - run: >-
          printf '%s\n'
          'one command spread over source lines'
      - run: |-
          printf '%s\n' first
          printf '%s\n' second
```

The first step resolves to one command with a space between its source lines.
The second retains the line break between its commands. Both strip their final
source line break because they use `-`.

## Supported indicators

The newly admitted forms follow [YAML 1.2.2 block scalar rules, section
8.1](https://yaml.org/spec/1.2.2/#81-block-scalar-styles):

- `>` folds breaks between ordinary text lines to spaces. Empty lines preserve
  paragraph breaks. Lines beginning with extra spaces or tabs, and the breaks
  surrounding them, remain literal.
- `-` strips the final break and trailing empty lines; `+` keeps them. Without
  either, clipping retains a final break when the source actually contains one,
  but removes trailing empty lines. An entirely empty clipped block is empty.
- An optional digit `1` through `9` specifies indentation relative to the
  mapping key's indentation, or the sequence dash for a scalar sequence item.
  The digit and chomping indicator may appear in either order: `|2-` and `|-2`
  are equivalent.
- Without a digit, the first non-empty line determines indentation. A leading
  empty line cannot contain more spaces than that first content line.
- LF, CRLF and CR become LF in these newly admitted scalar values. A final
  unterminated content line does not acquire a synthetic newline.

Comments on the header are YAML comments. Properly indented `#` lines inside
its body are script data. A less-indented comment ends the scalar; following
syntax cannot silently disappear into the preceding sequence item. Literal
spaces beyond the content indentation and tabs inside content are preserved.
Unsupported constructs elsewhere in the workflow remain refused; this is still
an explicitly bounded YAML subset.

## Compatibility of existing bare `|`

Unmodified `|` retains its previous decoder because existing command bytes
participate in graph identities. Ordinary newline-terminated scripts therefore
keep their exact command and canonical graph bytes.

That compatibility path retains known edge behavior: it synthesizes a final
newline at end of input, discards whitespace-only content lines, accepts
leading blank-line indentation that the new forms refuse, and requires a
non-empty content line. It also retains its previous handling of carriage
returns. Use an explicit form such as `|-`, `|+` or `|2` for the new block
semantics. This document does not claim full YAML conformance for bare `|` or
for the workflow scanner as a whole.

## Bounds and identity

Physical source lines, including comments and blank scalar lines, count toward
`Limits.max_lines`. Source bytes are bounded before scanning. New scalar bodies
are borrowed from the source while indentation, folding, chomping and resolved
size are checked; the resolved string is allocated only after its scalar byte
budget succeeds. Node, nesting and collection-entry limits remain active.

Scalar style itself is presentation, so no new graph version is introduced.
Two accepted forms yielding the same command and workflow data yield the same
canonical graph bytes. Their source spans still cover the original header,
body and consumed blank lines, including original line-ending bytes.

`crates/fgit-schema/tests/workflow_block_scalars.rs` contains exact-byte
fixtures, malformed/valid twins, physical-line and scalar limits, source spans,
compact sequence mappings, both indicator orders, and a fixed legacy graph
golden. `crates/fgit-runner/tests/workflow_script_blocks.rs` compiles complete
workflows and executes their resolved commands through the real trusted Linux
process adapter. It covers heredocs with blank lines, folded arguments and
paragraph separators, shell continuations, graph/source identity, and refusal
of unevaluated workflow expressions. These local shell tests do not execute
the native `fg` binary or claim forge publication.
