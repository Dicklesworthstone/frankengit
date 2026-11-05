# Native workflow flow collections

Native workflows accept single-line YAML sequences (`[...]`) and mappings
(`{...}`), including nested collections. The same scanner and workflow lowerer
handle block and flow syntax. Trigger lists, dependency lists, environment maps,
matrix axes and include/exclude records can use their familiar compact forms.

```yaml
name: compact matrix
on: [push, pull_request]
env: {LABEL: 'a,b # [literal]'}
jobs:
  build:
    runs-on: fgit-trusted-local
    strategy:
      fail-fast: false
      matrix: {mode: [debug, release], arch: [x86, arm], exclude: [{mode: debug, arch: arm}]}
    env: {MODE: '${{ matrix.mode }}', ARCH: '${{ matrix.arch }}'}
    steps:
      - {name: build, run: 'printf "%s|%s" "$MODE" "$ARCH"'}
  package:
    runs-on: fgit-trusted-local
    needs: [build]
    steps: [{run: echo all-selected-variants-passed}]
```

This example produces three build variants and a package job that depends on
all three. The existing [matrix profile](NATIVE_WORKFLOW_MATRICES.md) still
requires `fail-fast: false`, bounds expansion and restricts expressions to its
whole-value input forms. The [environment profile](NATIVE_WORKFLOW_STEP_CONTEXT.md)
still validates every layer before applying workflow, job and step precedence.

The syntax change also applies to filtered events, for example:

```yaml
on: {pull_request: {branches: [main], paths: ['src/**', '!src/private/**']}}
```

Filter order and meaning are unchanged. The separate
[branch](NATIVE_WORKFLOW_BRANCH_FILTERS.md),
[path](NATIVE_WORKFLOW_PATH_FILTERS.md) and
[tag](NATIVE_TAG_WORKFLOW_WATCH.md) profiles define their supported operators.

## Selected syntax

The scanner implements a bounded selection of the
[YAML 1.2.2 flow productions, section 7](https://yaml.org/spec/1.2.2/#chapter-7-flow-style-productions).
It does not claim general YAML or GitHub Actions compatibility.

- Every flow collection, including all of its nested values, must begin and end
  on one physical source line. A collection can follow `key:`, follow a block
  sequence's `-`, occupy an indented value line or form the complete document.
  Block and flow nodes can be mixed freely at those boundaries.
- Collections may be empty, and one trailing comma is allowed: `[]`, `{}`,
  `[one, two,]`, `{name: value,}`. Empty entries and omitted values refuse:
  `[,one]`, `[one,,two]`, `{name:}` and `{name}`.
- Mapping keys are scalar strings. An unquoted key requires space or tab after
  its separator colon: `{name: value}`. A quoted key can have an adjacent value,
  including a nested collection: `{"name":"value", "items":[one,two]}`.
  Complex keys, explicit-key notation and implicit pairs such as `[name: value]`
  refuse.
- Scalars remain strings. `null`, `false` and `01` keep those literal bytes;
  they do not become missing values, booleans or numbers. An explicit empty
  string is written `''` or `""`.
- Quote scalar content containing commas, brackets, braces, or a colon followed
  by whitespace or a flow delimiter. A URL such as `https://host:443/path` is a
  plain scalar; `'value: text'` needs quoting. Quotes inside an already-started
  plain scalar are data, so `isn't` is one string rather than a quote opener.
- A hash with no preceding whitespace is plain content, as in `path#fragment`.
  A separated comment can follow the complete collection: `[one] # comment`.
  It cannot interrupt a collection that must close on the same line. A quoted
  hash, as in `['a # b']`, remains content.
- Single quotes use doubled single quotes: `'it''s literal'`. Double-quoted
  flow scalars accept the existing `\n`, `\r`, `\t`, `\\`, `\"` and `\/`
  escapes. Other escapes, unterminated quotes, nonprintable source controls and
  byte-order marks refuse with a source span. Space and tab are the only syntax
  separation characters; other printable Unicode characters remain data.

Anchors, aliases, tags, merge keys and multiple documents remain refused.
Block scalar headers cannot appear inside flow collections. A block `run: |`
or `run: >-` can still be used beside flow fields; its existing script-byte
rules are described in [native script block forms](NATIVE_WORKFLOW_BLOCK_SCALARS.md).

The scanner preserves its previous normalization for already accepted block
spellings. The new quote/comment lexer only handles newly admitted flow forms.

## Budgets, identity and execution

Block and flow syntax share one node counter and one nesting budget across the
whole document, including compact `- key: value` mappings. A nested flow does
not start a new allowance. Bounds are checked before descent, node allocation,
collection growth or scalar decoding. Defaults remain:

| Bound | Default |
| --- | ---: |
| Source bytes | 256 KiB |
| Physical source lines | 4,096 |
| Container nesting depth | 16 |
| Nodes across the document | 4,096 |
| Entries in one mapping or sequence | 256 |
| Raw bytes in one scalar or key token | 8,192 |

Mapping keys do not count as separate nodes, matching the block scanner.
Scalar byte limits include quote/escape syntax and count UTF-8 bytes. A
collection can be larger than one scalar limit when each member fits; the
document, node and entry bounds still apply. Workflow-specific limits on jobs,
steps, effective environments, matrices, filters and dependency expansion also
remain in force.

Every new node and mapping key has a source byte span, including nested Unicode
tokens. Collection spans end at their closing delimiter, before a trailing
comment. Duplicate keys are checked after quote decoding and refuse at the
second key; source order never silently selects a winner.

Flow syntax does not introduce a graph version. Equivalent block and flow
workflows produce identical canonical graph bytes, including matrix bindings,
effective environments, dependency joins and ordered filters. Exact workflow
source bytes remain separately bound by execution evidence, so changing a
workflow's spelling still changes its source identity. The existing runner
consumes the same lowered graph and retains its authorization, trusted-local
execution and recovery requirements.

## Verification

The focused pure schema suite is
`crates/fgit-schema/tests/workflow_flow.rs`. It compares complete block and flow
workflow graphs, checks nested ASTs and source spans, exercises every shared
budget at its boundary, and pairs malformed forms with accepted nearby inputs.
It includes all physical line endings, quotes/comments, Unicode byte offsets,
typed strict-YAML refusals and very deep hostile nesting. Existing block scalar,
environment, matrix, trigger and graph golden tests continue to cover their
original spellings.

```sh
cargo test -p fgit-schema --all-targets --locked
cargo test -p fgit-runner --test workflow_conditions --locked
```

These targets do not require `/proc` or spawn workflow shell commands. Native
runner process tests and workflow E2E suites retain their real process,
filesystem and procfs requirements; the parser tests do not substitute for
those integration checks. The generated construct registry records both
`yaml.flow-sequence` and `yaml.flow-mapping` as normalized, and the existing
registry equality test checks the emitted JSON against the checked-in artifact.
