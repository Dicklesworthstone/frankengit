#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- exercises the FAILING branch of every
# assertion helper exactly once, so the self-test can prove each one fires.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-assert-negatives
fge_phase setup
work=$(fge_tempdir probe)
printf 'content\n' > "$work/present.txt"
printf 'not json at all\n' > "$work/bad.ndjson"
: > "$work/empty.ndjson"
fge_phase assert
fge_assert_eq           FG-000A-NEG-EQ    a b                       'eq negative'
fge_assert_ne           FG-000A-NEG-NE    same same                 'ne negative'
fge_assert_exit         FG-000A-NEG-EXIT  0 9                       'exit negative'
fge_assert_contains     FG-000A-NEG-CONT  haystack needle           'contains negative'
fge_assert_not_contains FG-000A-NEG-NCONT haystack hay              'not_contains negative'
# An empty needle is unfalsifiable: before this fired, the call passed
# unconditionally, so an unset expected-absent variable silently proved nothing.
fge_assert_not_contains FG-000A-NEG-NCONTE haystack ''               'not_contains empty-needle negative'
fge_assert_match        FG-000A-NEG-MATCH abc '^z+$'                'match negative'
# An empty pattern matches everything, so this is the empty-OPERAND negative for
# match, the twin of NCONTE above (frankengit-xypf).
fge_assert_match        FG-000A-NEG-MATCHE abc ''                     'match empty-pattern negative'
fge_assert_file         FG-000A-NEG-FILE  "$work/absent.txt"        'file negative'
fge_assert_no_file      FG-000A-NEG-NFILE "$work/present.txt"       'no_file negative'
# [ -e "" ] is false, so an empty path used to record PASS -- absence at a path
# that was never named (frankengit-xypf).
fge_assert_no_file      FG-000A-NEG-NFILEE ''                        'no_file empty-path negative'
fge_assert_dir          FG-000A-NEG-DIR   "$work/absent-dir"        'dir negative'
fge_assert_digest       FG-000A-NEG-DIG   deadbeef "$work/present.txt" 'digest negative'
fge_assert_digest       FG-000A-NEG-DIGM  deadbeef "$work/absent.txt"  'digest missing-file negative'
fge_assert_ndjson       FG-000A-NEG-NDJ   "$work/bad.ndjson"        'ndjson malformed negative'
fge_assert_ndjson       FG-000A-NEG-NDJM  "$work/absent.ndjson"     'ndjson missing negative'
fge_assert_ndjson       FG-000A-NEG-NDJE  "$work/empty.ndjson"      'ndjson empty negative'
fge_assert_cmd          FG-000A-NEG-CMD   'cmd negative' false
# No command at all: "$@" expands to nothing and the bare redirect succeeds,
# so this used to record PASS (frankengit-xypf).
fge_assert_cmd          FG-000A-NEG-CMDE  'cmd empty-predicate negative'
# An explicitly EMPTY third argument must not silently become FGE_LAST_EXIT.
fge_assert_exit         FG-000A-NEG-EXITE 0 ''                       'exit empty-actual negative'
fge_fail                FG-000A-NEG-FAIL  'explicit failure'
