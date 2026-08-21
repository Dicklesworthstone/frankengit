#!/usr/bin/env bash
# e2e: grammar corpus for the harness's pure-bash JSON/NDJSON validator
# (bead frankengit-fg000a-e2e-harness-4ci).
#
# The validator is the load-bearing part of "run_all validates every record":
# if it accepts malformed input, every downstream evidence claim inherits that
# hole. So it is exercised against a corpus of accept and reject cases rather
# than against the harness's own well-formed output, which it would obviously
# accept.
#
# Scope claim: harness mechanics only.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"

fge_init

fge_phase setup
fge_context suite harness-json

accepted=''
rejected=''
mismatches=''
checked=0

# check WANT DESC LINE   -- WANT is 0 (must accept) or 1 (must reject)
check() {
  local want=$1 desc=$2 line=$3 rc=0
  checked=$((checked + 1))
  fge_json_validate_line "$line" || rc=1
  if [ "$rc" -eq "$want" ]; then
    if [ "$want" -eq 0 ]; then accepted+="$desc; "; else rejected+="$desc; "; fi
  else
    mismatches+="$desc(want=$want got=$rc); "
  fi
}

fge_phase action

# --- must accept ----------------------------------------------------------
check 0 'flat object'          '{"a":1}'
check 0 'empty object'         '{}'
check 0 'nested containers'    '{"a":{"b":[1,2,{"c":null}]},"d":true}'
check 0 'escapes'              '{"a":"x\ty\\z\"q"}'
check 0 'unicode escape'       '{"a":"éA"}'
check 0 'raw utf8 passthrough' '{"a":"héllo → ✓ 漢字"}'
check 0 'negative exponent'    '{"a":-1.5e-10}'
check 0 'plus exponent'        '{"a":1E+3}'
check 0 'zero'                 '{"a":0}'
check 0 'negative zero'        '{"a":-0}'
check 0 'insignificant space'  '  { "a" : 1 , "b" : [ ] }  '
check 0 'empty array'          '{"a":[]}'
check 0 'empty string'         '{"":""}'
check 0 'solidus escape'       '{"a":"\/"}'
check 0 'deep nesting'         '{"a":{"b":{"c":{"d":{"e":[[[1]]]}}}}}'

# --- must reject ----------------------------------------------------------
check 1 'trailing comma object' '{"a":1,}'
check 1 'trailing comma array'  '{"a":[1,]}'
check 1 'unterminated string'   '{"a":"x}'
check 1 'unquoted key'          '{a:1}'
check 1 'single quoted'         "{'a':1}"
check 1 'trailing garbage'      '{"a":1} x'
check 1 'two objects'           '{"a":1}{"b":2}'
check 1 'bad escape'            '{"a":"\q"}'
check 1 'short unicode escape'  '{"a":"\u12"}'
check 1 'non-hex unicode'       '{"a":"\uZZZZ"}'
check 1 'raw control byte'      "$(printf '{"a":"x\001y"}')"
check 1 'raw tab in string'     "$(printf '{"a":"x\ty"}')"
check 1 'top-level array'       '[1,2]'
check 1 'top-level number'      '42'
check 1 'top-level string'      '"a"'
check 1 'missing colon'         '{"a" 1}'
check 1 'missing value'         '{"a":}'
check 1 'leading zero number'   '{"a":01}'
check 1 'leading plus number'   '{"a":+1}'
check 1 'bare fraction'         '{"a":.5}'
check 1 'trailing point'        '{"a":1.}'
check 1 'lonely exponent'       '{"a":1e}'
check 1 'NaN literal'           '{"a":NaN}'
check 1 'python None'           '{"a":None}'
check 1 'truncated tail'        '{"a":1,"b":'
check 1 'unclosed nested'       '{"a":{"b":1}'
check 1 'unopened brace'        '"a":1}'
check 1 'empty line'            ''
check 1 'comment'               '{"a":1} // note'

# --- structural extraction -------------------------------------------------
top_ok=0
fge_json_top '{"k":"v","n":{"deep":[1,2]},"s":"has,comma and \"quote\"","z":null}' || top_ok=1
top_k=$(fge_json_unquote "${FGE_JSON[k]}")
top_n=${FGE_JSON[n]}
top_s=$(fge_json_unquote "${FGE_JSON[s]}")
top_z=${FGE_JSON[z]}
top_count=${#FGE_JSON[@]}

# A duplicate key is a defect to report, not two values to merge.
dup_rejected=0
fge_json_top '{"a":1,"a":2}' || dup_rejected=1

# The same duplicate is still grammatically valid JSON, so the validator and
# the extractor deliberately disagree here; that difference is intentional.
dup_grammatical=0
fge_json_validate_line '{"a":1,"a":2}' || dup_grammatical=1

arr_ok=0
fge_json_array_strings '["one","tw\"o","th,ree","",""]' || arr_ok=1
arr_count=${#FGE_JSON_ARRAY[@]}
arr_q=${FGE_JSON_ARRAY[1]}
arr_c=${FGE_JSON_ARRAY[2]}

empty_arr_ok=0
fge_json_array_strings '[]' || empty_arr_ok=1
empty_arr_count=${#FGE_JSON_ARRAY[@]}

# An array of non-strings must be refused rather than silently coerced.
num_arr_rejected=0
fge_json_array_strings '[1,2]' || num_arr_rejected=1

# --- escape/round-trip -----------------------------------------------------
round_in=$(printf 'tab\there\nnewline "quoted" back\\slash \001ctl')
esc=$(fge_json_escape "$round_in")
round_ok=0
fge_json_validate_line "{\"v\":\"$esc\"}" || round_ok=1
fge_json_top "{\"v\":\"$esc\"}"
round_out=$(fge_json_unquote "${FGE_JSON[v]}")

fge_phase assert

fge_assert_eq FG-000A-JSON-001 '' "$mismatches" \
  'every grammar corpus case gets the intended verdict'
fge_assert_eq FG-000A-JSON-002 44 "$checked" \
  'the corpus actually ran every case'
fge_assert_cmd FG-000A-JSON-003 'the corpus contains real accept cases' \
  test "${#accepted}" -gt 0
fge_assert_cmd FG-000A-JSON-004 'the corpus contains real reject cases' \
  test "${#rejected}" -gt 0

fge_assert_eq FG-000A-JSON-005 0 "$top_ok"    'fge_json_top parses a mixed object'
fge_assert_eq FG-000A-JSON-006 4 "$top_count" 'fge_json_top finds every top-level key'
fge_assert_eq FG-000A-JSON-007 v "$top_k"     'fge_json_top decodes a string value'
fge_assert_eq FG-000A-JSON-008 '{"deep":[1,2]}' "$top_n" \
  'fge_json_top returns a nested value as raw JSON'
fge_assert_eq FG-000A-JSON-009 'has,comma and "quote"' "$top_s" \
  'fge_json_top does not split a value on commas or quotes inside a string'
fge_assert_eq FG-000A-JSON-010 null "$top_z"  'fge_json_top preserves a null'

fge_assert_eq FG-000A-JSON-011 1 "$dup_rejected" \
  'fge_json_top refuses a duplicate key rather than merging it'
fge_assert_eq FG-000A-JSON-012 0 "$dup_grammatical" \
  'the grammar validator still accepts that same line, as JSON requires'

fge_assert_eq FG-000A-JSON-013 0 "$arr_ok"          'fge_json_array_strings parses'
fge_assert_eq FG-000A-JSON-014 5 "$arr_count"       'it counts every element including empties'
fge_assert_eq FG-000A-JSON-015 'tw"o' "$arr_q"      'it decodes an escaped quote'
fge_assert_eq FG-000A-JSON-016 'th,ree' "$arr_c"    'it does not split on a comma inside an element'
fge_assert_eq FG-000A-JSON-017 0 "$empty_arr_ok"    'it accepts an empty array'
fge_assert_eq FG-000A-JSON-018 0 "$empty_arr_count" 'an empty array yields no elements'
fge_assert_eq FG-000A-JSON-019 1 "$num_arr_rejected" \
  'an array of numbers is refused rather than coerced to strings'

fge_assert_eq FG-000A-JSON-020 0 "$round_ok" \
  'escaped output is itself valid JSON'
fge_assert_eq FG-000A-JSON-021 "$round_in" "$round_out" \
  'escape then unquote round-trips tabs, newlines, quotes, backslashes and control bytes'
