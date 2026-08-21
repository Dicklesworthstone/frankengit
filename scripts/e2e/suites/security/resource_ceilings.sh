#!/usr/bin/env bash
# FG-066b: resource ceilings over every currently executable untrusted-input
# surface.  The suite is deliberately under `suites/`, because run_all.sh
# discovers that tree and never executes root-level scripts.
#
# The adjacent TSV is a verifier input, not a second policy authority.  It
# names the production-owned bound and the concrete corpus that must exercise
# an at-limit permitted input and an over-limit typed refusal.  Surfaces whose
# parser/transport does not exist are recorded as `non-admitted`; this script
# grants them no coverage credit and makes no claim that a future API is safe.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly INVENTORY="$SCRIPT_DIR/resource_ceilings.tsv"
readonly SEED="${FGIT_RESOURCE_CEILINGS_SEED:-66021}"

require_inventory_surface() {
  local surface=$1 state=$2
  if grep -q "^${surface}"$'\t'"${state}"$'\t' "$INVENTORY"; then
    fge_pass "FG-066B-INVENTORY-${surface}" \
      "$surface is declared as $state in the ceiling inventory"
  else
    fge_fail "FG-066B-INVENTORY-${surface}" \
      "$surface is missing its $state declaration from the ceiling inventory"
  fi
}

require_implemented_ceiling() {
  local surface=$1 dimension=$2 bound=$3 corpus=$4
  local row
  row="${surface}"$'\t'implemented$'\t'"${dimension}"$'\t'"${bound}"$'\t'"${corpus}"
  if grep -Fqx "$row" "$INVENTORY"; then
    fge_pass "FG-066B-CEILING-${surface}-${dimension}" \
      "$surface/$dimension remains bound by $bound and exercised by $corpus"
  else
    fge_fail "FG-066B-CEILING-${surface}-${dimension}" \
      "$surface/$dimension is missing its exact production bound-to-corpus mapping"
  fi
}

validate_inventory() {
  local surface state dimension bound corpus extra
  local implemented=0 non_admitted=0 malformed=0

  while IFS=$'\t' read -r surface state dimension bound corpus extra; do
    case "$surface" in
      '' | \#*) continue ;;
    esac
    if [ -n "${extra:-}" ] || [ -z "$state" ] || [ -z "$dimension" ] || [ -z "$bound" ] || [ -z "$corpus" ]; then
      malformed=$((malformed + 1))
      continue
    fi
    case "$state" in
      implemented)
        implemented=$((implemented + 1))
        [ "$corpus" != '-' ] || malformed=$((malformed + 1))
        ;;
      non-admitted)
        non_admitted=$((non_admitted + 1))
        [ "$corpus" = '-' ] || malformed=$((malformed + 1))
        ;;
      *) malformed=$((malformed + 1)) ;;
    esac
  done < "$INVENTORY"

  fge_assert_eq FG-066B-INVENTORY-001 0 "$malformed" \
    'every inventory row has a surface, state, dimension, bound, and corpus classification'
  fge_assert_eq FG-066B-INVENTORY-002 19 "$implemented" \
    'all 19 implemented surface/dimension ceilings remain mapped to a concrete corpus'
  fge_assert_eq FG-066B-INVENTORY-003 7 "$non_admitted" \
    'all seven named but absent product surfaces remain explicit non-claims'

  require_inventory_surface git-object-framing implemented
  require_inventory_surface pack-quarantine implemented
  require_inventory_surface wire-receive-pack implemented
  require_inventory_surface document-renderer implemented
  require_inventory_surface treefs-export implemented
  require_inventory_surface workflow-yaml non-admitted
  require_inventory_surface package-parser non-admitted
  require_inventory_surface webhook-payload non-admitted
  require_inventory_surface atp-transfer-block non-admitted
  require_inventory_surface lfs-pointer non-admitted
  require_inventory_surface policy-language non-admitted
  require_inventory_surface api-body non-admitted

  require_implemented_ceiling git-object-framing decompressed_object_bytes \
    ParseLimits::max_object_bytes fgit-git-object/adversarial_refusal
  require_implemented_ceiling git-object-framing loose_header_bytes \
    ParseLimits::max_loose_header_bytes fgit-git-object/adversarial_refusal
  require_implemented_ceiling pack-quarantine compressed_input_bytes \
    PackLimits::max_input_bytes fgit-pack/bombs_reader
  require_implemented_ceiling pack-quarantine entry_count \
    PackLimits::max_entries fgit-pack/bombs_reader
  require_implemented_ceiling pack-quarantine object_bytes \
    PackLimits::max_object_bytes fgit-pack/bombs_reader
  require_implemented_ceiling pack-quarantine aggregate_expanded_bytes \
    PackLimits::max_total_expanded_bytes fgit-pack/bombs_reader
  require_implemented_ceiling pack-quarantine inflate_expansion_ratio \
    PackLimits::max_expansion_ratio fgit-pack/bombs_reader
  require_implemented_ceiling wire-receive-pack command_count \
    ReceiveLimits::max_commands fgit-wire/receivepack_adversarial
  require_implemented_ceiling wire-receive-pack quarantine_bytes \
    ReceiveLimits::max_quarantine_bytes fgit-wire/receivepack_adversarial
  require_implemented_ceiling wire-receive-pack propagated_pack_limits \
    ReceiveLimits::pack fgit-wire/receivepack_limits_propagation
  require_implemented_ceiling document-renderer input_bytes \
    Limits::max_input_bytes fgit-doc/suite::adversarial
  require_implemented_ceiling document-renderer line_bytes \
    StructuralLimits::max_line_bytes fgit-doc/suite::adversarial
  require_implemented_ceiling document-renderer node_count \
    StructuralLimits::max_nodes fgit-doc/suite::adversarial
  require_implemented_ceiling document-renderer nesting_depth \
    StructuralLimits::max_depth fgit-doc/suite::adversarial
  require_implemented_ceiling document-renderer inline_delimiters \
    StructuralLimits::max_inline_delimiters fgit-doc/suite::adversarial
  require_implemented_ceiling treefs-export base_object_bytes \
    ParseLimits::max_object_bytes fgit-treefs/export_budgets
  require_implemented_ceiling treefs-export constructed_object_count \
    ExportLimits::max_objects fgit-treefs/resource_ceiling_inventory
  require_implemented_ceiling treefs-export constructed_total_bytes \
    ExportLimits::max_total_bytes fgit-treefs/export_budgets
  require_implemented_ceiling treefs-export tree_entry_count \
    ExportLimits::max_tree_entries fgit-treefs/export_budgets
}

run_corpus() {
  local id=$1 package=$2 target=$3 filter=$4 expected=$5 required_test=$6
  local status=0 output='' passed=0

  if [ -n "$filter" ]; then
    fge_capture "$id" env RCH_CARGO_WRAPPER_BYPASS=1 \
      FGIT_RESOURCE_CEILINGS_SEED="$SEED" \
      cargo test --locked -p "$package" --test "$target" -- "$filter" \
      || status=$?
  else
    fge_capture "$id" env RCH_CARGO_WRAPPER_BYPASS=1 \
      FGIT_RESOURCE_CEILINGS_SEED="$SEED" \
      cargo test --locked -p "$package" --test "$target" \
      || status=$?
  fi
  output="${FGE_LAST_STDOUT:-}"$'\n'"${FGE_LAST_STDERR:-}"

  fge_assert_exit "${id}-exit" 0 "$status" \
    "$package/$target completes its resource-ceiling corpus"
  passed="$(printf '%s\n' "$output" | grep -c '^test .* ok$' || true)"
  fge_assert_eq "${id}-count" "$expected" "$passed" \
    "$package/$target ran exactly its pinned resource-ceiling probe count"
  fge_assert_contains "${id}-anchor" "$output" "$required_test" \
    "$package/$target retained its named paired trip/pass probe"
}

fge_init fg066b-resource-ceilings
fge_context bead frankengit-fg066b-resource-ceilings-n221
fge_context evidence_class E1+E4
fge_context registry scripts/e2e/suites/security/resource_ceilings.tsv
fge_context seed "$SEED"
fge_context seed_semantics 'all current boundary fixtures are deterministic; the settable seed is recorded as the campaign replay namespace rather than falsely described as an RNG input'
fge_context coverage 'Git object framing, pack quarantine, wire receive-pack, document rendering, and TreeFS export only'
fge_context non_claim 'Workflow YAML, package, webhook, ATP block, LFS, policy-language, and request-body transports are not implemented/admitted in this checkout. Their rows are completeness disclosures, not pass evidence.'
fge_context durability_authority 'The exercised pack and receive corpora require refused input to leave no quarantine result; the TreeFS corpus exercises only an export proposal, which cannot publish an authority head.'

fge_phase setup
fge_assert_file FG-066B-INVENTORY-000 "$INVENTORY" \
  'the machine-consumed ceiling inventory is committed beside this suite'
validate_inventory

fge_phase action
run_corpus FG-066B-OBJECT fgit-git-object adversarial_refusal '' 2 \
  refusal_corpus_is_stable_and_surfaces_the_epoch_zero_divergence
run_corpus FG-066B-PACK fgit-pack bombs_reader '' 4 \
  declared_size_and_aggregate_bombs_trip_before_entry_output_allocation
run_corpus FG-066B-WIRE fgit-wire receivepack_adversarial '' 9 \
  a_pack_past_the_quarantine_ceiling_is_refused_without_ever_exceeding_it
run_corpus FG-066B-WIRE-PROPAGATION fgit-wire receivepack_limits_propagation '' 3 \
  a_tightened_session_bound_refuses_the_very_pack_a_permissive_one_accepts
run_corpus FG-066B-DOC fgit-doc suite adversarial:: 11 \
  an_oversized_input_is_refused_and_the_largest_accepted_one_is_not
run_corpus FG-066B-TREEFS fgit-treefs export_budgets '' 8 \
  a_byte_budget_is_enforced_and_a_generous_one_proceeds
run_corpus FG-066B-TREEFS-OBJECTS fgit-treefs resource_ceiling_inventory '' 1 \
  object_budget_refuses_one_below_the_exact_constructed_count_and_accepts_at_it
