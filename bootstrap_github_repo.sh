#!/usr/bin/env bash
set -euo pipefail

readonly RESET='\033[0m'
readonly BOLD='\033[1m'
readonly GREEN='\033[32m'
readonly YELLOW='\033[33m'
readonly RED='\033[31m'
readonly CYAN='\033[36m'

info() { printf '%b%s%b\n' "${CYAN}" "$*" "${RESET}"; }
success() { printf '%b%s%b\n' "${GREEN}" "$*" "${RESET}"; }
warn() { printf '%b%s%b\n' "${YELLOW}" "$*" "${RESET}"; }
fail() { printf '%b%s%b\n' "${RED}" "$*" "${RESET}" >&2; exit 1; }

OWNER="${FRANKENGIT_GITHUB_OWNER:-Dicklesworthstone}"
REPO="${FRANKENGIT_GITHUB_REPO:-frankengit}"
FULL_REPO="${OWNER}/${REPO}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$SCRIPT_DIR"

command -v git >/dev/null 2>&1 || fail 'git is required.'
command -v gh >/dev/null 2>&1 || fail 'GitHub CLI (gh) is required: https://cli.github.com/'

gh auth status >/dev/null 2>&1 || fail 'GitHub CLI is not authenticated. Run: gh auth login'

if [[ ! -d .git ]]; then
  info 'Initializing local Git repository on main...'
  git init -b main
fi

current_branch="$(git branch --show-current)"
if [[ -z "$current_branch" ]]; then
  git checkout -b main
elif [[ "$current_branch" != main ]]; then
  warn "Current branch is '$current_branch'; the script will publish that branch as main only after a safe local rename."
  git branch -m main
fi

if [[ -n "$(git status --porcelain)" ]]; then
  info 'Committing the current public-ready source tree...'
  git add --all
  git commit -m 'docs: publish the initial FrankenGit architecture and execution plan'
else
  info 'Local working tree is already clean.'
fi

if gh repo view "$FULL_REPO" >/dev/null 2>&1; then
  info "GitHub repository ${FULL_REPO} already exists."
else
  info "Creating public GitHub repository ${FULL_REPO}..."
  gh repo create "$FULL_REPO" \
    --public \
    --description 'Git-compatible, agent-native, repairable, self-hostable code forge and GitHub alternative.' \
    --source . \
    --remote origin
fi

expected_url="https://github.com/${FULL_REPO}.git"
if git remote get-url origin >/dev/null 2>&1; then
  actual_url="$(git remote get-url origin)"
  if [[ "$actual_url" != "$expected_url" && "$actual_url" != "git@github.com:${FULL_REPO}.git" ]]; then
    fail "Existing origin points to '$actual_url', not ${FULL_REPO}. Refusing to overwrite it."
  fi
else
  git remote add origin "$expected_url"
fi

info 'Pushing main and setting upstream...'
git push --set-upstream origin main

success "Published ${FULL_REPO}."
printf '%b%s%b\n' "${BOLD}" "https://github.com/${FULL_REPO}" "${RESET}"
