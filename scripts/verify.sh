#!/usr/bin/env bash
# Runs every check that must pass before a phase is considered complete.
# Pass --fix to rewrite files instead of only checking them.
set -euo pipefail

cd "$(dirname "$0")/.."

failures=()

step() {
  local name="$1"; shift
  printf '\033[36m==> %s\033[0m\n' "$name"
  if ! "$@"; then
    failures+=("$name")
    printf '\033[31m    FAILED: %s\033[0m\n' "$name"
  fi
}

if [[ "${1:-}" == "--fix" ]]; then
  step 'rust format (write)' cargo fmt --all
  step 'js format (write)'   pnpm format
  step 'js lint (fix)'       pnpm lint:fix
else
  step 'rust format' cargo fmt --all -- --check
  step 'js format'   pnpm format:check
  step 'js lint'     pnpm lint
fi

step 'rust clippy'    cargo clippy --workspace --all-targets --all-features -- -D warnings
step 'rust tests'     cargo test --workspace
step 'js typecheck'   pnpm -r typecheck
step 'js tests'       pnpm -r test:run
step 'frontend build' pnpm --filter '@rc/desktop-client' build

echo
if (( ${#failures[@]} > 0 )); then
  printf '\033[31m%d step(s) failed:\033[0m\n' "${#failures[@]}"
  printf '\033[31m  - %s\033[0m\n' "${failures[@]}"
  exit 1
fi

printf '\033[32mAll checks passed.\033[0m\n'
