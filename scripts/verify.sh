#!/usr/bin/env bash
# Runs every check that must pass before a change is considered complete.
# Pass --fix to rewrite files, then run the same steps as `pnpm verify`.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--fix" ]]; then
  printf '\033[36m==> rust format (write)\033[0m\n'
  cargo fmt --all
  printf '\033[36m==> js format (write)\033[0m\n'
  pnpm format
  printf '\033[36m==> js lint (fix)\033[0m\n'
  pnpm lint:fix
fi

exec pnpm verify
