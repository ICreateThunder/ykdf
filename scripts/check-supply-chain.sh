#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

need () { command -v "$1" >/dev/null 2>&1 || { echo "$1 not installed: $2"; exit 2; }; }
need cargo-audit "run 'cargo install --locked cargo-audit'"
need cargo-deny  "run 'cargo install --locked cargo-deny'"
need gitleaks    "install from https://github.com/gitleaks/gitleaks/releases or your package manager"

echo "=== cargo audit ===";    cargo audit
echo "=== cargo deny check ==="; cargo deny check
echo "=== gitleaks dir ===";   gitleaks dir . -c .gitleaks.toml
