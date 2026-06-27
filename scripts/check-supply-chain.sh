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

# OSV scan of every lockfile (Cargo workspace + Go reference module). Optional
# locally - CI's osv-scan job is the gate - so skip cleanly when not installed.
if command -v osv-scanner >/dev/null 2>&1; then
  echo "=== osv-scanner ==="
  osv-scanner scan source --config=osv-scanner.toml --recursive ./
else
  echo "=== osv-scanner (skipped: not installed) ==="
fi
