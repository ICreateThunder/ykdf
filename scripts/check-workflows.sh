#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

need () { command -v "$1" >/dev/null 2>&1 || { echo "$1 not installed: $2"; exit 2; }; }
need actionlint "install from https://github.com/rhysd/actionlint or your package manager"

echo "=== actionlint ==="; actionlint
