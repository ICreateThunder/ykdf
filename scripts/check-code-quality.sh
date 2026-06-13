#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

need () { command -v "$1" >/dev/null 2>&1 || { echo "$1 not installed: $2"; exit 2; }; }
need typos      "run 'cargo install --locked typos-cli'"
need cargo      "install Rust via https://rustup.rs"
need shellcheck "install from https://github.com/koalaman/shellcheck or your package manager"

echo "=== typos ==="; typos
echo "=== cargo fmt --check ==="; cargo fmt --check
echo "=== cargo clippy --workspace --all-targets -- -D warnings ==="
cargo clippy --workspace --all-targets -- -D warnings
echo "=== shellcheck scripts/*.sh ==="; shellcheck scripts/*.sh
