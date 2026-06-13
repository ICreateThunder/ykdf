#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
./check-supply-chain.sh
./check-code-quality.sh
./check-workflows.sh
