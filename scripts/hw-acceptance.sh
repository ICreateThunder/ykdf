#!/usr/bin/env bash
# YKDF hardware acceptance helper. See docs/hardware-acceptance.md.
#
# Captures a fixed matrix of *public* keys (`ykdf pubkey`, never secrets) from a
# YubiKey so two devices can be compared byte-for-byte. Identical public keys
# across two devices prove an identical derivation root (same slot-9d scalar,
# and for layered rows the same slot-2 HMAC secret).
#
#   hw-acceptance.sh capture <outfile>     # derive the matrix from the plugged-in key
#   hw-acceptance.sh diff <fileA> <fileB>  # compare two captures, PASS/FAIL
#
# The ykdf binary is taken from $YKDF (default: ykdf on PATH). Each row prompts
# for the PIV PIN and a touch; layered rows also touch the OTP slot.
set -euo pipefail

YKDF="${YKDF:-ykdf}"

# Matrix rows: "mode profile pipeline purpose index".
# Standard rows exercise both HKDF variants and the SHAKE pipeline; layered rows
# additionally fold in the slot-2 HMAC factor.
MATRIX=(
  "standard x25519     hkdf-sha512   acc 0"
  "standard ed25519    hkdf-sha512   acc 0"
  "standard age-x25519 hkdf-sha512   acc 0"
  "standard x25519     hkdf-sha3-512 acc 0"
  "standard mlkem768   shake256      acc 0"
  "standard mldsa65    shake256      acc 0"
  "layered  x25519     hkdf-sha512   acc 0"
  "layered  mlkem768   shake256      acc 0"
)

capture() {
  local outfile="$1"
  : > "$outfile"
  local i=0 total="${#MATRIX[@]}"
  for row in "${MATRIX[@]}"; do
    i=$((i + 1))
    # shellcheck disable=SC2086 # word-splitting the row into fields is intended
    set -- $row
    local mode="$1" profile="$2" pipeline="$3" purpose="$4" index="$5"
    local args=(pubkey --profile "$profile" --pipeline "$pipeline"
      --purpose "$purpose" --index "$index")
    [ "$mode" = "layered" ] && args+=(--layered)
    echo "[$i/$total] $mode $profile/$pipeline (PIN + touch)..." >&2
    local pub
    pub="$("$YKDF" "${args[@]}")"
    printf '%s %s %s %s %s\t%s\n' \
      "$mode" "$profile" "$pipeline" "$purpose" "$index" "$pub" >> "$outfile"
  done
  echo "Wrote ${total} public keys to ${outfile}." >&2
}

diff_captures() {
  local a="$1" b="$2"
  if diff -u "$a" "$b"; then
    echo "PASS: ${a} and ${b} are byte-identical."
  else
    echo "FAIL: captures differ (see the diff above)." >&2
    return 1
  fi
}

case "${1:-}" in
  capture)
    [ $# -eq 2 ] || { echo "usage: $0 capture <outfile>" >&2; exit 2; }
    capture "$2"
    ;;
  diff)
    [ $# -eq 3 ] || { echo "usage: $0 diff <fileA> <fileB>" >&2; exit 2; }
    diff_captures "$2" "$3"
    ;;
  *)
    echo "usage: $0 {capture <outfile> | diff <fileA> <fileB>}" >&2
    exit 2
    ;;
esac
