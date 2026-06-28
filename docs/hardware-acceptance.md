# Hardware acceptance tests

Two on-hardware checks that the automated suite cannot cover, because they need
two physical YubiKeys and a destructive write. Run them at the bench; everything
else (the byte-level format) is already proven by the golden vectors and the
reference implementations.

1. **Shared backup** — two YubiKeys provisioned with the same secrets derive
   byte-identical keys. This validates the backup story the docs promise but the
   CI cannot exercise.
2. **Slot-2 write path** — `ykdf init` actually programs OTP slot 2 such that the
   challenge-response read used by layered mode works. This is exercised as part
   of test 1 (the spare's slot 2 is written by `ykdf init`), with an optional
   independent cross-check.

Everything compared here is a **public key** (`ykdf pubkey`), so no secret is
ever written to disk. Identical public keys across two devices prove an identical
derivation root (same slot-9d scalar; for layered rows, same slot-2 HMAC secret).

## Safety preconditions

These tests **re-provision** PIV slot 9d and OTP slot 2 on both devices. Only
those two slots are touched. Before starting:

- These keys must be **development keys with nothing live on slot 9d / slot 2**.
  Re-provisioning changes the derivation root, so any keys previously derived
  from a device change.
- **Never run `ykman piv reset`** — it wipes *every* PIV slot, including any
  unrelated key you keep elsewhere (e.g. a SOPS/age key on another slot). `ykdf
  init --force` only overwrites slot 9d.
- Only **OTP slot 2** is programmed. A factory Yubico OTP or other config on
  **slot 1** is left untouched.
- If the PIV management key is not the factory default (e.g. PIN-protected on
  firmware 5.7+), pass `--mgmt-key protected` (or `--mgmt-key-file`) to every
  `ykdf init` below.
- Layered mode reads the HMAC factor over `hidraw`. Ensure the udev rule is
  installed and **replug** the key (see [provisioning.md](provisioning.md)). Do
  not run `udevadm trigger`.

Build the binary once and point the helper at it:

```bash
cargo build --release
export YKDF="$PWD/target/release/ykdf"
```

`pcscd` must be running for the PIV path (`systemctl status pcscd`).

## Test 1 — shared backup (two devices, byte-identical derivation)

Pick **device A** (any key) and **device B** (the spare you don't mind
re-rooting). Each `ykdf pubkey` row prompts for the PIV PIN and a touch; layered
rows also touch the OTP slot.

```bash
# 1. Provision device A: generate an EXPORTABLE slot-9d key + program slot 2.
#    The scalar and HMAC secret are printed once to stderr; capture them to
#    files so they stay out of the process table.
"$YKDF" init --exportable --layered            # add --mgmt-key protected if needed
#   -> "slot 9d private key (hex): <SCALAR>"   ... paste into scalar.hex
#   -> "Generated HMAC secret ...: <HMAC>"     ... paste into hmac.hex
printf %s '<SCALAR>' > scalar.hex
printf %s '<HMAC>'   > hmac.hex

# 2. Capture device A's public-key matrix.
scripts/hw-acceptance.sh capture a.txt

# 3. Swap to device B (the spare). Import the SAME secrets.
"$YKDF" init --import-file scalar.hex --layered --hmac-secret-file hmac.hex --force

# 4. Capture device B's matrix.
scripts/hw-acceptance.sh capture b.txt

# 5. Compare. PASS = byte-identical across every row, both pipelines, both modes.
scripts/hw-acceptance.sh diff a.txt b.txt
```

**Pass criteria:** `diff` reports `PASS`. The standard rows prove the PIV ECDH
root matches across both HKDF variants and the SHAKE pipeline; the layered rows
prove the slot-2 HMAC factor was written and is mixed in identically — i.e. the
slot-2 write path on device B works.

**If it fails:** a difference in *standard* rows means the slot-9d scalar import
diverged; a difference only in *layered* rows isolates the slot-2 HMAC secret or
its programming.

## Test 2 — independent slot-2 cross-check (optional)

Test 1 already exercises the slot-2 write path end to end through `ykdf`. For an
independent confirmation that the programmed secret is exactly what you intended,
compare the device's raw challenge-response against a host computation. The
layered HMAC challenge is the fixed ASCII string `ykdf-v1`, whose bytes in hex
are `796b64662d7631` (`ykman` takes the challenge in hex, not ASCII).

```bash
# Device: send the "ykdf-v1" challenge to slot 2 (touch when it blinks). Prints
# the 40-hex HMAC-SHA1 response. Run on both keys; identical => same secret.
ykman otp calculate 2 796b64662d7631

# Host: HMAC-SHA1(secret, "ykdf-v1") — the response the YubiKey must return.
printf 'ykdf-v1' | openssl dgst -sha1 -mac HMAC -macopt "hexkey:$(cat hmac.hex)"
```

The YubiKey computes plain `HMAC-SHA1(secret, challenge)`, so a match between the
two keys (and the host value) confirms `ykdf init` wrote the intended 20-byte
secret to slot 2.

## Cleanup

```bash
shred -u scalar.hex hmac.hex a.txt b.txt
```

The captures hold only public keys, but the secret files are the single copy of
the slot-9d scalar and the HMAC secret — destroy them (or store them as your
deliberate backup) once the test passes.
