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
# Read the key from the file inside the process so it never lands in the
# argument list (openssl's `-macopt hexkey:<v>` would expose it via
# /proc/<pid>/cmdline — the same leak the --*-file flags removed).
python3 -c 'import hmac,hashlib; k=bytes.fromhex(open("hmac.hex").read().strip()); print(hmac.new(k, b"ykdf-v1", hashlib.sha1).hexdigest())'
```

The YubiKey computes plain `HMAC-SHA1(secret, challenge)`, so a match between the
two keys (and the host value) confirms `ykdf init` wrote the intended 20-byte
secret to slot 2.

## Test 3 — confirm both factors contribute (optional)

Tests 1 and 2 prove two devices derive the same keys, not *why*. If the code
silently dropped a factor (a null or a constant in place of the real PIV ECDH or
HMAC), two devices that share both factors would still match, so the match alone
does not prove each factor feeds the output. The IKM is `self-ECDH(slot 9d)` for
standard mode and `self-ECDH(slot 9d) || HMAC-SHA1(slot 2, "ykdf-v1")` for
layered (`crates/ykdf-yubikey/src/lib.rs`); the context string does not encode
the mode, so standard and layered differ only in the IKM.

**Presence (one device, no writes).** Standard and layered output must differ:

```bash
"$YKDF" pubkey --profile x25519 --purpose acc            # IKM = ECDH
"$YKDF" pubkey --profile x25519 --purpose acc --layered  # IKM = ECDH || HMAC
```

Equal output means the HMAC factor is not mixed in. A fresh `ykdf clone` (a new
random scalar) with slot 2 unchanged must also change the output, which confirms
the PIV factor is mixed in.

**Value sensitivity (destructive).** Re-program slot 2 with a different secret:
the layered output changes and the standard output does not, so the HMAC value
(not a constant) drives the result. This breaks the two-key match, so do it only
on a device you are about to re-provision.

**Definitive (recompute the IKM off-device).** `derive`/`pubkey` accept
`--ikm-file`, so you can build the IKM from the slot 9d scalar and the slot 2
secret and check the hardware path produces the same key:

```bash
python3 - <<'PY'
from cryptography.hazmat.primitives.asymmetric import ec
import hmac, hashlib
scalar = int(open("scalar.hex").read().strip(), 16)        # slot 9d scalar
secret = bytes.fromhex(open("hmac.hex").read().strip())    # slot 2 HMAC secret
priv = ec.derive_private_key(scalar, ec.SECP256R1())
shared = priv.exchange(ec.ECDH(), priv.public_key())       # self-ECDH x-coord, 32 bytes
mac = hmac.new(secret, b"ykdf-v1", hashlib.sha1).digest()  # 20 bytes
open("ikm.bin", "wb").write(shared + mac)                  # IKM = ECDH || HMAC
PY

"$YKDF" pubkey --profile x25519 --purpose acc --layered           # hardware
"$YKDF" pubkey --profile x25519 --purpose acc --ikm-file ikm.bin  # recomputed
```

Byte-identical output proves the hardware folds in exactly the real ECDH and
HMAC values, with no null or default substituted. For the standard-only check,
write just `shared` and drop `--layered`. Reading the scalar and secret from
files (not the command line) keeps them out of the process table.

## Cleanup

```bash
shred -u scalar.hex hmac.hex a.txt b.txt
shred -u ikm.bin 2>/dev/null || true   # only if you ran Test 3
```

The captures hold only public keys, but the secret files are the single copy of
the slot-9d scalar and the HMAC secret; destroy them (or store them as your
deliberate backup) once the test passes. `ikm.bin` from Test 3 is raw key
material, so destroy it too.
