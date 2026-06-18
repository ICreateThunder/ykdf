# Ideas and experiments

A log of design ideas that are out of scope for current work but worth keeping.
Nothing here is committed to a roadmap; these are thought experiments and
candidate features.

## Exportable / importable slot 9d key (IMPLEMENTED)

Shipped as `ykdf init --exportable` (host-generate the P-256 scalar, import to
slot 9d, display it once) and `ykdf init --import <hex>` (provision another
device from the saved scalar). Conveyance chosen: display-once hex on stderr
with a loud "only copy" warning. A passphrase-encrypted-file conveyance could
still be added later if display-once proves inconvenient.

## `t`-of-`n` Shamir backup (thought experiment)

Split an exportable seed into Shamir shares and reconstruct from any `t`.

- **Share wrapping:** (a) symmetric, each share encrypted under a key derived
  from that YubiKey's HMAC challenge-response; or (b) asymmetric, each share
  encrypted to public-key material the holder already controls (a personal
  GPG/PIV public cert, or the OpenPGP key on the same YubiKey), so the device's
  existing asymmetric decryption unwraps the share. Option (b) reuses standard
  primitives and binds shares to identities via their public certs.
- **Model constraint:** reconstruction happens in host RAM, so this only fits
  the exportable/software-seed model above, never a non-extractable on-device
  PIV key.
- **Operational complexity (the real blocker):** a `t`-of-`n` scheme nominally
  needs `t` keys present at reconstruction, and plugging in many YubiKeys at once
  is impractical. Mitigation: sequential insertion, prompting for one key at a
  time, unwrapping its share, then moving on; needs only a single port (or an NFC
  tap on mobile). Favor low thresholds such as 2-of-3.
- **Implementation:** use a vetted SSS library (`vsss-rs` or SLIP-39) with
  constant-time GF(256); zeroize the reconstructed secret immediately.

## Other deferred items

- AES-192 PIV management keys: the `yubikey` 0.8 backend only supports TDES
  management keys, so firmware 5.7+ devices (whose default management key is
  AES-192) cannot be authenticated by `ykdf init` even with the default value.
  Blocked until the `yubikey` crate gains non-TDES MGM key support; workaround
  is to set a TDES management key via `ykman`. PIN-protected/derived TDES keys
  are supported (`--mgmt-key protected|derived`).
- PIN / PUK / management-key rotation as part of or alongside `ykdf init`.
- Seed-derived HMAC slot 2 secret (reproducible from a passphrase) if the
  display-once model proves inconvenient.
- Keep secrets out of the process table: `ykdf init --hmac-secret`,
  `--mgmt-key`, and `--import` take values as command-line arguments, which are
  visible to other local users via `/proc/<pid>/cmdline` and `ps` (and land in
  shell history). Add a file/stdin/fd input path (e.g. `--import -`,
  `--hmac-secret-file <path>`) so explicit secrets never hit the argument list.
  The default random-generation paths are unaffected.
