# Ideas and experiments

A log of design ideas that are out of scope for current work but worth keeping.
Nothing here is committed to a roadmap; these are thought experiments and
candidate features.

## Exportable / importable slot 9d key (near-term follow-up)

On-device PIV generation (`ykdf init`, default) is non-extractable: the slot 9d
key never leaves the YubiKey, so it cannot be backed up. Losing the device loses
every key derived from the PIV factor.

An opt-in exportable mode would trade some hardware strength for a real backup:

- `ykdf init --exportable`: generate a P-256 key in host memory, import it into
  slot 9d via `piv::import_ecc_key` (already feasible; `untested` feature is
  enabled), write the carrier certificate as usual, and surface the 32-byte
  scalar once so it can be backed up.
- `ykdf init --import <key>`: provision a second YubiKey from the saved scalar,
  giving two devices that produce identical self-ECDH output — a true backup.

Fully compatible with the existing self-ECDH derive path: an imported key still
has a public key, still gets a cert, and `read_public_key` + `ecdh` are
unchanged.

Security notes:

- The private key transits host RAM; zeroize immediately after import.
- Key conveyance is the sensitive surface: display-once vs passphrase-encrypted
  file (could reuse the age/KDF machinery). Decide before building.
- Weaker than non-extractable on-device generation; document the tradeoff so the
  user chooses deliberately.

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

- PIN / PUK / management-key rotation as part of or alongside `ykdf init`.
- Seed-derived HMAC slot 2 secret (reproducible from a passphrase) if the
  display-once model proves inconvenient.
- Keep secrets out of the process table: `ykdf init --hmac-secret` and
  `--mgmt-key` take values as command-line arguments, which are visible to
  other local users via `/proc/<pid>/cmdline` and `ps`. Add a file/stdin/env
  input path (e.g. `--hmac-secret-file -`) so explicit secrets never hit the
  argument list. The default random-generation path is unaffected.
