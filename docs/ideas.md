# Ideas and experiments

> **Warning — unvetted thinking ahead.** Nothing in this file is reviewed,
> finalised, or security-audited. These are open thought experiments: some may be
> insecure, premature, or mutually contradictory. Do not treat anything here as a
> recommendation, a commitment, or a description of shipped behaviour. Discussion
> is open and welcome — challenge it.

A log of design ideas that are out of scope for current work but worth keeping.
Nothing here is committed to a roadmap; these are thought experiments and
candidate features.

## Open design questions

- **Manifest file:** stay fully stateless (context strings documented externally)
  vs. an optional local manifest listing derived keys for usability. Leaning
  stateless to avoid introducing state to sync and back up; any manifest would be
  a non-authoritative convenience, never required to re-derive.

(The HMAC challenge strategy - fixed `b"ykdf-v1"` vs. context-as-challenge - is
settled: the fixed challenge is frozen into the v1 format.)

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

## Hierarchical / bulk provisioning - the "pyramid" (thought experiment)

Provision many YubiKeys from a single root, in one session, with the secret kept
in host RAM only (never displayed, clipboarded, or written). Two distinct shapes
that are easy to conflate:

- **Clones (same root), IMPLEMENTED as `ykdf clone`:** every device gets the
  *same* slot-9d scalar (and, if layered, the same slot-2 HMAC secret), so all
  devices derive *identical* keys - true interchangeable backups. "Generate one
  scalar, push it to N keys, wipe the in-RAM copy." Shipped as the swap-session
  `ykdf clone` (one port, insert/provision/swap/repeat, secret held in RAM and
  zeroized on exit); the single-device `init --import-file` flow is its
  one-at-a-time ancestor.
- **Children (derived roots):** a master derives a *different* root per device,
  `child_i = HKDF(master_ikm, "ykdf-root-v1", i)` (and a matching child HMAC), so
  each device is an independent identity the master can *recreate* but which is
  **not** a backup of its siblings. This is hardened BIP-32-style HD derivation at
  the provisioning layer. One-way: a child (or its leaked keys) cannot climb to
  the master or to siblings.

Properties and caveats:

- **Master = single point of compromise:** whoever holds the master can derive
  every child. Keep it offline; the "wipe the master after provisioning" workflow
  (master is a transient in-RAM scalar) removes the apex entirely once the batch
  is cut.
- **Master IKM transits host RAM** at provisioning time (Zeroized after) - same
  exposure class as `--exportable`, scoped to provisioning, never at leaf-derive.
- **Layered factor:** the master must derive both the child scalar and the child
  HMAC secret for a child to reproduce a full layered root.
- **Versus Shamir (above):** for *resilient backup* with no single apex, `t`-of-`n`
  is arguably stronger; the pyramid optimises for *bulk minting / regeneration*
  from one root, not threshold recovery. They are complementary.
- **All additive:** rides entirely on the existing KDF and provisioning
  primitives; does not touch the frozen v1 format.

**Recommended shape: a single level (flat clones).** Depth is a cost, not a
feature - every extra layer keeps master secret material in RAM longer and widens
the exposure window between shares. So default to one level (generate one root,
push it to N devices, wipe the in-RAM copy immediately). Go beyond one level only
behind a proper threshold scheme (the Shamir `t`-of-`n` design above), never via
naive deep HD derivation, which multiplies in-RAM secrets for no resilience gain.

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
- Keep secrets out of the process table (IMPLEMENTED): shipped as
  `--import-file`, `--hmac-secret-file`, and `--mgmt-key-file` (each accepts `-`
  for stdin and a `/dev/fd/N` path); the inline forms still work but warn.
