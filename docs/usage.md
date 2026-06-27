# CLI usage

The `ykdf` command-line tool. Provision a YubiKey first (see
[provisioning.md](provisioning.md)), then derive keys on demand.

```bash
# Provision a YubiKey first (generate the slot 9d key on-device, write its cert)
ykdf init
# ...or also program HMAC-SHA1 on OTP slot 2 for layered mode
ykdf init --layered

# Derive a WireGuard private key (ephemeral - never hits disk)
ykdf derive --profile x25519 --purpose wg-home
# Enter PIV PIN, touch YubiKey → prints base64 private key

# Derive and configure WireGuard directly
wg set wg0 private-key <(ykdf derive --profile x25519 --purpose wg-home)

# Derive Ed25519 for SSH
ykdf derive --profile ed25519 --purpose ssh-github --format openssh

# Derive ML-KEM-768 keypair
ykdf derive --profile mlkem768 --purpose secure-email --format pem

# Derive a raw symmetric key
ykdf derive --profile symmetric --purpose backup-encryption

# Override the pipeline (any profile that accepts it)
ykdf derive --profile ed25519 --pipeline hkdf-sha3-512 --purpose git-signing

# Key rotation - bump index, re-share public key
ykdf derive --profile x25519 --purpose wg-home --index 1

# Layered mode (PIV + HMAC)
ykdf derive --profile ed25519 --purpose high-value --layered

# Add passphrase as additional factor
ykdf derive --profile ed25519 --purpose high-value --passphrase

# Show public key only
ykdf pubkey --profile x25519 --purpose wg-home
```

## Choosing the smartcard transport

On Linux, `--transport auto|pcsc|scdaemon` selects how the PIV factor reaches the
card (auto-detect by default; routes through `gpg-agent`'s scdaemon when it holds
the card, so `ykdf` coexists with gpg). `YKDF_TRANSPORT` is honoured as a fallback
when `--transport` is `auto`. See [provisioning.md](provisioning.md#gpg-coexistence)
and [transport-notes.md](transport-notes.md) for details.

## Profiles, pipelines, and output formats

The available `--profile` values, `--pipeline` options, and per-profile output
formats are described in [design.md](design.md#key-profiles). Run `ykdf --help`,
`ykdf derive --help`, etc. for the full, authoritative flag list.
