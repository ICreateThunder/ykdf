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

## Recipes

A recipe is a named bundle of derivation parameters, so a routine key becomes
`ykdf derive wg-home` instead of a line of flags. Recipes live in a TOML file at
`$XDG_CONFIG_HOME/ykdf/config.toml` (or `$HOME/.config/ykdf/config.toml`); override
the path with `--config <path>` or the `YKDF_CONFIG` variable. The file holds
labels only, never a PIN, passphrase, or key, so it is safe to keep in a
dotfiles repository or sync between machines. It never changes what a derivation
produces: the same recipe and the same YubiKey always yield the same key.

```toml
# $HOME/.config/ykdf/config.toml

# Applied to every recipe unless the recipe overrides them.
[defaults]
index = 0

[recipe.wg-home]
profile     = "x25519"
description = "WireGuard home tunnel"

[recipe.git-signing]
profile  = "ed25519"
pipeline = "hkdf-sha3-512"
index    = 2

[recipe.backup]
profile = "age-x25519"
purpose = "backup-encryption"
```

Each recipe needs a `profile`; `purpose`, `pipeline`, `index`, `layered`, and
`description` are optional. An omitted `purpose` defaults to the recipe name, so
`[recipe.wg-home]` derives with purpose `wg-home`. Values resolve in the order
explicit flag, recipe field, `[defaults]`, then the profile's built-in default,
so a flag always wins.

```bash
# Derive using a recipe
ykdf derive wg-home

# Same run, but override the rotation index
ykdf derive wg-home --index 1

# Public key for a recipe
ykdf pubkey git-signing

# List the configured recipes
ykdf recipe list

# Show a recipe's fully resolved parameters before deriving
ykdf recipe show git-signing
```

An unknown field in the file is rejected, and each recipe is validated against
the same rules as the equivalent flags, so `ykdf recipe show` reports a bad
profile or purpose without touching the YubiKey.

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
