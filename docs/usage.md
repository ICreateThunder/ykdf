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

## WireGuard

WireGuard keys are Curve25519 in base64, which is the `x25519` profile. `ykdf wg`
derives that key and prints it the way WireGuard expects, so you never handle a
raw scalar or pipe keys between tools. Every subcommand takes the same derivation
flags as `ykdf derive` (`--purpose`, `--index`, `--pipeline`, `--layered`,
`--passphrase`, `--transport`) and an optional recipe name; the profile is fixed
to `x25519`, so there is no `--profile`.

```bash
# Private key (base64), for PrivateKey = in a config or `wg set`
ykdf wg key --purpose vpn-laptop

# Public key (base64), to hand to the other end
ykdf wg pubkey --purpose vpn-laptop

# A [Peer] stanza describing this device, to paste into the server's config
ykdf wg peer --purpose vpn-laptop --allowed-ips 10.0.0.2/32 --endpoint laptop.example:51820

# A full interface config, optionally with one peer
ykdf wg config --purpose vpn-laptop \
  --address 10.0.0.2/24 --dns 1.1.1.1 --listen-port 51820 \
  --peer-pubkey <server-pubkey> --endpoint vpn.example.com:51820 \
  --allowed-ips 0.0.0.0/0 --allowed-ips ::/0 --keepalive 25
```

`wg config` writes to stdout by default; `-o <path>` writes the file with mode
0600, since it holds the private key. `--address` is required, and the `[Peer]`
block appears only when `--peer-pubkey` is given (the other peer flags require
it). Repeatable flags (`--address`, `--dns`, `--allowed-ips`) are joined with
commas in the order given.

A recipe supplies the derivation parameters exactly as it does for `derive`, so
`ykdf wg config home --address 10.0.0.2/24` reuses the `home` recipe's purpose
and index. The recipe's profile must be `x25519`; naming an `ed25519` or
`age-x25519` recipe is refused rather than deriving a key WireGuard cannot use.

A recipe can also carry the network fields in a `[recipe.<name>.wg]` section, so
a whole config comes from one command:

```toml
[recipe.home]
profile = "x25519"
purpose = "wg-home"

[recipe.home.wg]
address     = ["10.0.0.2/24"]
listen-port = 51820
dns         = ["1.1.1.1"]

[[recipe.home.wg.peer]]        # repeat the block for more peers
public-key  = "<server-pubkey>"
endpoint    = "vpn.example.com:51820"
allowed-ips = ["0.0.0.0/0", "::/0"]
keepalive   = 25
```

`ykdf wg config home` then assembles the full config with no flags. Flags still
override: `--dns 9.9.9.9` swaps only the DNS, and `--peer-pubkey <k>
--allowed-ips <cidr>` replaces the recipe's peers with the one given.
`ykdf wg peer home` uses the recipe's `address` as its AllowedIPs. The section is
labels only (a PresharedKey is never stored), and `ykdf recipe show home` prints
the resolved fields before you derive.

## Signing and verifying

`ykdf sign` derives a signing key and signs a message with it. For `ed25519` the
output is an OpenSSH signature (SSHSIG), so anyone can check it with
`ssh-keygen -Y verify` and no YKDF installed:

```bash
ykdf pubkey --profile ed25519 --purpose release > signer.pub
ykdf sign --profile ed25519 --purpose release --in CHANGELOG.md --out CHANGELOG.md.sig
```

The message is read from stdin, or from `--in <path>`; the signature goes to
stdout, or to `--out <path>`. `--namespace` sets the SSHSIG domain (default
`file`) and the verifier must use the same value; `--hash sha512|sha256` selects
the message-hash algorithm (default `sha512`). A recipe supplies the derivation
parameters exactly as it does for `derive`, and the profile must be a signing
profile (`ed25519`).

`ykdf verify` checks a signature against a supplied public key. It derives
nothing and needs no YubiKey:

```bash
ykdf verify --public-key @signer.pub --signature CHANGELOG.md.sig --in CHANGELOG.md
```

`--public-key` takes an `ssh-ed25519 <base64>` line, or `@<path>` to read one
from a file. The same signature checks with stock OpenSSH:

```bash
printf 'signer@ykdf %s\n' "$(cat signer.pub)" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I signer@ykdf -n file \
  -s CHANGELOG.md.sig < CHANGELOG.md
```

Signing is deterministic: the same key and message always produce the same
signature.

The ML-DSA signing profiles (`mldsa44`/`mldsa65`/`mldsa87`) sign into a
`ykdf-sig:v1` container rather than an SSHSIG, because no ubiquitous ML-DSA
signature standard exists to target. The commands are identical, and the public
key is the base64 string `ykdf pubkey` prints:

```bash
ykdf pubkey --profile mldsa65 --purpose release > signer-mldsa.pub
ykdf sign --profile mldsa65 --purpose release --in CHANGELOG.md --out CHANGELOG.md.sig
ykdf verify --public-key @signer-mldsa.pub --signature CHANGELOG.md.sig --in CHANGELOG.md
```

ML-DSA signing always uses SHA-512, so `--hash` applies to ed25519 only. The
`ykdf-sig:v1` format is specified in [signatures.md](signatures.md).

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
