# Provisioning and setup

How to prepare a YubiKey for YKDF, grant the Linux permissions the transports
need, and set up two interchangeable backup keys.

## Linux permissions (PC/SC and hidraw)

The default (non-layered) PIV path talks to the YubiKey over PC/SC, so the
`pcscd` service must be installed and running (`systemctl enable --now pcscd`).
No special permissions are needed for it.

Layered mode additionally reads HMAC-SHA1 from OTP slot 2 over the kernel
`hidraw` interface, whose device node is root-only by default. Without access,
`--layered` fails with a clear "needs udev access or elevated privileges" error.
Install the bundled rule to grant the logged-in user access:

```bash
sudo install -m 0644 dist/udev/70-ykdf.rules /etc/udev/rules.d/70-ykdf.rules
sudo udevadm control --reload
# then REPLUG the YubiKey so the rule applies.
# Avoid a bare `udevadm trigger`: it re-enumerates every device and can disrupt
# other USB connections. To apply without replugging, scope it to the key:
#   sudo udevadm trigger --subsystem-match=hidraw --attr-match=idVendor=1050
```

The rule grants access via `uaccess` (systemd-logind / elogind), matched by the
Yubico USB vendor id. When packaged, it installs to `/usr/lib/udev/rules.d/`
automatically.

### gpg coexistence

If you use the YubiKey for GPG, `gpg-agent`'s `scdaemon` holds the smartcard
exclusively for the lifetime of the daemon. `ykdf` handles this automatically: it
detects the held card and routes its PIV APDUs *through* scdaemon (the Assuan
`SCD APDU` passthrough), so no kill is needed and gpg keeps working. Control this
with `--transport`:

```bash
ykdf derive ... --transport auto       # default: PC/SC, fall back to scdaemon if busy
ykdf derive ... --transport pcsc       # force direct PC/SC (e.g. gpgconf --kill scdaemon first)
ykdf derive ... --transport scdaemon   # force routing through gpg-agent
```

`YKDF_TRANSPORT=auto|pcsc|scdaemon` is honoured as a fallback when `--transport`
is left at `auto`. Layered mode still reads the HMAC factor over hidraw (a
separate interface scdaemon does not hold), so it needs the udev rule above. The
hardware-verified details are in [transport-notes.md](transport-notes.md).

## Single YubiKey (on-device generation)

```bash
# Provision slot 9d: generate the P-256 key on-device (private key never
# leaves the YubiKey) and write the carrier certificate the derive path reads.
ykdf init

# Or also program HMAC-SHA1 on OTP slot 2 for layered mode in one step:
ykdf init --layered
```

`ykdf init` refuses to overwrite an already-provisioned slot 9d unless given
`--force`. On-device generation is non-extractable, so the slot 9d key cannot be
backed up; if the device is lost, keys derived from the PIV factor are
unrecoverable. Back up the derived outputs you rely on, or use the two-YubiKey
backup setup below.

If you have changed the PIV management key from the factory default, tell
`ykdf init` how to authenticate. For a key stored on the device and unlocked by
your PIN (`ykman piv info` shows *"Management key is stored on the YubiKey,
protected by PIN"*), use `--mgmt-key protected` (or `--mgmt-key derived` for a
PIN-derived key); for an explicit key, pass it as `--mgmt-key <48-hex>`. Note the
`yubikey` 0.8 backend only supports TDES management keys, not the AES-192 default
on firmware 5.7+.

```bash
ykdf init --mgmt-key protected            # PIN-protected management key
ykdf init --exportable --mgmt-key protected
```

The equivalent manual steps with `ykman`:

```bash
# Generate P-256 key on-device (private key never leaves the YubiKey)
ykman piv keys generate --algorithm ECCP256 --touch-policy ALWAYS 9d /tmp/ykdf-pub.pem

# Create a self-signed certificate from the public key
ykman piv certificates generate --subject "CN=ykdf" 9d /tmp/ykdf-pub.pem

# Clean up (public key is now stored in the certificate on the YubiKey)
rm /tmp/ykdf-pub.pem
```

## Backup (two YubiKeys with identical secrets)

To use two YubiKeys as interchangeable backups, the same key must live on both.
On-device generation cannot be backed up (the key is non-extractable), so
generate the key on the host and import it into each device.

```bash
# Device 1: generate an EXPORTABLE key and program HMAC slot 2. The slot 9d
# private key (and the generated HMAC secret) are printed once to stderr.
ykdf init --exportable --layered
# -> "slot 9d private key (hex): <SCALAR>"
# -> "Generated HMAC secret ...: <HMAC>"

# Device 2 (swap YubiKeys): import the SAME key and HMAC secret.
ykdf init --import <SCALAR> --layered --hmac-secret <HMAC>
```

Both YubiKeys now produce identical derivations. Save `<SCALAR>` securely: it is
the only copy of the private key and cannot be recovered from the device.

Equivalent manual steps with `ykman` / `openssl`:

```bash
# Generate and import P-256 key to both YubiKeys (PIV slot 9d)
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/piv.pem
openssl req -new -x509 -key /tmp/piv.pem -out /tmp/piv-cert.pem \
  -days 36500 -subj "/CN=ykdf"

ykman -d <serial_1> piv keys import --touch-policy always 9d /tmp/piv.pem
ykman -d <serial_1> piv certificates import 9d /tmp/piv-cert.pem
ykman -d <serial_2> piv keys import --touch-policy always 9d /tmp/piv.pem
ykman -d <serial_2> piv certificates import 9d /tmp/piv-cert.pem

# Program identical HMAC secret to both (OTP slot 2, for --layered mode)
HMAC_SECRET=$(openssl rand -hex 20)
ykman -d <serial_1> otp chalresp --touch 2 "$HMAC_SECRET"
ykman -d <serial_2> otp chalresp --touch 2 "$HMAC_SECRET"

# Destroy originals
shred -u /tmp/piv.pem /tmp/piv-cert.pem
unset HMAC_SECRET
```

After setup, both YubiKeys produce identical derivations. Lose one, the other is
a full backup.
