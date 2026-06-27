# YubiKey transport notes

Hardware-verified notes on which YubiKey interfaces expose the two factors YKDF
reads (PIV ECDH on slot 9d, HMAC-SHA1 challenge-response on OTP slot 2), and the
consequences for the desktop and Android transports. Verified on a YubiKey 5 NFC
(firmware 5.7.x).

## Interface matrix

| Factor | USB CCID (PC/SC) | USB HID | NFC (ISO-DEP) |
| --- | --- | --- | --- |
| PIV ECDH (slot 9d) | yes (via pcscd) | n/a | yes (APDU) |
| HMAC-CR (OTP slot 2) | **no** | yes (hidraw/libusb) | yes (APDU) |

The decisive result is the one "no": **HMAC challenge-response is not available
over the USB CCID interface.**

### Evidence (all on hardware, via pcscd / opensc-tool / ykman)

- `SELECT a0000005272001` (OTP applet) over USB CCID succeeds (`SW=9000`,
  returns the firmware/status bytes).
- The challenge-response command (`INS 0x01`, `P1=0x38` for slot 2) over USB
  CCID returns `SW=6D00` ("instruction not supported").
- `ykman` forced over the CCID reader (SmartCardConnection) fails:
  "The connection type required for this command is not supported/enabled".
- `ykman` over HID (hidraw) succeeds and returns the 20-byte HMAC.
- The same `INS 0x01` command works over **NFC ISO-DEP** (the Android handler and
  the KeePassDX "Key Driver" both rely on it).

So on USB the OTP applet is selectable over CCID but does not expose the
challenge-response command; that command lives only on the HID interface. Over
NFC there is no HID, and the applet exposes challenge-response via APDUs. Yubico's
"challenge-response is HID-only over USB" is correct; their "cannot be done over
NFC" statement does not apply to the OTP-applet APDU path.

## Consequence: "HMAC over CCID" (Scope B) is not possible on USB

The idea of moving the HMAC factor onto the CCID/PC-SC channel (like PIV) to drop
the libusb dependency does not work: the YubiKey will not answer challenge-response
on USB CCID. The desktop must use the HID interface for the HMAC factor on USB.

## The desktop HMAC fix: hidraw, not libusb

The current desktop path (`yubikey-hmac-otp` via `rusb`/libusb) detaches the
kernel `usbhid` driver to claim the OTP interface. On this system it hangs, and
because it is interrupted before releasing, it leaves the interface driverless
(no hidraw node) until the key is re-plugged. `ykman` reads the same factor over
**hidraw** (the kernel driver) with no detach and no hang.

Implemented: `ykdf-yubikey` now talks to the OTP HID over the Linux `hidraw`
interface with a small in-tree implementation of the OTP frame protocol (both
the challenge-response read and slot-2 programming), replacing `yubikey-hmac-otp`.
This:

- fixes the Linux hang and the driver-corruption-on-failure (no kernel-driver
  detach), and bounds the status polling so it errors instead of blocking,
- drops the `rusb` / `libusb1-sys` dependency, and
- is structured so the Windows native HID API and macOS can be added later
  behind the same interface (which would also clear the original libusb Windows
  blocker).

It still requires hidraw access permission (a udev / `uaccess` rule) for non-root
use, but the failure mode is now a clean error rather than a hang. Verified on
hardware: the hidraw read reproduces the same HMAC as `ykman`.

## One operation at a time: read HMAC before the PIV touch

The YubiKey serializes operations across all its interfaces (OTP-HID, FIDO-HID,
CCID) and supports only one connection at a time at the hardware level
(<https://developers.yubico.com/Mobile/Concepts.html>). In practice, right after
a **touch-triggered** PIV operation on CCID, the device is briefly (observed
~6 s) unavailable on the OTP-HID interface: a `--layered` derivation that read
HMAC immediately after the ECDH touch would time out on the HID read.

The fix is ordering, not waiting: `derive_ikm` reads the **HMAC factor (HID)
first**, then performs the touch-triggered ECDH (CCID) **last**, so no HID
operation ever follows the touch. The IKM is `ECDH || HMAC` regardless of read
order, so the output is unchanged. The HMAC read also keeps a short bounded retry
as a safety net. Verified on hardware: the desktop `--layered` output now matches
the Android NFC value byte-for-byte.

## gpg / scdaemon contention (CCID)

`gpg-agent`'s `scdaemon` claims the YubiKey CCID interface exclusively. While it
holds the card, PC/SC clients (opensc-tool, and YKDF's PIV path) get
"Reader in use by another application". `gpgconf --kill scdaemon` releases it
(scdaemon re-spawns on demand). Note this affects only the CCID/smartcard
interface, not the OTP HID interface.

Implemented: `yubikey::YubiKey::open()` silently skips a reader it cannot connect
to, so an exclusively-held card collapses into a misleading "no YubiKey found".
The open path now re-probes the readers on failure and, if one reports a PC/SC
sharing violation, surfaces a clear `SmartcardBusy` error naming the
`gpgconf --kill scdaemon` remedy instead of `DeviceNotFound`. The CLI runs this
check before prompting for the PIN, so a busy card fails fast.

Hardware finding (GnuPG 2.4.9, `disable-ccid` set so scdaemon uses pcscd):
scdaemon connects to the card in **exclusive** mode and holds it for the
**lifetime of the daemon**, not just during an operation. Verified: with
scdaemon merely running and idle (no `gpg --card-edit`, no active operation),
`ykdf` still gets `SCARD_E_SHARING_VIOLATION`. Consequences for the design:

- **No auto-retry.** scdaemon does not release the card on its own, so a bounded
  retry would only delay the actionable error. We removed that idea after testing.
- **`SCD RESET` is insufficient.** `gpg-connect-agent "SCD RESET" /bye` returns
  `OK` and resets the card but scdaemon keeps its PC/SC handle; `ykdf` stays
  blocked.
- **Killing is the only release over PC/SC.** `gpgconf --kill scdaemon` drops the
  handle; scdaemon re-spawns and re-grabs on the next gpg card operation, so it is
  a hand-off, not a permanent fix.

To coexist without the kill hand-off, `ykdf` can route its PIV APDUs **through**
gpg-agent's scdaemon via the Assuan `SCD APDU` passthrough (scdaemon runs
`--multi-server` for exactly this). scdaemon remains the sole card owner and
multiplexes, so gpg keeps working. This is implemented (`ykdf-yubikey::scd`,
selected by `--transport`/`YKDF_TRANSPORT`, default auto-detect) and reuses the
raw-APDU PIV sequence from the Android NFC transport.

Implementation notes (hardware-verified on the YK5 NFC):

- Only the **PIV/ECDH** factor goes through scdaemon (CCID). The HMAC factor is
  HID-only over USB, so layered mode still reads it over hidraw (a separate
  interface scdaemon does not hold), HMAC-first as in the direct path.
- scdaemon's `SCD APDU` passes APDUs raw: it does **not** auto-follow ISO-7816
  `61xx` response chaining, so the cert read issues GET RESPONSE itself.
- Assuan `D` lines are binary with only `%`/CR/LF escaped (read as bytes, not
  UTF-8). `SCD SERIALNO` reports on an `S` status line and returns `OK`/`ERR`;
  "does scdaemon hold the card?" checks `OK` vs `ERR`, not payload contents.
- Auto-detection routes to scdaemon only when it actually holds the card (probed
  via `SCD SERIALNO`), so a card locked by a *different* application (Yubico
  Authenticator, a PKCS#11 module, ...) yields the generic "smartcard busy" error
  rather than a misleading scdaemon failure. The trade-off of the passthrough is a
  dependency on gpg-agent, which is why it is opt-in / auto-fallback, not the
  default for non-gpg users.

## hidraw access (udev)

The OTP HID node (`/dev/hidraw*`, USB interface 0) is root-only by default, so
`--layered` needs `sudo` without a udev rule. `dist/udev/70-ykdf.rules` grants
the logged-in seat user access via systemd-logind `uaccess`, scoped to interface
0 (OTP) of any YubiKey (vendor 0x1050); interface 1 (FIDO) is left to Yubico's
own rules. The failure mode without it is a clean permission error, not a hang.

## Net architecture

- Desktop (USB): PIV over CCID (pcscd) and HMAC over HID (hidraw). Two
  interfaces, unavoidable, because the YubiKey does not offer challenge-response
  on CCID.
- Android (NFC): both factors over a single ISO-DEP APDU channel. NFC is the
  cleaner transport, and the Android path is unaffected by the libusb and pcscd
  issues above. This was verified end to end: the NFC-derived key matches the
  desktop CLI byte-for-byte (PIV ECDH path).
