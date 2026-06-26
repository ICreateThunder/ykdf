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

Recommended direction: replace the `rusb`/libusb HMAC path with a hidraw /
`hidapi` implementation. This:

- fixes the Linux hang and the driver-corruption-on-failure,
- is cross-platform (`hidapi` covers Linux hidraw, the Windows native HID API,
  and macOS), which also removes the original libusb Windows blocker, and
- drops the `rusb` / `libusb1-sys` dependency.

It still requires hidraw access permission (a udev / `uaccess` rule) for non-root
use, but the failure mode becomes a clean error rather than a hang.

## gpg / scdaemon contention (CCID)

`gpg-agent`'s `scdaemon` claims the YubiKey CCID interface exclusively. While it
holds the card, PC/SC clients (opensc-tool, and YKDF's PIV path) get
"Reader in use by another application". `gpgconf --kill scdaemon` releases it
(scdaemon re-spawns on demand). The PIV path should surface this as a clear
"smartcard busy" error and optionally retry, rather than failing opaquely. Note
this affects only the CCID/smartcard interface, not the OTP HID interface.

## Net architecture

- Desktop (USB): PIV over CCID (pcscd) and HMAC over HID (hidraw). Two
  interfaces, unavoidable, because the YubiKey does not offer challenge-response
  on CCID.
- Android (NFC): both factors over a single ISO-DEP APDU channel. NFC is the
  cleaner transport, and the Android path is unaffected by the libusb and pcscd
  issues above. This was verified end to end: the NFC-derived key matches the
  desktop CLI byte-for-byte (PIV ECDH path).
