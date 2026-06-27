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
