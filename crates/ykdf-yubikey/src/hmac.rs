//! HMAC-SHA1 challenge-response on `YubiKey` OTP slot 2.
//!
//! Reads over the Linux `hidraw` interface (the kernel HID driver) using the
//! `YubiKey` OTP frame protocol. This needs no libusb and does not detach the
//! kernel driver, so it neither hangs nor leaves the OTP interface in a broken
//! state (unlike a raw-USB claim). Challenge-response is not exposed over the
//! `YubiKey` CCID interface, so the HID path is the only option on USB; see
//! `docs/transport-notes.md`. Other platforms are not yet implemented.

use zeroize::Zeroizing;

// Only the non-Linux stubs reference Error at this level; the Linux module
// imports it itself.
#[cfg(not(target_os = "linux"))]
use crate::error::Error;

/// Fixed challenge for HMAC-SHA1. Domain separation happens in the expand phase
/// via the context string, so the HMAC output is the same regardless of which
/// key is being derived.
const CHALLENGE: &[u8] = b"ykdf-v1";

/// CRC-16 residual that a correct `data || crc_le` produces. Used to validate
/// the response frame.
const CRC_OK_RESIDUAL: u16 = 0xf0b8;

/// CRC-16 used by the `YubiKey` OTP frame protocol (reflected, poly 0x8408,
/// preset 0xFFFF, no final xor).
fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            let lsb = crc & 1;
            crc >>= 1;
            if lsb != 0 {
                crc ^= 0x8408;
            }
        }
    }
    crc
}

/// Perform HMAC-SHA1 challenge-response on OTP slot 2.
///
/// Returns the 20-byte HMAC response.
///
/// # Errors
///
/// Returns `Error::HmacFailed` if the OTP HID device cannot be found or opened
/// (for example missing udev permissions), if the exchange times out, or if the
/// response CRC is wrong. It returns promptly on failure rather than blocking.
#[cfg(target_os = "linux")]
pub fn challenge_response() -> crate::Result<Zeroizing<Vec<u8>>> {
    linux::challenge_response(CHALLENGE)
}

/// HMAC over HID is currently implemented only on Linux (`hidraw`).
///
/// # Errors
///
/// Always returns `Error::HmacFailed` on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn challenge_response() -> crate::Result<Zeroizing<Vec<u8>>> {
    Err(Error::HmacFailed {
        detail: "HMAC over HID is only implemented on Linux so far".to_owned(),
    })
}

/// Program a 20-byte HMAC-SHA1 secret onto OTP slot 2 for challenge-response.
///
/// Overwrites any existing slot 2 configuration. `require_touch` sets the
/// button-press policy.
///
/// # Errors
///
/// Returns `Error::HmacProgramFailed` if the OTP HID device cannot be found or
/// opened, or the write fails.
#[cfg(target_os = "linux")]
pub fn program_slot2_hmac(secret: &[u8; 20], require_touch: bool) -> crate::Result<()> {
    linux::program_slot2_hmac(secret, require_touch)
}

/// Programming the HMAC slot over HID is currently implemented only on Linux.
///
/// # Errors
///
/// Always returns `Error::HmacProgramFailed` on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn program_slot2_hmac(_secret: &[u8; 20], _require_touch: bool) -> crate::Result<()> {
    Err(Error::HmacProgramFailed {
        detail: "programming the HMAC slot over HID is only implemented on Linux so far".to_owned(),
    })
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{self, OpenOptions};
    use std::io;
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{Duration, Instant};

    use zeroize::{Zeroize, Zeroizing};

    use super::{CRC_OK_RESIDUAL, crc16};
    use crate::error::Error;

    const SLOT2_HMAC: u8 = 0x38;
    const SLOT_WRITE_FLAG: u8 = 0x80;
    const RESP_PENDING_FLAG: u8 = 0x40;
    const PAYLOAD_SIZE: usize = 64;
    const FRAME_SIZE: usize = 70;
    const RESPONSE_SIZE: usize = 36;
    const HMAC_LEN: usize = 20;
    /// Each feature report carries 7 payload bytes + 1 status byte.
    const REPORT_DATA: usize = 7;
    /// Bound the status polling so a misconfigured slot errors instead of hanging.
    const WAIT_LIMIT: usize = 2000;

    // hidraw ioctl request numbers for a 9-byte buffer (1 report-id byte + the
    // 8-byte report). _IOC(dir, type, nr, size); dir 3 = READ|WRITE, type 'H'.
    const HID_BUF_LEN: u64 = 9;
    const fn ioc(dir: u64, ty: u64, nr: u64, size: u64) -> libc::c_ulong {
        ((dir << 30) | (size << 16) | (ty << 8) | nr) as libc::c_ulong
    }
    const HIDIOCSFEATURE: libc::c_ulong = ioc(3, 0x48, 0x06, HID_BUF_LEN);
    const HIDIOCGFEATURE: libc::c_ulong = ioc(3, 0x48, 0x07, HID_BUF_LEN);

    /// Total time to keep retrying the exchange before giving up.
    const RETRY_BUDGET: Duration = Duration::from_secs(8);
    /// Pause between retries.
    const RETRY_PAUSE: Duration = Duration::from_millis(250);

    pub fn challenge_response(challenge: &[u8]) -> crate::Result<Zeroizing<Vec<u8>>> {
        // Right after a touch-triggered PIV operation on the CCID interface, the
        // OTP HID can be briefly unresponsive (a post-touch cooldown on the
        // device). Retry the whole exchange for a few seconds so we ride that
        // out instead of erroring, while still bounding the total time.
        let deadline = Instant::now() + RETRY_BUDGET;
        loop {
            match one_challenge_response(challenge) {
                Ok(hmac) => return Ok(hmac),
                Err(e) => {
                    if Instant::now() >= deadline {
                        return Err(e);
                    }
                    thread::sleep(RETRY_PAUSE);
                }
            }
        }
    }

    fn one_challenge_response(challenge: &[u8]) -> crate::Result<Zeroizing<Vec<u8>>> {
        let path = find_otp_hidraw()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| Error::HmacFailed {
                detail: format!(
                    "cannot open {} ({e}); the OTP HID interface needs udev access or elevated privileges",
                    path.display()
                ),
            })?;
        let fd = file.as_raw_fd();

        wait_flags(fd, |f| f & SLOT_WRITE_FLAG == 0)?;
        let frame = build_frame(challenge, SLOT2_HMAC);
        write_frame(fd, &frame)?;

        // Zeroized on drop: this buffer holds the 20-byte HMAC, which is secret
        // IKM material.
        let mut response = Zeroizing::new([0u8; RESPONSE_SIZE]);
        read_response(fd, &mut response)?;

        // The response is the 20-byte HMAC followed by its 2-byte CRC.
        if crc16(&response[..HMAC_LEN + 2]) != CRC_OK_RESIDUAL {
            return Err(Error::HmacFailed {
                detail: "response CRC mismatch (is OTP slot 2 a HMAC-SHA1 slot?)".to_owned(),
            });
        }
        Ok(Zeroizing::new(response[..HMAC_LEN].to_vec()))
    }

    const SLOT2_CONFIG: u8 = 0x03; // Command::Configuration2
    const CONFIG_STRUCT_SIZE: usize = 52;
    const TKT_CHAL_RESP: u8 = 0x40;
    const CFG_CHAL_HMAC: u8 = 0x22;
    const CFG_CHAL_BTN_TRIG: u8 = 0x08;

    /// Program a 20-byte HMAC-SHA1 secret onto OTP slot 2 for challenge-response
    /// (fixed 64-byte input mode), overwriting any existing slot 2 config.
    pub fn program_slot2_hmac(secret: &[u8; 20], require_touch: bool) -> crate::Result<()> {
        let path = find_otp_hidraw().map_err(reflag_program)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| Error::HmacProgramFailed {
                detail: format!(
                    "cannot open {} ({e}); the OTP HID interface needs udev access or elevated privileges",
                    path.display()
                ),
            })?;
        let fd = file.as_raw_fd();

        wait_flags(fd, |f| f & SLOT_WRITE_FLAG == 0).map_err(reflag_program)?;
        let payload = build_hmac_config_payload(secret, require_touch);
        // Zeroized on drop: the frame embeds the 64-byte config payload, which
        // contains the raw HMAC secret being programmed.
        let frame = Zeroizing::new(frame_from_payload(&payload, SLOT2_CONFIG));
        write_frame(fd, &frame).map_err(reflag_program)?;
        wait_flags(fd, |f| f & SLOT_WRITE_FLAG == 0).map_err(reflag_program)?;
        Ok(())
    }

    /// Build the 64-byte slot configuration payload for HMAC-SHA1
    /// challenge-response. The packed layout is
    /// `fixed[16] uid[6] key[16] acc_code[6] fixed_size ext_flags tkt_flags cfg_flags rfu[2] crc[2]`.
    /// The 20-byte HMAC key fills `key` plus the first 4 bytes of `uid`.
    fn build_hmac_config_payload(
        secret: &[u8; 20],
        require_touch: bool,
    ) -> Zeroizing<[u8; PAYLOAD_SIZE]> {
        // Both buffers embed the raw HMAC secret, so they are zeroized on drop.
        let mut cfg = Zeroizing::new([0u8; CONFIG_STRUCT_SIZE]);
        cfg[16..20].copy_from_slice(&secret[16..20]); // uid[0..4] = key tail
        cfg[22..38].copy_from_slice(&secret[0..16]); // key = key head
        cfg[46] = TKT_CHAL_RESP;
        cfg[47] = if require_touch {
            CFG_CHAL_HMAC | CFG_CHAL_BTN_TRIG
        } else {
            CFG_CHAL_HMAC
        };
        // Config CRC is the one's-complement of the CRC over the first 50 bytes,
        // stored little-endian, so crc16 over the full struct yields the residual.
        let crc = 0xffffu16.wrapping_sub(crc16(&cfg[..CONFIG_STRUCT_SIZE - 2]));
        cfg[50] = (crc & 0xff) as u8;
        cfg[51] = (crc >> 8) as u8;

        let mut payload = Zeroizing::new([0u8; PAYLOAD_SIZE]);
        payload[..CONFIG_STRUCT_SIZE].copy_from_slice(&cfg[..]);
        payload
    }

    /// Re-tag a read-path error as a programming error.
    fn reflag_program(e: Error) -> Error {
        match e {
            Error::HmacFailed { detail } => Error::HmacProgramFailed { detail },
            other => other,
        }
    }

    /// Build the 70-byte command frame from a challenge: a 64-byte payload, the
    /// slot command, the frame CRC, and filler.
    fn build_frame(challenge: &[u8], command: u8) -> [u8; FRAME_SIZE] {
        // Variable-length challenges are zero-padded; the firmware strips
        // trailing zeros. If the challenge itself ends in a zero, pad with 0xff
        // instead so the boundary is preserved (mirrors the reference driver).
        let mut payload = if challenge.last() == Some(&0) {
            [0xffu8; PAYLOAD_SIZE]
        } else {
            [0u8; PAYLOAD_SIZE]
        };
        payload[..challenge.len()].copy_from_slice(challenge);
        frame_from_payload(&payload, command)
    }

    /// Wrap a 64-byte payload into the 70-byte command frame (payload, command,
    /// frame CRC over the payload, filler).
    fn frame_from_payload(payload: &[u8; PAYLOAD_SIZE], command: u8) -> [u8; FRAME_SIZE] {
        let crc = crc16(payload);
        let mut frame = [0u8; FRAME_SIZE];
        frame[..PAYLOAD_SIZE].copy_from_slice(payload);
        frame[PAYLOAD_SIZE] = command;
        frame[PAYLOAD_SIZE + 1] = (crc & 0xff) as u8;
        frame[PAYLOAD_SIZE + 2] = (crc >> 8) as u8;
        frame
    }

    /// Send the frame as a sequence of 7-byte feature reports. An all-zero
    /// chunk is skipped unless it is the first or last, matching the device's
    /// expectations.
    fn write_frame(fd: i32, frame: &[u8; FRAME_SIZE]) -> crate::Result<()> {
        let mut seq: u8 = 0;
        let mut offset = 0;
        while offset < FRAME_SIZE {
            let chunk = &frame[offset..offset + REPORT_DATA];
            let is_last = offset + REPORT_DATA >= FRAME_SIZE;
            if seq == 0 || is_last || chunk.iter().any(|&b| b != 0) {
                let mut packet = [0u8; 8];
                packet[..REPORT_DATA].copy_from_slice(chunk);
                packet[7] = SLOT_WRITE_FLAG | seq;
                wait_flags(fd, |f| f & SLOT_WRITE_FLAG == 0)?;
                set_feature(fd, &packet)?;
                // On the config-write path these report bytes are secret.
                packet.zeroize();
            }
            offset += REPORT_DATA;
            seq += 1;
        }
        Ok(())
    }

    /// Read the response in 7-byte chunks until the sequence wraps.
    fn read_response(fd: i32, response: &mut [u8; RESPONSE_SIZE]) -> crate::Result<usize> {
        let first = wait_flags(fd, |f| f & RESP_PENDING_FLAG != 0)?;
        response[..8].copy_from_slice(&first);
        let mut filled = REPORT_DATA;
        loop {
            if filled + 8 > RESPONSE_SIZE {
                break;
            }
            let chunk = get_feature(fd)?;
            response[filled..filled + 8].copy_from_slice(&chunk);
            let flags = chunk[7];
            if flags & RESP_PENDING_FLAG == 0 {
                break;
            }
            let seq = flags & 0x1f;
            if filled > 0 && seq == 0 {
                break;
            }
            filled += REPORT_DATA;
        }
        write_reset(fd)?;
        Ok(filled)
    }

    /// Tell the device we are done reading and reset its write state.
    fn write_reset(fd: i32) -> crate::Result<()> {
        set_feature(fd, &[0, 0, 0, 0, 0, 0, 0, 0x8f])?;
        wait_flags(fd, |f| f & SLOT_WRITE_FLAG == 0)?;
        Ok(())
    }

    /// Poll the status (feature report byte 7) until `want` is satisfied.
    fn wait_flags<F: Fn(u8) -> bool>(fd: i32, want: F) -> crate::Result<[u8; 8]> {
        for _ in 0..WAIT_LIMIT {
            let buf = get_feature(fd)?;
            if want(buf[7]) {
                return Ok(buf);
            }
            thread::sleep(Duration::from_millis(1));
        }
        Err(Error::HmacFailed {
            detail: "timed out waiting for the YubiKey OTP slot (is slot 2 configured?)".to_owned(),
        })
    }

    #[allow(unsafe_code)] // the hidraw ioctl is the one FFI call this crate needs
    fn set_feature(fd: i32, report: &[u8; 8]) -> crate::Result<()> {
        let mut buf = [0u8; 9]; // buf[0] = report number 0
        buf[1..9].copy_from_slice(report);
        // SAFETY: `fd` is a valid open hidraw descriptor (the caller holds the
        // backing `File` alive for the call). `buf` is a live, aligned `[u8; 9]`
        // on the stack. HIDIOCSFEATURE encodes size = HID_BUF_LEN (9), matching
        // the buffer, so the kernel reads exactly these 9 bytes and no further.
        let rc = unsafe { libc::ioctl(fd, HIDIOCSFEATURE, buf.as_mut_ptr()) };
        if rc < 0 {
            return Err(Error::HmacFailed {
                detail: format!("SET_FEATURE failed: {}", io::Error::last_os_error()),
            });
        }
        Ok(())
    }

    #[allow(unsafe_code)] // the hidraw ioctl is the one FFI call this crate needs
    fn get_feature(fd: i32) -> crate::Result<[u8; 8]> {
        let mut buf = [0u8; 9]; // buf[0] = report number 0
        // SAFETY: `fd` is a valid open hidraw descriptor (the caller holds the
        // backing `File` alive for the call). `buf` is a live, aligned `[u8; 9]`
        // on the stack. HIDIOCGFEATURE encodes size = HID_BUF_LEN (9), matching
        // the buffer, so the kernel writes exactly these 9 bytes and no further.
        let rc = unsafe { libc::ioctl(fd, HIDIOCGFEATURE, buf.as_mut_ptr()) };
        if rc < 0 {
            return Err(Error::HmacFailed {
                detail: format!("GET_FEATURE failed: {}", io::Error::last_os_error()),
            });
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(&buf[1..9]);
        Ok(out)
    }

    /// Find the `/dev/hidraw*` node for the `YubiKey` OTP interface (USB vendor
    /// 0x1050, USB interface 0). Interface 1 is FIDO and is skipped.
    fn find_otp_hidraw() -> crate::Result<PathBuf> {
        let entries = fs::read_dir("/sys/class/hidraw").map_err(|e| Error::HmacFailed {
            detail: format!("cannot enumerate hidraw devices: {e}"),
        })?;
        for entry in entries.flatten() {
            let sysdev = entry.path().join("device");
            let Ok(uevent) = fs::read_to_string(sysdev.join("uevent")) else {
                continue;
            };
            let is_yubico = uevent
                .lines()
                .any(|l| l.starts_with("HID_ID=") && l.to_uppercase().contains(":00001050:"));
            if !is_yubico {
                continue;
            }
            // The OTP interface is USB interface 0; its canonical sysfs path
            // contains the ":1.0/" interface component (FIDO is ":1.1/").
            let Ok(real) = fs::canonicalize(&sysdev) else {
                continue;
            };
            if real.to_string_lossy().contains(":1.0/") {
                return Ok(PathBuf::from("/dev").join(entry.file_name()));
            }
        }
        Err(Error::HmacFailed {
            detail: "no YubiKey OTP HID interface found (vendor 0x1050, interface 0)".to_owned(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::{
            CFG_CHAL_BTN_TRIG, CFG_CHAL_HMAC, CONFIG_STRUCT_SIZE, CRC_OK_RESIDUAL, TKT_CHAL_RESP,
            build_hmac_config_payload, crc16,
        };

        /// The 20-byte HMAC key lands in key[16] + uid[0..4], the flags are set
        /// for fixed-input HMAC-SHA1 challenge-response, and the internal config
        /// CRC produces the residual the firmware checks. Validates the write
        /// path's byte layout without touching hardware.
        #[test]
        fn hmac_config_payload_layout() {
            let secret: [u8; 20] = core::array::from_fn(|i| u8::try_from(i + 1).unwrap());
            let p = build_hmac_config_payload(&secret, false);
            assert_eq!(&p[22..38], &secret[0..16], "key head");
            assert_eq!(&p[16..20], &secret[16..20], "key tail in uid");
            assert_eq!(p[46], TKT_CHAL_RESP, "ticket flags");
            assert_eq!(p[47], CFG_CHAL_HMAC, "config flags");
            assert_eq!(
                crc16(&p[..CONFIG_STRUCT_SIZE]),
                CRC_OK_RESIDUAL,
                "config crc"
            );
        }

        #[test]
        fn touch_sets_button_trigger() {
            let p = build_hmac_config_payload(&[0u8; 20], true);
            assert_eq!(p[47], CFG_CHAL_HMAC | CFG_CHAL_BTN_TRIG);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CHALLENGE, CRC_OK_RESIDUAL, crc16};

    /// Frozen v1 invariant: the HMAC-SHA1 challenge is fixed. Changing it
    /// re-namespaces every layered-mode derivation, so it is part of the v1
    /// format. The golden vectors run over `--ikm-file` and never touch this
    /// hardware path, so this is the only guard against a silent change.
    #[test]
    fn challenge_is_frozen() {
        assert_eq!(CHALLENGE, b"ykdf-v1");
    }

    /// The CRC-16 residual property the protocol relies on: the stored CRC is
    /// the one's-complement of the CRC over the data, so running `crc16` over
    /// the data followed by that stored CRC yields the fixed residual. This is
    /// how both the slot config and the device's response frame are checked.
    #[test]
    fn crc16_residual_holds() {
        let data = b"ykdf challenge-response crc check";
        let stored = 0xffffu16.wrapping_sub(crc16(data));
        let mut framed = data.to_vec();
        framed.push((stored & 0xff) as u8);
        framed.push((stored >> 8) as u8);
        assert_eq!(crc16(&framed), CRC_OK_RESIDUAL);
    }
}
