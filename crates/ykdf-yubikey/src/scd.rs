//! Alternative desktop PIV/OTP transport: route APDUs THROUGH gpg-agent's
//! scdaemon via the Assuan `SCD APDU` passthrough, instead of opening PC/SC
//! directly.
//!
//! scdaemon connects to the `YubiKey` smartcard in exclusive mode and holds it for
//! the lifetime of the daemon, so a user who relies on gpg cannot use the direct
//! PC/SC path without killing scdaemon. Sending the PIV and OTP APDUs through
//! scdaemon lets `ykdf` coexist: scdaemon stays the sole card owner and
//! multiplexes. This path is opt-in; the direct PC/SC path remains the default
//! for users without gpg.
//!
//! The APDU sequence mirrors the Android NFC handler (which is byte-identical to
//! the desktop PC/SC path): SELECT PIV, GET DATA slot-9d cert, VERIFY PIN,
//! GENERAL AUTHENTICATE (self-ECDH); plus, for layered mode, SELECT OTP and the
//! HMAC-SHA1 challenge on slot 2.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::Command;

use x509_cert::der::Decode;
use zeroize::Zeroizing;

use crate::IkmMode;
use crate::error::Error;

/// Standard PIV applet AID.
const AID_PIV: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

const INS_VERIFY: u8 = 0x20;
const INS_GET_DATA: u8 = 0xCB;
const INS_GENERAL_AUTHENTICATE: u8 = 0x87;
const INS_SELECT: u8 = 0xA4;
const ALG_ECC_P256: u8 = 0x11;
const SLOT_9D: u8 = 0x9D;

const ECDH_SECRET_LEN: usize = 32;
const HMAC_RESPONSE_LEN: usize = 20;
const POINT_LEN: usize = 65;

/// Derive IKM by driving the `YubiKey` through gpg-agent's scdaemon.
///
/// Only the PIV/ECDH factor goes through scdaemon (the CCID/smartcard channel).
/// The HMAC factor is HID-only over USB - the OTP applet does not expose
/// challenge-response over CCID - so layered mode reads HMAC over hidraw, which
/// is a separate interface scdaemon does not hold. As in the direct path, HMAC
/// is read first, before the touch-triggered ECDH.
///
/// # Errors
///
/// Returns [`Error::Scd`] if the agent/scdaemon cannot be reached or an APDU
/// fails, [`Error::WrongPin`]/[`Error::PinLocked`] on PIN failure, or the
/// PIV/HMAC error variants on a malformed response.
pub(crate) fn derive_ikm(mode: IkmMode, pin: &[u8]) -> crate::Result<ykdf_core::Ikm> {
    // HMAC over hidraw (HID) first: the HID interface is free even while
    // scdaemon holds the smartcard, and reading it before the ECDH touch avoids
    // the post-touch HID stall (see hmac.rs / docs/transport-notes.md).
    let hmac = if mode == IkmMode::Layered {
        Some(crate::hmac::challenge_response()?)
    } else {
        None
    };

    let mut conn = Assuan::connect()?;
    conn.serialno()?; // ensure scdaemon has the card open before raw APDUs
    conn.select(AID_PIV)?;
    let point = conn.read_slot9d_point()?;
    conn.verify_pin(pin)?;
    eprintln!("Touch your YubiKey...");
    let ecdh = conn.ecdh(&point)?;

    // IKM = ECDH || HMAC, mirroring the direct path's zeroizing assembly.
    let mut ikm = Zeroizing::new(Vec::with_capacity(ECDH_SECRET_LEN + HMAC_RESPONSE_LEN));
    ikm.extend_from_slice(&ecdh);
    if let Some(hmac) = hmac {
        ikm.extend_from_slice(&hmac);
    }
    let inner = std::mem::take(&mut *ikm);
    ykdf_core::Ikm::new(inner).map_err(|e| Error::EcdhFailed {
        detail: e.to_string(),
    })
}

/// Best-effort check: does scdaemon currently hold a card we can reach?
///
/// Used by transport auto-selection to avoid misattributing a busy smartcard to
/// scdaemon: only when scdaemon answers `SCD SERIALNO` (i.e. it holds the card)
/// do we route through it. If gpg is absent, the agent is down, or another
/// application holds the card, this returns `false` and the caller surfaces the
/// generic "smartcard busy" error instead.
pub(crate) fn scdaemon_holds_card() -> bool {
    // `SCD SERIALNO` reports the serial on an Assuan `S` status line and returns
    // `OK` when scdaemon can reach a card, or `ERR` when it cannot (no card, or
    // the card is held by another application). Success is the signal, not the
    // (status-line) data, so check for Ok, not a non-empty payload.
    Assuan::connect()
        .and_then(|mut conn| conn.serialno())
        .is_ok()
}

/// A minimal Assuan client connection to gpg-agent, used to send `SCD` commands.
struct Assuan {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Assuan {
    /// Connect to the running gpg-agent and consume its greeting.
    fn connect() -> crate::Result<Self> {
        let path = agent_socket_path()?;
        let writer = UnixStream::connect(&path)
            .map_err(|e| Error::Scd(format!("cannot connect to gpg-agent at {path}: {e}")))?;
        let reader = BufReader::new(
            writer
                .try_clone()
                .map_err(|e| Error::Scd(format!("cannot clone agent socket: {e}")))?,
        );
        let mut conn = Self { reader, writer };
        let greeting = conn.read_line()?;
        if !greeting.starts_with(b"OK") {
            return Err(Error::Scd(format!(
                "unexpected agent greeting: {}",
                String::from_utf8_lossy(&greeting)
            )));
        }
        Ok(conn)
    }

    /// Ask scdaemon for the card serial, opening the card if needed. Returns the
    /// raw serial bytes; an error means scdaemon could not reach a card (no card,
    /// or held by a non-scdaemon application).
    fn serialno(&mut self) -> crate::Result<Vec<u8>> {
        self.command("SCD SERIALNO")
    }

    /// Send one Assuan command and collect any `D` data until `OK`/`ERR`.
    ///
    /// Lines are read as raw bytes: Assuan only escapes `%`, CR, and LF in `D`
    /// data, so a response (e.g. a certificate) is otherwise arbitrary binary and
    /// is not valid UTF-8.
    fn command(&mut self, line: &str) -> crate::Result<Vec<u8>> {
        self.writer
            .write_all(line.as_bytes())
            .and_then(|()| self.writer.write_all(b"\n"))
            .map_err(|e| Error::Scd(format!("write failed: {e}")))?;
        let mut data = Vec::new();
        loop {
            let line = self.read_line()?;
            if let Some(rest) = line.strip_prefix(b"D ") {
                decode_percent(rest, &mut data);
            } else if line == b"OK" || line.starts_with(b"OK ") {
                return Ok(data);
            } else if let Some(err) = line.strip_prefix(b"ERR ") {
                return Err(Error::Scd(format!(
                    "agent error: {}",
                    String::from_utf8_lossy(err)
                )));
            }
            // Status (`S `), comment (`#`), and inquiry lines are ignored.
        }
    }

    /// Read one line (raw bytes) from the agent, stripped of its trailing CR/LF.
    fn read_line(&mut self) -> crate::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let n = self
            .reader
            .read_until(b'\n', &mut buf)
            .map_err(|e| Error::Scd(format!("read failed: {e}")))?;
        if n == 0 {
            return Err(Error::Scd("gpg-agent closed the connection".to_owned()));
        }
        while matches!(buf.last(), Some(b'\n' | b'\r')) {
            buf.pop();
        }
        Ok(buf)
    }

    /// Send an APDU and return the full response (data + 2-byte SW), handling
    /// ISO-7816 response chaining.
    ///
    /// scdaemon passes APDUs through raw, so a `61 xx` status ("xx more bytes
    /// available") is not auto-followed the way a PC/SC reader would: we issue
    /// GET RESPONSE ourselves and concatenate until a non-`61` status, mirroring
    /// the Android NFC handler.
    fn apdu(&mut self, apdu: &[u8]) -> crate::Result<Vec<u8>> {
        let mut resp = self.send_apdu(apdu)?;
        while resp.len() >= 2 && resp[resp.len() - 2] == 0x61 {
            let le = resp[resp.len() - 1];
            resp.truncate(resp.len() - 2); // drop the 61 xx status
            let more = self.send_apdu(&[0x00, 0xC0, 0x00, 0x00, le])?; // GET RESPONSE
            resp.extend_from_slice(&more);
        }
        Ok(resp)
    }

    /// Send one raw APDU via `SCD APDU` and return its response (data + SW).
    fn send_apdu(&mut self, apdu: &[u8]) -> crate::Result<Vec<u8>> {
        let mut hexs = String::with_capacity(apdu.len() * 2 + 9);
        hexs.push_str("SCD APDU ");
        for b in apdu {
            let _ = write!(hexs, "{b:02X}");
        }
        self.command(&hexs)
    }

    /// Send `apdu` and require a `9000` status word, returning the response data.
    fn apdu_ok(&mut self, apdu: &[u8], what: &str) -> crate::Result<Vec<u8>> {
        let resp = self.apdu(apdu)?;
        let (data, sw) = split_sw(&resp, what)?;
        classify_sw(sw, what)?;
        Ok(data.to_vec())
    }

    fn select(&mut self, aid: &[u8]) -> crate::Result<()> {
        let mut apdu = vec![
            0x00,
            INS_SELECT,
            0x04,
            0x00,
            u8::try_from(aid.len()).unwrap(),
        ];
        apdu.extend_from_slice(aid);
        self.apdu_ok(&apdu, "SELECT")?;
        Ok(())
    }

    /// Read the slot-9d certificate and return its 65-byte uncompressed point.
    fn read_slot9d_point(&mut self) -> crate::Result<Vec<u8>> {
        // GET DATA for the Key Management certificate object (tag 5F C1 0B).
        let apdu = [
            0x00,
            INS_GET_DATA,
            0x3F,
            0xFF,
            0x05,
            0x5C,
            0x03,
            0x5F,
            0xC1,
            0x0B,
        ];
        let resp = self.apdu_ok(&apdu, "GET DATA (cert)")?;
        let obj = tlv_find(&resp, 0x53)
            .ok_or_else(|| Error::Scd("certificate object (0x53) not found".to_owned()))?;
        let cert_der = tlv_find(obj, 0x70)
            .ok_or_else(|| Error::Scd("certificate (0x70) not found".to_owned()))?;
        let cert = x509_cert::Certificate::from_der(cert_der)
            .map_err(|e| Error::Scd(format!("certificate parse failed: {e}")))?;
        let point = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        if point.len() != POINT_LEN || point[0] != 0x04 {
            return Err(Error::Scd(format!(
                "unexpected slot-9d public point ({} bytes)",
                point.len()
            )));
        }
        Ok(point.to_vec())
    }

    fn verify_pin(&mut self, pin: &[u8]) -> crate::Result<()> {
        if pin.is_empty() || pin.len() > 8 {
            return Err(Error::Scd("PIN must be 1..8 bytes".to_owned()));
        }
        // PIV VERIFY expects the PIN right-padded to 8 bytes with 0xFF.
        let mut apdu = Zeroizing::new(vec![0x00, INS_VERIFY, 0x00, 0x80, 0x08]);
        apdu.extend_from_slice(pin);
        apdu.resize(5 + 8, 0xFF);
        self.apdu_ok(&apdu, "VERIFY PIN")?;
        Ok(())
    }

    /// Perform self-ECDH on slot 9d with the given peer point.
    fn ecdh(&mut self, point: &[u8]) -> crate::Result<Zeroizing<Vec<u8>>> {
        // GENERAL AUTHENTICATE: 7C { 82 00 (response placeholder), 85 <point> }.
        let inner_len = 2 + 2 + point.len();
        let mut data = Vec::with_capacity(2 + inner_len);
        data.push(0x7C);
        data.push(u8::try_from(inner_len).unwrap());
        data.extend_from_slice(&[0x82, 0x00, 0x85, u8::try_from(point.len()).unwrap()]);
        data.extend_from_slice(point);

        let mut apdu = vec![
            0x00,
            INS_GENERAL_AUTHENTICATE,
            ALG_ECC_P256,
            SLOT_9D,
            u8::try_from(data.len()).unwrap(),
        ];
        apdu.extend_from_slice(&data);
        apdu.push(0x00); // Le

        let resp = self.apdu_ok(&apdu, "GENERAL AUTHENTICATE")?;
        let template = tlv_find(&resp, 0x7C)
            .ok_or_else(|| Error::Scd("no dynamic auth template (0x7C)".to_owned()))?;
        let secret = tlv_find(template, 0x82)
            .ok_or_else(|| Error::Scd("no shared secret (0x82)".to_owned()))?;
        if secret.len() != ECDH_SECRET_LEN {
            return Err(Error::EcdhFailed {
                detail: format!("unexpected ECDH output length: {}", secret.len()),
            });
        }
        Ok(Zeroizing::new(secret.to_vec()))
    }
}

/// Resolve the gpg-agent socket path via `gpgconf --list-dirs agent-socket`.
fn agent_socket_path() -> crate::Result<String> {
    let out = Command::new("gpgconf")
        .args(["--list-dirs", "agent-socket"])
        .output()
        .map_err(|e| Error::Scd(format!("cannot run gpgconf (is GnuPG installed?): {e}")))?;
    if !out.status.success() {
        return Err(Error::Scd(
            "gpgconf --list-dirs agent-socket failed".to_owned(),
        ));
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if path.is_empty() {
        return Err(Error::Scd(
            "gpgconf returned no agent-socket path".to_owned(),
        ));
    }
    Ok(path)
}

/// Split an APDU response into its data and 2-byte status word.
fn split_sw<'a>(resp: &'a [u8], what: &str) -> crate::Result<(&'a [u8], u16)> {
    if resp.len() < 2 {
        return Err(Error::Scd(format!("{what}: response too short")));
    }
    let (data, sw) = resp.split_at(resp.len() - 2);
    Ok((data, (u16::from(sw[0]) << 8) | u16::from(sw[1])))
}

/// Map an ISO-7816 status word to success or a specific error.
fn classify_sw(sw: u16, what: &str) -> crate::Result<()> {
    match sw {
        0x9000 => Ok(()),
        // 63 Cx: PIN verification failed, x attempts remaining.
        0x63C0..=0x63CF => Err(Error::WrongPin {
            retries: u8::try_from(sw & 0x000F).unwrap_or(0),
        }),
        // 69 83: PIN blocked (authentication method locked).
        0x6983 => Err(Error::PinLocked),
        // 69 82: security status not satisfied (PIN not verified). Distinct from a
        // wrong PIN: it carries no attempt counter.
        0x6982 => Err(Error::Scd(format!(
            "{what} failed: security status not satisfied (PIN required, SW=6982)"
        ))),
        other => Err(Error::Scd(format!("{what} failed: SW={other:04X}"))),
    }
}

/// Find the value of a single-byte BER-TLV `tag` at the top level of `data`.
fn tlv_find(data: &[u8], tag: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i < data.len() {
        let t = data[i];
        i += 1;
        if i >= data.len() {
            return None;
        }
        let mut len = data[i] as usize;
        i += 1;
        if len & 0x80 != 0 {
            let n = len & 0x7F;
            len = 0;
            for _ in 0..n {
                if i >= data.len() {
                    return None;
                }
                len = (len << 8) | data[i] as usize;
                i += 1;
            }
        }
        if i + len > data.len() {
            return None;
        }
        if t == tag {
            return Some(&data[i..i + len]);
        }
        i += len;
    }
    None
}

/// Decode an Assuan `D`-line payload (percent-escaped) into raw bytes.
fn decode_percent(b: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < b.len() {
        if let Some(byte) = percent_escape(b, i) {
            out.push(byte);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
}

/// Decode a `%XX` escape starting at `i`, or `None` if it is not one.
fn percent_escape(b: &[u8], i: usize) -> Option<u8> {
    if b[i] != b'%' {
        return None;
    }
    let h = hex_val(*b.get(i + 1)?)?;
    let l = hex_val(*b.get(i + 2)?)?;
    Some((h << 4) | l)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_sw, decode_percent, split_sw, tlv_find};
    use crate::error::Error;

    #[test]
    fn percent_decodes_escapes() {
        let mut out = Vec::new();
        decode_percent(b"AB%25CD%0a", &mut out);
        assert_eq!(out, b"AB%CD\n");
    }

    #[test]
    fn tlv_finds_nested_value() {
        // 53 { 70 03 AA BB CC, 71 01 00 }  (inner value is 8 bytes)
        let data = [0x53, 0x08, 0x70, 0x03, 0xAA, 0xBB, 0xCC, 0x71, 0x01, 0x00];
        let obj = tlv_find(&data, 0x53).unwrap();
        assert_eq!(tlv_find(obj, 0x70).unwrap(), &[0xAA, 0xBB, 0xCC]);
        assert_eq!(tlv_find(obj, 0x71).unwrap(), &[0x00]);
    }

    #[test]
    fn tlv_handles_long_form_length() {
        let mut data = vec![0x70, 0x81, 0x02, 0xDE, 0xAD];
        data.push(0x99); // trailing byte, ignored
        assert_eq!(tlv_find(&data, 0x70).unwrap(), &[0xDE, 0xAD]);
    }

    #[test]
    fn split_sw_separates_status() {
        let (data, sw) = split_sw(&[0xAA, 0xBB, 0x90, 0x00], "x").unwrap();
        assert_eq!(data, &[0xAA, 0xBB]);
        assert_eq!(sw, 0x9000);
        assert!(split_sw(&[0x90], "x").is_err());
    }

    #[test]
    fn classify_sw_maps_known_statuses() {
        assert!(classify_sw(0x9000, "x").is_ok());
        // 63 Cx -> wrong PIN with x attempts; not confused with 69 82.
        assert!(matches!(
            classify_sw(0x63C2, "x"),
            Err(Error::WrongPin { retries: 2 })
        ));
        assert!(matches!(classify_sw(0x6983, "x"), Err(Error::PinLocked)));
        // 69 82 is "security status not satisfied", NOT a wrong-PIN with 2 tries.
        assert!(matches!(classify_sw(0x6982, "x"), Err(Error::Scd(_))));
        assert!(matches!(classify_sw(0x6A82, "x"), Err(Error::Scd(_))));
    }
}
