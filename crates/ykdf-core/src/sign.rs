//! Detached signatures over derived keys, shared by the CLI and JNI bridge.
//!
//! Enabled by the `sign` feature. Two shapes:
//!
//! - **ed25519** produces an OpenSSH `SSHSIG` (PROTOCOL.sshsig), so
//!   `ssh-keygen -Y verify` validates it with no YKDF on the far side.
//! - **ML-DSA** produces a `ykdf-sig:v1` container (added in a follow-up); there
//!   is no ubiquitous detached-ML-DSA standard to target.
//!
//! Verification is pure: it takes a supplied public key, so it needs no
//! derivation and no hardware.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer, Verifier};
use sha2::{Digest, Sha256, Sha512};

use crate::format::write_openssh_string;
use crate::{Ed25519SeedBytes, Error, Profile, ProfileOutput, Result};

const SSHSIG_MAGIC: &[u8] = b"SSHSIG";
const SSHSIG_VERSION: u32 = 1;
const SSH_ED25519: &[u8] = b"ssh-ed25519";
const SSHSIG_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const SSHSIG_END: &str = "-----END SSH SIGNATURE-----";

/// The message-hash algorithm named inside an `SSHSIG`. `ssh-keygen` defaults to
/// SHA-512.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-256.
    Sha256,
    /// SHA-512 (the `ssh-keygen` default).
    Sha512,
}

impl HashAlg {
    /// The wire label written into the `SSHSIG` blob.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    fn from_label(label: &str) -> Option<Self> {
        match label {
            "sha256" => Some(Self::Sha256),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(message).to_vec(),
            Self::Sha512 => Sha512::digest(message).to_vec(),
        }
    }
}

/// Sign `message` with the derived key in `output`, returning a detached
/// signature.
///
/// `namespace` is the SSHSIG domain (`ssh-keygen`'s `-n`), conventionally
/// `"file"`; the verifier must supply the same value.
///
/// # Errors
///
/// Returns [`Error::SigningUnsupported`] if the profile has no signing key
/// (only ed25519 and the ML-DSA profiles can sign).
pub fn sign_message(
    output: &ProfileOutput,
    profile: Profile,
    namespace: &str,
    hash: HashAlg,
    message: &[u8],
) -> Result<String> {
    match output {
        ProfileOutput::Ed25519Seed(seed) => Ok(sign_sshsig(seed, namespace, hash, message)),
        // ML-DSA (ykdf-sig:v1) lands in the follow-up PR.
        _ => Err(Error::SigningUnsupported {
            profile: profile.as_str(),
        }),
    }
}

/// Verify a detached `signature` over `message` against a supplied
/// `public_key`.
///
/// The format is detected from `signature`: an `SSHSIG` armour block takes the
/// ed25519 path. `public_key` is the canonical public-key string for the
/// profile (for ed25519, a `ssh-ed25519 <base64>` line, the same one
/// `ykdf pubkey` prints). `namespace` must match what the signature was made
/// with.
///
/// # Errors
///
/// Returns [`Error::SignatureVerificationFailed`] if the signature is not valid
/// for the key and message, or a `Malformed*` / [`Error::NamespaceMismatch`]
/// error if an input cannot be parsed or the namespace differs.
pub fn verify_message(
    signature: &str,
    public_key: &str,
    namespace: &str,
    message: &[u8],
) -> Result<()> {
    if signature.trim_start().starts_with(SSHSIG_BEGIN) {
        verify_sshsig(signature, public_key, namespace, message)
    } else {
        Err(Error::MalformedSignature {
            detail: "unrecognised signature format (expected an SSH SIGNATURE block)".to_owned(),
        })
    }
}

fn sign_sshsig(seed: &Ed25519SeedBytes, namespace: &str, hash: HashAlg, message: &[u8]) -> String {
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed.0);
    let verifying = signing.verifying_key();

    // The ed25519 signature is over this framed, pre-hashed blob (PROTOCOL.sshsig).
    let signed = sshsig_signed_data(namespace, hash, &hash.digest(message));
    let signature = signing.sign(&signed);

    let mut pubkey_blob = Vec::new();
    write_openssh_string(&mut pubkey_blob, SSH_ED25519);
    write_openssh_string(&mut pubkey_blob, verifying.as_bytes());

    let mut signature_blob = Vec::new();
    write_openssh_string(&mut signature_blob, SSH_ED25519);
    write_openssh_string(&mut signature_blob, &signature.to_bytes());

    let mut outer = Vec::new();
    outer.extend_from_slice(SSHSIG_MAGIC);
    outer.extend_from_slice(&SSHSIG_VERSION.to_be_bytes());
    write_openssh_string(&mut outer, &pubkey_blob);
    write_openssh_string(&mut outer, namespace.as_bytes());
    write_openssh_string(&mut outer, b""); // reserved
    write_openssh_string(&mut outer, hash.label().as_bytes());
    write_openssh_string(&mut outer, &signature_blob);

    armour(&outer)
}

/// The blob that ed25519 actually signs: magic, namespace, reserved, hash
/// algorithm, and the message digest (PROTOCOL.sshsig).
fn sshsig_signed_data(namespace: &str, hash: HashAlg, digest: &[u8]) -> Vec<u8> {
    let mut signed = Vec::new();
    signed.extend_from_slice(SSHSIG_MAGIC);
    write_openssh_string(&mut signed, namespace.as_bytes());
    write_openssh_string(&mut signed, b""); // reserved
    write_openssh_string(&mut signed, hash.label().as_bytes());
    write_openssh_string(&mut signed, digest);
    signed
}

fn verify_sshsig(signature: &str, public_key: &str, namespace: &str, message: &[u8]) -> Result<()> {
    let expected_key = parse_ssh_ed25519_pubkey(public_key)?;

    let blob = dearmour(signature)?;
    let mut r = SshReader::new(&blob);

    let magic = r.read_raw(SSHSIG_MAGIC.len())?;
    if magic != SSHSIG_MAGIC {
        return Err(malformed_sig("bad magic preamble"));
    }
    let version = r.read_u32()?;
    if version != SSHSIG_VERSION {
        return Err(malformed_sig("unsupported SSHSIG version"));
    }
    let pubkey_blob = r.read_string()?;
    let blob_namespace = r.read_string()?;
    let _reserved = r.read_string()?;
    let hash_label = r.read_string()?;
    let signature_blob = r.read_string()?;

    // The signature is bound to its namespace; verifying under a different one
    // would silently accept a signature made for another purpose.
    if blob_namespace != namespace.as_bytes() {
        return Err(Error::NamespaceMismatch {
            expected: namespace.to_owned(),
            got: String::from_utf8_lossy(blob_namespace).into_owned(),
        });
    }

    let embedded_key = read_ed25519_key_blob(pubkey_blob)?;
    if embedded_key != expected_key {
        return Err(malformed_sig(
            "signature was made by a different key than the one supplied",
        ));
    }

    let hash = HashAlg::from_label(
        core::str::from_utf8(hash_label).map_err(|_| malformed_sig("non-utf8 hash label"))?,
    )
    .ok_or_else(|| malformed_sig("unknown hash algorithm"))?;

    let raw_sig = read_ed25519_signature_blob(signature_blob)?;

    let signed = sshsig_signed_data(namespace, hash, &hash.digest(message));
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&embedded_key)
        .map_err(|_| malformed_sig("invalid ed25519 public key"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&raw_sig);
    verifying
        .verify(&signed, &sig)
        .map_err(|_| Error::SignatureVerificationFailed)
}

/// Parse a `ssh-ed25519 <base64> [comment]` public-key line into its 32 raw
/// key bytes.
fn parse_ssh_ed25519_pubkey(line: &str) -> Result<[u8; 32]> {
    let mut fields = line.split_whitespace();
    let kind = fields
        .next()
        .ok_or_else(|| malformed_pubkey("empty public key"))?;
    if kind != "ssh-ed25519" {
        return Err(malformed_pubkey("not an ssh-ed25519 key"));
    }
    let b64 = fields
        .next()
        .ok_or_else(|| malformed_pubkey("missing key data"))?;
    let blob = BASE64
        .decode(b64)
        .map_err(|_| malformed_pubkey("key data is not valid base64"))?;
    read_ed25519_key_blob(&blob)
}

/// Read a `string "ssh-ed25519" ‖ string key[32]` blob into the raw key bytes.
fn read_ed25519_key_blob(blob: &[u8]) -> Result<[u8; 32]> {
    let mut r = SshReader::new(blob);
    if r.read_string()? != SSH_ED25519 {
        return Err(malformed_pubkey("public key is not ssh-ed25519"));
    }
    let key = r.read_string()?;
    key.try_into()
        .map_err(|_| malformed_pubkey("ed25519 key is not 32 bytes"))
}

/// Read a `string "ssh-ed25519" ‖ string sig[64]` blob into the raw signature.
fn read_ed25519_signature_blob(blob: &[u8]) -> Result<[u8; 64]> {
    let mut r = SshReader::new(blob);
    if r.read_string()? != SSH_ED25519 {
        return Err(malformed_sig("signature is not ssh-ed25519"));
    }
    let sig = r.read_string()?;
    sig.try_into()
        .map_err(|_| malformed_sig("ed25519 signature is not 64 bytes"))
}

/// Base64-encode `blob` and wrap it in the SSHSIG armour, lines wrapped at 70
/// columns to match `ssh-keygen`'s output. Ends with a trailing newline.
fn armour(blob: &[u8]) -> String {
    let b64 = BASE64.encode(blob);
    let mut out = String::with_capacity(b64.len() + 128);
    out.push_str(SSHSIG_BEGIN);
    out.push('\n');
    let mut i = 0;
    while i < b64.len() {
        let end = (i + 70).min(b64.len());
        // b64 is ASCII, so byte slicing lands on char boundaries.
        out.push_str(&b64[i..end]);
        out.push('\n');
        i = end;
    }
    out.push_str(SSHSIG_END);
    out.push('\n');
    out
}

/// Strip the SSHSIG armour and decode the base64 body. Tolerant of surrounding
/// whitespace and any line wrapping, like `ssh-keygen`.
fn dearmour(armoured: &str) -> Result<Vec<u8>> {
    let body: String = armoured
        .lines()
        .map(str::trim)
        .skip_while(|l| *l != SSHSIG_BEGIN)
        .skip(1)
        .take_while(|l| *l != SSHSIG_END)
        .collect();
    if body.is_empty() {
        return Err(malformed_sig("empty or missing SSH SIGNATURE block"));
    }
    BASE64
        .decode(body.as_bytes())
        .map_err(|_| malformed_sig("signature body is not valid base64"))
}

fn malformed_sig(detail: &str) -> Error {
    Error::MalformedSignature {
        detail: detail.to_owned(),
    }
}

fn malformed_pubkey(detail: &str) -> Error {
    Error::MalformedPublicKey {
        detail: detail.to_owned(),
    }
}

/// A minimal reader for the OpenSSH `string` wire encoding (u32-be length +
/// bytes), the counterpart to [`write_openssh_string`].
struct SshReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SshReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_raw(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| malformed_sig("truncated signature"))?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_raw(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_string(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        self.read_raw(len)
    }
}

#[cfg(test)]
mod tests {
    use super::{HashAlg, sign_message, verify_message};
    use crate::{Context, Ikm, Profile, derive, extract, public_key_string};

    /// Derive the ed25519 output and its public-key line from the golden IKM.
    fn ed25519_key() -> (crate::ProfileOutput, String) {
        let ctx = Context::new(Profile::Ed25519, "sign-test", 0).unwrap();
        let ikm = Ikm::new((0u8..32).collect()).unwrap();
        let mk = extract(&ikm, ctx.pipeline()).unwrap();
        let out = derive(&mk, &ctx).unwrap();
        let pk = public_key_string(&out, Profile::Ed25519).unwrap();
        (out, pk)
    }

    #[test]
    fn sshsig_round_trips() {
        let (out, pk) = ed25519_key();
        let sig = sign_message(&out, Profile::Ed25519, "file", HashAlg::Sha512, b"hello").unwrap();
        assert!(sig.starts_with("-----BEGIN SSH SIGNATURE-----"));
        verify_message(&sig, &pk, "file", b"hello").unwrap();
    }

    #[test]
    fn signing_is_deterministic() {
        let (out, _) = ed25519_key();
        let a = sign_message(&out, Profile::Ed25519, "file", HashAlg::Sha512, b"msg").unwrap();
        let b = sign_message(&out, Profile::Ed25519, "file", HashAlg::Sha512, b"msg").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn tampered_message_fails() {
        let (out, pk) = ed25519_key();
        let sig = sign_message(&out, Profile::Ed25519, "file", HashAlg::Sha512, b"hello").unwrap();
        assert!(verify_message(&sig, &pk, "file", b"HELLO").is_err());
    }

    #[test]
    fn wrong_namespace_fails() {
        let (out, pk) = ed25519_key();
        let sig = sign_message(&out, Profile::Ed25519, "file", HashAlg::Sha512, b"hello").unwrap();
        assert!(verify_message(&sig, &pk, "email", b"hello").is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let (out, _) = ed25519_key();
        let sig = sign_message(&out, Profile::Ed25519, "file", HashAlg::Sha512, b"hello").unwrap();
        // A different derivation index gives a different key.
        let ctx = Context::new(Profile::Ed25519, "sign-test", 1).unwrap();
        let ikm = Ikm::new((0u8..32).collect()).unwrap();
        let mk = extract(&ikm, ctx.pipeline()).unwrap();
        let other = derive(&mk, &ctx).unwrap();
        let other_pk = public_key_string(&other, Profile::Ed25519).unwrap();
        assert!(verify_message(&sig, &other_pk, "file", b"hello").is_err());
    }

    #[test]
    fn sha256_variant_round_trips() {
        let (out, pk) = ed25519_key();
        let sig = sign_message(&out, Profile::Ed25519, "file", HashAlg::Sha256, b"hello").unwrap();
        verify_message(&sig, &pk, "file", b"hello").unwrap();
    }

    #[test]
    fn non_signing_profile_is_rejected() {
        let ctx = Context::new(Profile::X25519, "sign-test", 0).unwrap();
        let ikm = Ikm::new((0u8..32).collect()).unwrap();
        let mk = extract(&ikm, ctx.pipeline()).unwrap();
        let out = derive(&mk, &ctx).unwrap();
        assert!(sign_message(&out, Profile::X25519, "file", HashAlg::Sha512, b"x").is_err());
    }
}
