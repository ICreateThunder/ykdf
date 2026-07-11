//! Detached signatures over derived keys, shared by the CLI and JNI bridge.
//!
//! Enabled by the `sign` feature. Two shapes:
//!
//! - **ed25519** produces an OpenSSH `SSHSIG` (PROTOCOL.sshsig), so
//!   `ssh-keygen -Y verify` validates it with no YKDF on the far side.
//! - **ML-DSA** produces a `ykdf-sig:v1` container (see `docs/signatures.md`);
//!   there is no ubiquitous detached-ML-DSA standard to target.
//!
//! Verification is pure: it takes a supplied public key, so it needs no
//! derivation and no hardware.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer, Verifier};
use ml_dsa::{
    B32, EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature, SigningKey,
    VerifyingKey,
};
use sha2::{Digest, Sha256, Sha512};

use crate::format::write_openssh_string;
use crate::{Ed25519SeedBytes, Error, Profile, ProfileOutput, Result};

const SSHSIG_MAGIC: &[u8] = b"SSHSIG";
const SSHSIG_VERSION: u32 = 1;
const SSH_ED25519: &[u8] = b"ssh-ed25519";
const SSHSIG_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const SSHSIG_END: &str = "-----END SSH SIGNATURE-----";

/// Container prefix for an ML-DSA `ykdf-sig:v1` signature. Followed by
/// `<profile>:<base64(signature)>`.
const YKDF_SIG_PREFIX: &str = "ykdf-sig:v1:";
/// FIPS 204 context string binding the format version into every ML-DSA
/// signature (the native domain-separation slot).
const YKDF_SIG_CTX: &[u8] = b"ykdf-sig:v1";

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
        // ML-DSA always binds SHA-512 in its own framing, so `hash` is ignored
        // here (it only selects the SSHSIG digest for ed25519).
        ProfileOutput::MlDsaKeypair(kp) => {
            sign_ykdf_sig(profile, &kp.signing_key, namespace, message)
        }
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
    let trimmed = signature.trim();
    if trimmed.starts_with(SSHSIG_BEGIN) {
        verify_sshsig(signature, public_key, namespace, message)
    } else if let Some(body) = trimmed.strip_prefix(YKDF_SIG_PREFIX) {
        verify_ykdf_sig(body, public_key, namespace, message)
    } else {
        Err(Error::MalformedSignature {
            detail: "unrecognised signature format (expected SSHSIG or ykdf-sig:v1)".to_owned(),
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

// --- ML-DSA (ykdf-sig:v1) ------------------------------------------------

/// The message ML-DSA signs for a `ykdf-sig:v1` signature: the namespace, the
/// hash label, and the SHA-512 message digest, each OpenSSH-string encoded.
/// The format version is bound separately through the ML-DSA context string
/// ([`YKDF_SIG_CTX`]), and the profile is fixed by the key, so neither is
/// repeated here.
fn ykdf_sig_signed_data(namespace: &str, message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::new();
    write_openssh_string(&mut framed, namespace.as_bytes());
    write_openssh_string(&mut framed, b"sha512");
    write_openssh_string(&mut framed, &Sha512::digest(message));
    framed
}

fn sign_ykdf_sig(profile: Profile, seed: &[u8], namespace: &str, message: &[u8]) -> Result<String> {
    let framed = ykdf_sig_signed_data(namespace, message);
    let signature = match profile {
        Profile::MlDsa44 => mldsa_sign::<MlDsa44>(seed, &framed),
        Profile::MlDsa65 => mldsa_sign::<MlDsa65>(seed, &framed),
        Profile::MlDsa87 => mldsa_sign::<MlDsa87>(seed, &framed),
        _ => {
            return Err(Error::SigningUnsupported {
                profile: profile.as_str(),
            });
        }
    }?;
    Ok(format!(
        "{YKDF_SIG_PREFIX}{}:{}",
        profile.as_str(),
        BASE64.encode(&signature)
    ))
}

/// Deterministically sign `framed` under the ML-DSA parameter set `P` from the
/// 32-byte seed, returning the raw signature bytes.
fn mldsa_sign<P: MlDsaParams>(seed: &[u8], framed: &[u8]) -> Result<Vec<u8>> {
    let seed = B32::try_from(seed).map_err(|_| Error::PostProcessing {
        detail: "ML-DSA seed is not 32 bytes".to_owned(),
    })?;
    let signing = SigningKey::<P>::from_seed(&seed);
    let signature = signing
        .expanded_key()
        .sign_deterministic(framed, YKDF_SIG_CTX)
        .map_err(|_| Error::PostProcessing {
            detail: "ML-DSA signing failed".to_owned(),
        })?;
    Ok(signature.encode().to_vec())
}

/// Verify a `ykdf-sig:v1` body (`<profile>:<base64(signature)>`) against a
/// supplied base64 verifying key.
fn verify_ykdf_sig(body: &str, public_key: &str, namespace: &str, message: &[u8]) -> Result<()> {
    let (profile_label, sig_b64) = body
        .split_once(':')
        .ok_or_else(|| malformed_sig("ykdf-sig is missing its signature body"))?;
    let profile = Profile::from_str_label(profile_label)
        .ok_or_else(|| malformed_sig("ykdf-sig names an unknown profile"))?;
    let signature = BASE64
        .decode(sig_b64.trim())
        .map_err(|_| malformed_sig("ykdf-sig body is not valid base64"))?;
    let verifying_key = BASE64
        .decode(public_key.trim())
        .map_err(|_| malformed_pubkey("ML-DSA public key is not valid base64"))?;
    let framed = ykdf_sig_signed_data(namespace, message);
    match profile {
        Profile::MlDsa44 => mldsa_verify::<MlDsa44>(&verifying_key, &signature, &framed),
        Profile::MlDsa65 => mldsa_verify::<MlDsa65>(&verifying_key, &signature, &framed),
        Profile::MlDsa87 => mldsa_verify::<MlDsa87>(&verifying_key, &signature, &framed),
        _ => Err(malformed_sig("ykdf-sig profile is not an ML-DSA profile")),
    }
}

/// Verify raw ML-DSA `signature` bytes over `framed` under parameter set `P`
/// with the raw `verifying_key` bytes. A wrong-length key or signature (for
/// example a mislabelled profile) fails to decode rather than verifying wrongly.
fn mldsa_verify<P: MlDsaParams>(
    verifying_key: &[u8],
    signature: &[u8],
    framed: &[u8],
) -> Result<()> {
    let encoded = EncodedVerifyingKey::<P>::try_from(verifying_key)
        .map_err(|_| malformed_pubkey("ML-DSA public key has the wrong length"))?;
    let verifying = VerifyingKey::<P>::decode(&encoded);
    let signature = Signature::<P>::try_from(signature)
        .map_err(|_| malformed_sig("ML-DSA signature has the wrong length"))?;
    if verifying.verify_with_context(framed, YKDF_SIG_CTX, &signature) {
        Ok(())
    } else {
        Err(Error::SignatureVerificationFailed)
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
        let len = usize::try_from(self.read_u32()?)
            .map_err(|_| malformed_sig("string length exceeds usize"))?;
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

    /// Derive an ML-DSA output and its base64 verifying key from the golden IKM.
    fn mldsa_key(profile: Profile, index: u32) -> (crate::ProfileOutput, String) {
        let ctx = Context::new(profile, "sign-test", index).unwrap();
        let ikm = Ikm::new((0u8..32).collect()).unwrap();
        let mk = extract(&ikm, ctx.pipeline()).unwrap();
        let out = derive(&mk, &ctx).unwrap();
        let pk = public_key_string(&out, profile).unwrap();
        (out, pk)
    }

    #[test]
    fn mldsa_round_trips_all_levels() {
        for profile in [Profile::MlDsa44, Profile::MlDsa65, Profile::MlDsa87] {
            let (out, pk) = mldsa_key(profile, 0);
            let sig = sign_message(&out, profile, "file", HashAlg::Sha512, b"hello").unwrap();
            assert!(sig.starts_with("ykdf-sig:v1:"));
            assert!(sig.contains(profile.as_str()));
            verify_message(&sig, &pk, "file", b"hello").unwrap();
        }
    }

    #[test]
    fn mldsa_is_deterministic() {
        let (out, _) = mldsa_key(Profile::MlDsa65, 0);
        let a = sign_message(&out, Profile::MlDsa65, "file", HashAlg::Sha512, b"msg").unwrap();
        let b = sign_message(&out, Profile::MlDsa65, "file", HashAlg::Sha512, b"msg").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn mldsa_tamper_and_namespace_fail() {
        let (out, pk) = mldsa_key(Profile::MlDsa65, 0);
        let sig = sign_message(&out, Profile::MlDsa65, "file", HashAlg::Sha512, b"hello").unwrap();
        assert!(verify_message(&sig, &pk, "file", b"HELLO").is_err());
        assert!(verify_message(&sig, &pk, "email", b"hello").is_err());
    }

    #[test]
    fn mldsa_wrong_key_fails() {
        let (out, _) = mldsa_key(Profile::MlDsa65, 0);
        let sig = sign_message(&out, Profile::MlDsa65, "file", HashAlg::Sha512, b"hello").unwrap();
        let (_, other_pk) = mldsa_key(Profile::MlDsa65, 1);
        assert!(verify_message(&sig, &other_pk, "file", b"hello").is_err());
    }

    #[test]
    fn mldsa_mislabelled_profile_fails() {
        // A mldsa65 signature checked against a mldsa44 key must fail to decode
        // (wrong length), never verify wrongly.
        let (out, _) = mldsa_key(Profile::MlDsa65, 0);
        let sig = sign_message(&out, Profile::MlDsa65, "file", HashAlg::Sha512, b"hi").unwrap();
        let (_, pk44) = mldsa_key(Profile::MlDsa44, 0);
        assert!(verify_message(&sig, &pk44, "file", b"hi").is_err());
    }
}
