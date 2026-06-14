use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ykdf_core::{Profile, ProfileOutput};

use crate::cli::OutputFormat;
use crate::error::CliError;

/// Format profile output for display, using the specified or default format.
pub fn format_output(
    output: &ProfileOutput,
    profile: Profile,
    format: Option<&OutputFormat>,
) -> Result<Vec<u8>, CliError> {
    let fmt = format.cloned().unwrap_or_else(|| default_format(profile));
    validate_format(profile, &fmt)?;

    match (output, &fmt) {
        // base64
        (ProfileOutput::SecretKey(k), OutputFormat::Base64) => Ok(line(BASE64.encode(k.0))),
        (ProfileOutput::Ed25519Seed(s), OutputFormat::Base64) => Ok(line(BASE64.encode(s.0))),
        (ProfileOutput::MlKemKeypair(kp), OutputFormat::Base64) => {
            Ok(line(BASE64.encode(&kp.decapsulation_key)))
        }
        (ProfileOutput::Raw(r), OutputFormat::Base64) => Ok(line(BASE64.encode(&r.0))),

        // hex
        (ProfileOutput::SecretKey(k), OutputFormat::Hex) => Ok(line(hex::encode(k.0))),
        (ProfileOutput::Ed25519Seed(s), OutputFormat::Hex) => Ok(line(hex::encode(s.0))),
        (ProfileOutput::MlKemKeypair(kp), OutputFormat::Hex) => {
            Ok(line(hex::encode(&kp.decapsulation_key)))
        }
        (ProfileOutput::Raw(r), OutputFormat::Hex) => Ok(line(hex::encode(&r.0))),

        // openssh (ed25519 only)
        (ProfileOutput::Ed25519Seed(s), OutputFormat::Openssh) => {
            Ok(line(format_openssh_ed25519(&s.0)))
        }

        // age identity (already formatted)
        (ProfileOutput::AgeIdentity(a), OutputFormat::Age) => Ok(line(a.identity.clone())),

        // binary (raw bytes, no newline)
        (ProfileOutput::SecretKey(k), OutputFormat::Binary) => Ok(k.0.to_vec()),
        (ProfileOutput::Ed25519Seed(s), OutputFormat::Binary) => Ok(s.0.to_vec()),
        (ProfileOutput::MlKemKeypair(kp), OutputFormat::Binary) => Ok(kp.decapsulation_key.clone()),
        (ProfileOutput::AgeIdentity(a), OutputFormat::Binary) => Ok(a.secret_key.to_vec()),
        (ProfileOutput::Raw(r), OutputFormat::Binary) => Ok(r.0.clone()),

        _ => Err(CliError::InvalidFormat {
            profile: profile.as_str(),
            format: format_name(&fmt),
        }),
    }
}

/// Format a public key from profile output.
pub fn format_pubkey(output: &ProfileOutput, profile: Profile) -> Result<Vec<u8>, CliError> {
    if matches!(profile, Profile::Symmetric | Profile::Raw) {
        return Err(CliError::NoPubkey {
            profile: profile.as_str(),
        });
    }
    match output {
        ProfileOutput::SecretKey(k) => {
            let secret = x25519_dalek::StaticSecret::from(k.0);
            let public = x25519_dalek::PublicKey::from(&secret);
            Ok(line(BASE64.encode(public.as_bytes())))
        }
        ProfileOutput::Ed25519Seed(s) => {
            let signing = ed25519_dalek::SigningKey::from_bytes(&s.0);
            let verifying = signing.verifying_key();
            let mut pubkey_blob = Vec::new();
            write_openssh_string(&mut pubkey_blob, b"ssh-ed25519");
            write_openssh_string(&mut pubkey_blob, verifying.as_bytes());
            Ok(line(format!("ssh-ed25519 {}", BASE64.encode(&pubkey_blob))))
        }
        ProfileOutput::AgeIdentity(a) => {
            let secret = x25519_dalek::StaticSecret::from(a.secret_key);
            let public = x25519_dalek::PublicKey::from(&secret);
            let hrp = bech32::Hrp::parse("age").map_err(|_| CliError::NoPubkey {
                profile: profile.as_str(),
            })?;
            let recipient =
                bech32::encode::<bech32::Bech32>(hrp, public.as_bytes()).map_err(|_| {
                    CliError::NoPubkey {
                        profile: profile.as_str(),
                    }
                })?;
            Ok(line(recipient))
        }
        ProfileOutput::MlKemKeypair(kp) => Ok(line(BASE64.encode(&kp.encapsulation_key))),
        ProfileOutput::Raw(_) => Err(CliError::NoPubkey {
            profile: profile.as_str(),
        }),
    }
}

fn default_format(profile: Profile) -> OutputFormat {
    match profile {
        Profile::Ed25519 => OutputFormat::Openssh,
        Profile::AgeX25519 => OutputFormat::Age,
        Profile::Symmetric | Profile::Raw => OutputFormat::Hex,
        Profile::X25519 | Profile::MlKem512 | Profile::MlKem768 | Profile::MlKem1024 => {
            OutputFormat::Base64
        }
    }
}

fn validate_format(profile: Profile, format: &OutputFormat) -> Result<(), CliError> {
    let valid = match format {
        OutputFormat::Base64 | OutputFormat::Hex | OutputFormat::Binary => {
            !matches!(profile, Profile::AgeX25519)
        }
        OutputFormat::Openssh => profile == Profile::Ed25519,
        OutputFormat::Age => profile == Profile::AgeX25519,
    };
    if valid {
        Ok(())
    } else {
        Err(CliError::InvalidFormat {
            profile: profile.as_str(),
            format: format_name(format),
        })
    }
}

fn format_name(f: &OutputFormat) -> &'static str {
    match f {
        OutputFormat::Base64 => "base64",
        OutputFormat::Hex => "hex",
        OutputFormat::Openssh => "openssh",
        OutputFormat::Age => "age",
        OutputFormat::Binary => "binary",
    }
}

fn line(s: String) -> Vec<u8> {
    let mut out = s.into_bytes();
    out.push(b'\n');
    out
}

// --- OpenSSH private key formatter ---

/// Build an OpenSSH private key PEM for an Ed25519 seed.
///
/// Follows the OpenSSH PROTOCOL.key format:
/// <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key>
fn format_openssh_ed25519(seed: &[u8; 32]) -> String {
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    let verifying = signing.verifying_key();
    let pubkey_bytes = verifying.as_bytes();
    // ed25519 private key in OpenSSH is seed || public (64 bytes)
    let mut privkey_bytes = [0u8; 64];
    privkey_bytes[..32].copy_from_slice(seed);
    privkey_bytes[32..].copy_from_slice(pubkey_bytes);

    // Public key section (for the outer wrapper)
    let mut pub_blob = Vec::new();
    write_openssh_string(&mut pub_blob, b"ssh-ed25519");
    write_openssh_string(&mut pub_blob, pubkey_bytes);

    // Private key section
    let mut priv_section = Vec::new();
    // checkint (repeated, unencrypted so value does not matter)
    let checkint: u32 = 0;
    priv_section.extend_from_slice(&checkint.to_be_bytes());
    priv_section.extend_from_slice(&checkint.to_be_bytes());
    // key type
    write_openssh_string(&mut priv_section, b"ssh-ed25519");
    // public key
    write_openssh_string(&mut priv_section, pubkey_bytes);
    // private key (seed || public, 64 bytes)
    write_openssh_string(&mut priv_section, &privkey_bytes);
    // comment (empty)
    write_openssh_string(&mut priv_section, b"");
    // padding to 8-byte alignment
    let pad_len = (8 - (priv_section.len() % 8)) % 8;
    for i in 1..=pad_len {
        // Safe: pad_len <= 7, so i fits in u8.
        #[allow(clippy::cast_possible_truncation)]
        priv_section.push(i as u8);
    }

    // Assemble the full blob
    let mut blob = Vec::new();
    // magic
    blob.extend_from_slice(b"openssh-key-v1\0");
    // cipher
    write_openssh_string(&mut blob, b"none");
    // kdf
    write_openssh_string(&mut blob, b"none");
    // kdf options (empty string)
    write_openssh_string(&mut blob, b"");
    // number of keys
    blob.extend_from_slice(&1u32.to_be_bytes());
    // public key blob
    write_openssh_string(&mut blob, &pub_blob);
    // private key section (length-prefixed)
    write_openssh_string(&mut blob, &priv_section);

    // PEM encode
    let b64 = BASE64.encode(&blob);
    let mut pem = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        // base64 output is always valid ASCII/UTF-8.
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----");

    pem
}

/// Write a length-prefixed OpenSSH string (u32 big-endian length + bytes).
fn write_openssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    #[allow(clippy::cast_possible_truncation)]
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}
