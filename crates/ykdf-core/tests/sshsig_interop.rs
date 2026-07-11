//! Interoperability: a signature produced by `sign_message` for an ed25519 key
//! must validate with the system `ssh-keygen -Y verify`. This guards the SSHSIG
//! byte layout against silent drift, which unit tests alone cannot catch.
//!
//! Only built with the `sign` feature (on in a workspace test via the CLI's
//! feature activation). Skips gracefully when `ssh-keygen` is not installed.
#![cfg(feature = "sign")]

use std::io::Write;
use std::process::{Command, Stdio};

use ykdf_core::{Context, HashAlg, Ikm, Profile, derive, extract, public_key_string, sign_message};

fn ssh_keygen_present() -> bool {
    Command::new("ssh-keygen")
        .arg("-Y")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn sign_and_pubkey(namespace: &str, hash: HashAlg, message: &[u8]) -> (String, String) {
    let ctx = Context::new(Profile::Ed25519, "interop", 0).unwrap();
    let ikm = Ikm::new((0u8..32).collect()).unwrap();
    let mk = extract(&ikm, ctx.pipeline()).unwrap();
    let out = derive(&mk, &ctx).unwrap();
    let pubkey = public_key_string(&out, Profile::Ed25519).unwrap();
    let sig = sign_message(&out, Profile::Ed25519, namespace, hash, message).unwrap();
    (sig, pubkey)
}

/// Run `ssh-keygen -Y verify` over `message` with the given signature and
/// allowed-signers public key. Returns whether ssh-keygen accepted it. `tag`
/// keeps concurrent tests in separate temp directories.
fn ssh_keygen_verifies(
    tag: &str,
    namespace: &str,
    pubkey: &str,
    sig: &str,
    message: &[u8],
) -> bool {
    let dir = std::env::temp_dir().join(format!("ykdf-sshsig-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sig_path = dir.join("msg.sig");
    let allowed = dir.join("allowed_signers");
    std::fs::write(&sig_path, sig).unwrap();
    std::fs::write(&allowed, format!("signer@ykdf {pubkey}\n")).unwrap();

    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&allowed)
        .args(["-I", "signer@ykdf", "-n", namespace, "-s"])
        .arg(&sig_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(message).unwrap();
    let status = child.wait().unwrap();

    let _ = std::fs::remove_dir_all(&dir);
    status.success()
}

#[test]
fn ssh_keygen_accepts_our_sha512_signature() {
    if !ssh_keygen_present() {
        eprintln!("skipping: ssh-keygen not installed");
        return;
    }
    let (sig, pubkey) = sign_and_pubkey("file", HashAlg::Sha512, b"interop message\n");
    assert!(ssh_keygen_verifies(
        "sha512",
        "file",
        &pubkey,
        &sig,
        b"interop message\n"
    ));
}

#[test]
fn ssh_keygen_accepts_our_sha256_signature() {
    if !ssh_keygen_present() {
        eprintln!("skipping: ssh-keygen not installed");
        return;
    }
    let (sig, pubkey) = sign_and_pubkey("file", HashAlg::Sha256, b"interop message\n");
    assert!(ssh_keygen_verifies(
        "sha256",
        "file",
        &pubkey,
        &sig,
        b"interop message\n"
    ));
}

#[test]
fn ssh_keygen_rejects_a_tampered_message() {
    if !ssh_keygen_present() {
        eprintln!("skipping: ssh-keygen not installed");
        return;
    }
    let (sig, pubkey) = sign_and_pubkey("file", HashAlg::Sha512, b"original\n");
    assert!(!ssh_keygen_verifies(
        "tamper",
        "file",
        &pubkey,
        &sig,
        b"tampered\n"
    ));
}
