//! Golden test vectors for the v1 derivation format.
//!
//! `vectors/v1.json` (repo root) is the canonical, language-neutral conformance
//! suite: a second implementation (Android/WASM) reproduces these exact bytes
//! to prove it matches. Here it serves three roles:
//!
//! 1. `vectors_match_committed` recomputes every vector and asserts it equals
//!    the committed JSON. Any change to the byte output breaks CI. This freezes
//!    v1.
//! 2. `hkdf_reference_cross_check` recomputes the HKDF master key and expand
//!    output with the independent `hkdf` crate (a separate RFC 5869
//!    implementation) and asserts equality with our hand-rolled code. This is
//!    the guard against a systematic bug in our own HKDF being blessed.
//! 3. `regenerate` (ignored) rewrites the JSON from the code, for intentional
//!    changes. Run with `--features argon2` so passphrase vectors are included.
//!
//! Scope is the core derivation only (IKM -> extract -> expand -> derive). The
//! `YubiKey` ECDH/HMAC transport is hardware and out of scope; the IKM is an
//! input here.

use serde::{Deserialize, Serialize};
use ykdf_core::expand::expand;
use ykdf_core::{Context, Ikm, Pipeline, Profile, ProfileOutput, derive, derive_raw, extract};

/// The extract salt, embedded here independently of the library so the oracle
/// does not borrow the value it is meant to check.
const EXTRACT_SALT: &[u8] = b"ykdf-v1";

/// Fixed 32-byte IKM (standard mode: PIV ECDH output).
const IKM_32: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Fixed 52-byte IKM (layered mode: ECDH 32 bytes concatenated with a 20-byte
/// HMAC-SHA1 response). The transport is not exercised; this is just a longer
/// IKM that the core treats uniformly.
const IKM_52: [u8; 52] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3,
];

/// Passphrase used by passphrase-cascade vectors.
const PASSPHRASE: &str = "correct horse battery staple";

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct VectorFile {
    version: String,
    description: String,
    vectors: Vec<Vector>,
}

/// `Debug` is intentional: an `assert_eq!` failure prints the full hex of the
/// master key, expanded bytes, and derived output, but every input here is a
/// public synthetic test constant (sequential IKM bytes), not real secret
/// material, so there is nothing sensitive to leak.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct Vector {
    name: String,
    pipeline: String,
    profile: String,
    purpose: String,
    index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    length: Option<usize>,
    ikm_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passphrase: Option<String>,
    /// Master key after extract (and passphrase cascade, if any). 64 bytes.
    master_key_hex: String,
    /// Expand output before profile post-processing.
    expanded_hex: String,
    output: Output,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default)]
struct Output {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret_key_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ed25519_seed_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    age_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    age_secret_key_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mlkem_ek_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mlkem_dk_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    raw_hex: Option<String>,
}

/// Input specification for one vector (outputs are computed).
struct Spec {
    name: String,
    ikm: &'static [u8],
    passphrase: Option<&'static str>,
    pipeline: Pipeline,
    profile: Profile,
    purpose: &'static str,
    index: u32,
    length: Option<usize>,
}

fn spec(
    name: &str,
    pipeline: Pipeline,
    profile: Profile,
    purpose: &'static str,
    index: u32,
) -> Spec {
    Spec {
        name: name.to_string(),
        ikm: &IKM_32,
        passphrase: None,
        pipeline,
        profile,
        purpose,
        index,
        length: None,
    }
}

fn matrix() -> Vec<Spec> {
    use Pipeline::{HkdfSha3, HkdfSha512, Shake256};
    use Profile::{AgeX25519, Ed25519, MlKem512, MlKem768, MlKem1024, Raw, Symmetric, X25519};

    let mut v = vec![
        // Classical profiles over their default pipeline (HKDF-SHA512).
        spec("x25519/hkdf-sha512", HkdfSha512, X25519, "test", 0),
        spec("ed25519/hkdf-sha512", HkdfSha512, Ed25519, "test", 0),
        spec("age-x25519/hkdf-sha512", HkdfSha512, AgeX25519, "test", 0),
        spec("symmetric/hkdf-sha512", HkdfSha512, Symmetric, "test", 0),
        // Classical profiles over the alternate HKDF-SHA3-512 pipeline.
        spec("x25519/hkdf-sha3-512", HkdfSha3, X25519, "test", 0),
        spec("ed25519/hkdf-sha3-512", HkdfSha3, Ed25519, "test", 0),
        spec("age-x25519/hkdf-sha3-512", HkdfSha3, AgeX25519, "test", 0),
        spec("symmetric/hkdf-sha3-512", HkdfSha3, Symmetric, "test", 0),
        // ML-KEM profiles (SHAKE256 only).
        spec("mlkem512/shake256", Shake256, MlKem512, "test", 0),
        spec("mlkem768/shake256", Shake256, MlKem768, "test", 0),
        spec("mlkem1024/shake256", Shake256, MlKem1024, "test", 0),
        // Domain separation: different purpose and index must change output.
        spec(
            "x25519/hkdf-sha512/wg-home-idx1",
            HkdfSha512,
            X25519,
            "wg-home",
            1,
        ),
    ];

    // Raw profile across all pipelines and lengths crossing the 64-byte block
    // boundary (exercises the HKDF counter loop and SHAKE squeeze).
    for &(pipeline, label) in &[
        (HkdfSha512, "hkdf-sha512"),
        (HkdfSha3, "hkdf-sha3-512"),
        (Shake256, "shake256"),
    ] {
        for &len in &[1usize, 32, 64, 65, 200] {
            let mut s = spec(&format!("raw/{label}/len{len}"), pipeline, Raw, "test", 0);
            s.length = Some(len);
            v.push(s);
        }
    }

    // Longer (layered-style) IKM through the core.
    let mut layered = spec("raw/hkdf-sha512/layered-ikm", HkdfSha512, Raw, "test", 0);
    layered.ikm = &IKM_52;
    layered.length = Some(32);
    v.push(layered);

    // Passphrase cascade (Argon2id). Only with the argon2 feature.
    #[cfg(feature = "argon2")]
    {
        let mut p = spec(
            "x25519/hkdf-sha512/passphrase",
            HkdfSha512,
            X25519,
            "test",
            0,
        );
        p.passphrase = Some(PASSPHRASE);
        v.push(p);
    }

    v
}

fn compute(spec: &Spec) -> Vector {
    let ikm = Ikm::new(spec.ikm.to_vec()).expect("ikm");
    #[allow(unused_mut)]
    let mut master = extract(&ikm, spec.pipeline).expect("extract");

    #[cfg(feature = "argon2")]
    if let Some(pass) = spec.passphrase {
        use ykdf_core::{Argon2Params, cascade_passphrase, stretch_passphrase};
        let stretched =
            stretch_passphrase(pass.as_bytes(), &Argon2Params::default()).expect("stretch");
        master = cascade_passphrase(&master, &stretched, spec.pipeline).expect("cascade");
    }

    let len = spec.length.unwrap_or_else(|| spec.profile.expand_len());
    let ctx =
        Context::with_pipeline(spec.profile, spec.pipeline, spec.purpose, spec.index).expect("ctx");
    let expanded = expand(&master, &ctx, len).expect("expand");

    let derived = if spec.profile == Profile::Raw {
        derive_raw(&master, &ctx, len).expect("derive_raw")
    } else {
        derive(&master, &ctx).expect("derive")
    };

    let output = match &derived {
        ProfileOutput::SecretKey(k) => Output {
            secret_key_hex: Some(hex::encode(k.0)),
            ..Output::default()
        },
        ProfileOutput::Ed25519Seed(s) => Output {
            ed25519_seed_hex: Some(hex::encode(s.0)),
            ..Output::default()
        },
        ProfileOutput::AgeIdentity(a) => Output {
            age_identity: Some(a.identity.clone()),
            age_secret_key_hex: Some(hex::encode(a.secret_key)),
            ..Output::default()
        },
        ProfileOutput::MlKemKeypair(kp) => Output {
            mlkem_ek_hex: Some(hex::encode(&kp.encapsulation_key)),
            mlkem_dk_hex: Some(hex::encode(&kp.decapsulation_key)),
            ..Output::default()
        },
        ProfileOutput::Raw(r) => Output {
            raw_hex: Some(hex::encode(&r.0)),
            ..Output::default()
        },
    };

    Vector {
        name: spec.name.clone(),
        pipeline: spec.pipeline.as_str().to_string(),
        profile: spec.profile.as_str().to_string(),
        purpose: spec.purpose.to_string(),
        index: spec.index,
        length: spec.length,
        ikm_hex: hex::encode(spec.ikm),
        passphrase: spec.passphrase.map(str::to_string),
        master_key_hex: hex::encode(master.as_bytes()),
        expanded_hex: hex::encode(expanded.as_bytes()),
        output,
    }
}

fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/v1.json")
}

fn load_committed() -> VectorFile {
    let json = std::fs::read_to_string(vectors_path())
        .expect("vectors/v1.json must exist; run the `regenerate` test to create it");
    serde_json::from_str(&json).expect("vectors/v1.json must be valid JSON")
}

#[test]
fn vectors_match_committed() {
    let committed = load_committed();
    assert_eq!(committed.version, "v1");

    let mut expected: Vec<Vector> = matrix().iter().map(compute).collect();
    let mut got = committed.vectors;

    // Without the argon2 feature, passphrase vectors cannot be recomputed here;
    // drop them from the committed set so the rest still verify standalone.
    if cfg!(not(feature = "argon2")) {
        got.retain(|v| v.passphrase.is_none());
    }

    expected.sort_by(|a, b| a.name.cmp(&b.name));
    got.sort_by(|a, b| a.name.cmp(&b.name));

    assert_eq!(
        got.len(),
        expected.len(),
        "vector count mismatch: committed has names {:?}, computed has {:?}",
        got.iter().map(|v| &v.name).collect::<Vec<_>>(),
        expected.iter().map(|v| &v.name).collect::<Vec<_>>()
    );
    for (g, e) in got.iter().zip(expected.iter()) {
        assert_eq!(g, e, "vector `{}` drifted from committed value", e.name);
    }
}

/// Independent RFC 5869 cross-check: recompute the HKDF master key and expand
/// output with the `hkdf` crate and require equality with our implementation.
/// SHAKE256 has no HKDF-crate analogue and is verified structurally elsewhere.
#[test]
fn hkdf_reference_cross_check() {
    use hkdf::Hkdf;
    use sha2::Sha512;
    use sha3::Sha3_512;

    let mut checked = 0;
    for spec in matrix() {
        if spec.passphrase.is_some() {
            continue; // cascade is not a plain HKDF-extract
        }
        let len = spec.length.unwrap_or_else(|| spec.profile.expand_len());
        let ikm = Ikm::new(spec.ikm.to_vec()).unwrap();
        let our_mk = extract(&ikm, spec.pipeline).unwrap();
        let ctx =
            Context::with_pipeline(spec.profile, spec.pipeline, spec.purpose, spec.index).unwrap();
        let info = ctx.kdf_info(len);
        let our_exp = expand(&our_mk, &ctx, len).unwrap();

        match spec.pipeline {
            Pipeline::HkdfSha512 => {
                let (prk, hk) = Hkdf::<Sha512>::extract(Some(EXTRACT_SALT), spec.ikm);
                assert_eq!(prk.as_slice(), our_mk.as_bytes(), "{}: extract", spec.name);
                let mut okm = vec![0u8; len];
                hk.expand(&info, &mut okm).unwrap();
                assert_eq!(okm, our_exp.as_bytes(), "{}: expand", spec.name);
                checked += 1;
            }
            Pipeline::HkdfSha3 => {
                let (prk, hk) = Hkdf::<Sha3_512>::extract(Some(EXTRACT_SALT), spec.ikm);
                assert_eq!(prk.as_slice(), our_mk.as_bytes(), "{}: extract", spec.name);
                let mut okm = vec![0u8; len];
                hk.expand(&info, &mut okm).unwrap();
                assert_eq!(okm, our_exp.as_bytes(), "{}: expand", spec.name);
                checked += 1;
            }
            Pipeline::Shake256 => {}
        }
    }
    assert!(checked > 0, "expected some HKDF vectors to cross-check");
}

/// Rewrite `vectors/v1.json` from the current code. Ignored by default; run
/// intentionally with:
///   cargo test -p ykdf-core --features argon2 --test vectors regenerate -- --ignored
#[test]
#[ignore = "regenerates the committed golden vectors; run intentionally"]
fn regenerate() {
    #[cfg(not(feature = "argon2"))]
    panic!("run regenerate with --features argon2 so passphrase vectors are included");

    #[cfg(feature = "argon2")]
    {
        write_vectors();
    }
}

#[cfg(feature = "argon2")]
fn write_vectors() {
    let file = VectorFile {
        version: "v1".to_string(),
        description:
            "YKDF v1 golden vectors. Core derivation only (IKM -> extract -> expand -> derive). \
             See docs/SPEC.md. Regenerate with the `regenerate` test."
                .to_string(),
        vectors: matrix().iter().map(compute).collect(),
    };
    let mut json = serde_json::to_string_pretty(&file).expect("serialize");
    json.push('\n');
    std::fs::write(vectors_path(), json).expect("write vectors/v1.json");
}
