use ykdf_core::{
    Context, Ikm, Pipeline, Profile, ProfileOutput, cascade, derive, derive_raw, extract,
};

/// Fixed test IKM simulating 32 bytes of ECDH output.
fn test_ikm() -> Ikm {
    Ikm::new(vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ])
    .unwrap()
}

#[test]
fn ikm_rejects_short_input() {
    assert!(Ikm::new(vec![0u8; 15]).is_err());
    assert!(Ikm::new(vec![0u8; 16]).is_ok());
}

#[test]
fn hkdf_extract_is_deterministic() {
    let ikm = test_ikm();
    let mk1 = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    let mk2 = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    assert_eq!(mk1.as_bytes(), mk2.as_bytes());
}

#[test]
fn sponge_extract_is_deterministic() {
    let ikm = test_ikm();
    let mk1 = extract(&ikm, Pipeline::Shake256).unwrap();
    let mk2 = extract(&ikm, Pipeline::Shake256).unwrap();
    assert_eq!(mk1.as_bytes(), mk2.as_bytes());
}

#[test]
fn different_pipelines_produce_different_master_keys() {
    let ikm = test_ikm();
    let sha512 = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    let sha3 = extract(&ikm, Pipeline::HkdfSha3).unwrap();
    let sponge = extract(&ikm, Pipeline::Shake256).unwrap();
    assert_ne!(sha512.as_bytes(), sponge.as_bytes());
    assert_ne!(sha512.as_bytes(), sha3.as_bytes());
    assert_ne!(sha3.as_bytes(), sponge.as_bytes());
}

#[test]
fn hkdf_sha3_extract_is_deterministic() {
    let ikm = test_ikm();
    let mk1 = extract(&ikm, Pipeline::HkdfSha3).unwrap();
    let mk2 = extract(&ikm, Pipeline::HkdfSha3).unwrap();
    assert_eq!(mk1.as_bytes(), mk2.as_bytes());
}

#[test]
fn x25519_derives_over_sha3_pipeline() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::HkdfSha3).unwrap();
    let ctx = Context::with_pipeline(Profile::X25519, Pipeline::HkdfSha3, "wg-home", 0).unwrap();

    let out = derive(&mk, &ctx).unwrap();
    match &out {
        ProfileOutput::SecretKey(k) => {
            // Clamped, and distinct from the SHA-512 pipeline output.
            assert_eq!(k.0[0] & 0x07, 0);
            let mk512 = extract(&ikm, Pipeline::HkdfSha512).unwrap();
            let ctx512 = Context::new(Profile::X25519, "wg-home", 0).unwrap();
            let out512 = derive(&mk512, &ctx512).unwrap();
            match &out512 {
                ProfileOutput::SecretKey(k512) => assert_ne!(k.0, k512.0),
                _ => panic!("expected SecretKey output"),
            }
        }
        _ => panic!("expected SecretKey output"),
    }
}

#[test]
fn x25519_derive_is_deterministic() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    let ctx = Context::new(Profile::X25519, "wg-home", 0).unwrap();

    let out1 = derive(&mk, &ctx).unwrap();
    let out2 = derive(&mk, &ctx).unwrap();

    match (&out1, &out2) {
        (ProfileOutput::SecretKey(a), ProfileOutput::SecretKey(b)) => {
            assert_eq!(a.0, b.0);
            // Verify clamping
            assert_eq!(a.0[0] & 0x07, 0);
            assert_eq!(a.0[31] & 0x80, 0);
            assert_ne!(a.0[31] & 0x40, 0);
        }
        _ => panic!("expected SecretKey output"),
    }
}

#[test]
fn different_purposes_produce_different_keys() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::HkdfSha512).unwrap();

    let ctx1 = Context::new(Profile::X25519, "wg-home", 0).unwrap();
    let ctx2 = Context::new(Profile::X25519, "wg-office", 0).unwrap();

    let out1 = derive(&mk, &ctx1).unwrap();
    let out2 = derive(&mk, &ctx2).unwrap();

    match (&out1, &out2) {
        (ProfileOutput::SecretKey(a), ProfileOutput::SecretKey(b)) => {
            assert_ne!(a.0, b.0);
        }
        _ => panic!("expected SecretKey output"),
    }
}

#[test]
fn different_indices_produce_different_keys() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::HkdfSha512).unwrap();

    let ctx0 = Context::new(Profile::X25519, "wg-home", 0).unwrap();
    let ctx1 = Context::new(Profile::X25519, "wg-home", 1).unwrap();

    let out0 = derive(&mk, &ctx0).unwrap();
    let out1 = derive(&mk, &ctx1).unwrap();

    match (&out0, &out1) {
        (ProfileOutput::SecretKey(a), ProfileOutput::SecretKey(b)) => {
            assert_ne!(a.0, b.0);
        }
        _ => panic!("expected SecretKey output"),
    }
}

#[test]
fn ed25519_derive_produces_seed() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    let ctx = Context::new(Profile::Ed25519, "git-signing", 0).unwrap();

    let out = derive(&mk, &ctx).unwrap();
    assert!(matches!(out, ProfileOutput::Ed25519Seed(_)));
}

#[test]
fn symmetric_derive_produces_key() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    let ctx = Context::new(Profile::Symmetric, "disk-encryption", 0).unwrap();

    let out = derive(&mk, &ctx).unwrap();
    assert!(matches!(out, ProfileOutput::SecretKey(_)));
}

#[test]
fn age_derive_produces_identity() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    let ctx = Context::new(Profile::AgeX25519, "backup", 0).unwrap();

    let out = derive(&mk, &ctx).unwrap();
    match &out {
        ProfileOutput::AgeIdentity(age) => {
            assert!(age.identity.starts_with("AGE-SECRET-KEY-1"));
        }
        _ => panic!("expected AgeIdentity output"),
    }
}

#[test]
fn mlkem768_derive_produces_keypair() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::Shake256).unwrap();
    let ctx = Context::new(Profile::MlKem768, "email", 0).unwrap();

    let out = derive(&mk, &ctx).unwrap();
    match &out {
        ProfileOutput::MlKemKeypair(kp) => {
            assert_eq!(kp.encapsulation_key.len(), 1184);
            // Seed-based representation (64 bytes), not expanded dk
            assert_eq!(kp.decapsulation_key.len(), 64);
        }
        _ => panic!("expected MlKemKeypair output"),
    }
}

#[test]
fn mlkem768_derive_is_deterministic() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::Shake256).unwrap();
    let ctx = Context::new(Profile::MlKem768, "email", 0).unwrap();

    let out1 = derive(&mk, &ctx).unwrap();
    let out2 = derive(&mk, &ctx).unwrap();

    match (&out1, &out2) {
        (ProfileOutput::MlKemKeypair(a), ProfileOutput::MlKemKeypair(b)) => {
            assert_eq!(a.encapsulation_key, b.encapsulation_key);
            assert_eq!(a.decapsulation_key, b.decapsulation_key);
        }
        _ => panic!("expected MlKemKeypair output"),
    }
}

#[test]
fn raw_derive_produces_bytes() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    let ctx = Context::new(Profile::Raw, "test", 0).unwrap();

    let out = derive(&mk, &ctx).unwrap();
    match &out {
        ProfileOutput::Raw(raw) => {
            assert_eq!(raw.0.len(), 32);
        }
        _ => panic!("expected Raw output"),
    }
}

#[test]
fn raw_derive_variable_length() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    let ctx = Context::new(Profile::Raw, "test", 0).unwrap();

    for len in [16, 32, 48, 64, 128] {
        let out = derive_raw(&mk, &ctx, len).unwrap();
        match &out {
            ProfileOutput::Raw(raw) => assert_eq!(raw.0.len(), len),
            _ => panic!("expected Raw output"),
        }
    }
}

#[test]
fn raw_derive_rejects_zero_length() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    let ctx = Context::new(Profile::Raw, "test", 0).unwrap();
    assert!(derive_raw(&mk, &ctx, 0).is_err());
}

#[test]
fn raw_derive_rejects_non_raw_profile() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    let ctx = Context::new(Profile::X25519, "test", 0).unwrap();
    assert!(derive_raw(&mk, &ctx, 32).is_err());
}

#[test]
fn raw_derive_default_still_32_bytes() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    let ctx = Context::new(Profile::Raw, "test", 0).unwrap();
    let out = derive(&mk, &ctx).unwrap();
    match &out {
        ProfileOutput::Raw(raw) => assert_eq!(raw.0.len(), 32),
        _ => panic!("expected Raw output"),
    }
}

#[test]
fn cascade_is_deterministic() {
    let ikm = test_ikm();
    let early = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    let additional = b"additional-entropy-source";

    let mk1 = cascade(&early, additional, Pipeline::HkdfSha512).unwrap();
    let mk2 = cascade(&early, additional, Pipeline::HkdfSha512).unwrap();
    assert_eq!(mk1.as_bytes(), mk2.as_bytes());
}

#[test]
fn cascade_differs_from_early_secret() {
    let ikm = test_ikm();
    let early = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    let additional = b"additional-entropy-source";

    let cascaded = cascade(&early, additional, Pipeline::HkdfSha512).unwrap();
    assert_ne!(early.as_bytes(), cascaded.as_bytes());
}

#[test]
fn cascade_different_additional_ikm_differs() {
    let ikm = test_ikm();
    let early = extract(&ikm, Pipeline::HkdfSha512).unwrap();

    let mk1 = cascade(&early, b"factor-a", Pipeline::HkdfSha512).unwrap();
    let mk2 = cascade(&early, b"factor-b", Pipeline::HkdfSha512).unwrap();
    assert_ne!(mk1.as_bytes(), mk2.as_bytes());
}

#[test]
fn cascade_sponge_is_deterministic() {
    let ikm = test_ikm();
    let early = extract(&ikm, Pipeline::Shake256).unwrap();
    let additional = b"passphrase-stretched";

    let mk1 = cascade(&early, additional, Pipeline::Shake256).unwrap();
    let mk2 = cascade(&early, additional, Pipeline::Shake256).unwrap();
    assert_eq!(mk1.as_bytes(), mk2.as_bytes());
}

#[cfg(feature = "argon2")]
mod argon2_tests {
    use ykdf_core::{Argon2Params, stretch_passphrase};

    #[test]
    fn stretch_is_deterministic() {
        let params = Argon2Params::default();
        let out1 = stretch_passphrase(b"test-passphrase", &params).unwrap();
        let out2 = stretch_passphrase(b"test-passphrase", &params).unwrap();
        assert_eq!(out1.as_bytes(), out2.as_bytes());
        assert_eq!(out1.as_bytes().len(), 64);
    }

    #[test]
    fn different_passphrases_differ() {
        let params = Argon2Params::default();
        let out1 = stretch_passphrase(b"passphrase-a", &params).unwrap();
        let out2 = stretch_passphrase(b"passphrase-b", &params).unwrap();
        assert_ne!(out1.as_bytes(), out2.as_bytes());
    }

    #[test]
    fn custom_salt_differs_from_default() {
        let default_params = Argon2Params::default();
        let custom_params = Argon2Params::default().with_salt(b"custom-salt-value".to_vec());
        let out1 = stretch_passphrase(b"test", &default_params).unwrap();
        let out2 = stretch_passphrase(b"test", &custom_params).unwrap();
        assert_ne!(out1.as_bytes(), out2.as_bytes());
    }

    #[test]
    fn full_cascade_with_argon2() {
        use ykdf_core::{Context, Pipeline, Profile, ProfileOutput, cascade, derive, extract};

        let ikm = super::test_ikm();
        let early = extract(&ikm, Pipeline::HkdfSha512).unwrap();

        let params = Argon2Params::default();
        let stretched = stretch_passphrase(b"my-passphrase", &params).unwrap();

        let master = cascade(&early, stretched.as_bytes(), Pipeline::HkdfSha512).unwrap();
        let ctx = Context::new(Profile::X25519, "wg-home", 0).unwrap();
        let out = derive(&master, &ctx).unwrap();
        assert!(matches!(out, ProfileOutput::SecretKey(_)));
    }
}
