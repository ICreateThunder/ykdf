//! dudect-style timing-leakage measurement for the core derivation paths.
//!
//! Each benchmark times an operation over two input classes — a fixed secret
//! (`Class::Left`) and a fresh random secret (`Class::Right`) — and reports a
//! Welch t-statistic. A small |t| (roughly < 10) across long runs indicates no
//! detectable input-dependent timing; a large, growing |t| indicates a leak.
//!
//! Scope: the deterministic core (extract, expand, profile post-processing),
//! whose timing must not depend on secret bytes. The Argon2id passphrase path
//! is deliberately NOT measured here: Argon2id is a memory-hard function with
//! intentionally data-dependent access patterns, so it would report expected
//! "leakage" that is by design, not a flaw.
//!
//! Run: `cargo run --release` (in this directory). This is a manual activity,
//! not a CI gate — dudect is statistical and runs until interrupted.

use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rand::{Rng, RngExt};
use ykdf_core::{derive, extract, Context, Ikm, Pipeline, Profile};

const ITERS: usize = 100_000;

/// Build `ITERS` 32-byte inputs, each either the fixed all-zero secret (Left)
/// or a fresh random secret (Right), paired with its class.
fn classed_inputs(rng: &mut BenchRng) -> Vec<(Class, [u8; 32])> {
    let mut out = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        if rng.random::<bool>() {
            out.push((Class::Left, [0u8; 32]));
        } else {
            let mut secret = [0u8; 32];
            rng.fill_bytes(&mut secret);
            out.push((Class::Right, secret));
        }
    }
    out
}

/// `extract` (HMAC-SHA512 over the secret IKM) must be constant-time in the IKM.
fn extract_is_secret_independent(runner: &mut CtRunner, rng: &mut BenchRng) {
    for (class, secret) in classed_inputs(rng) {
        let ikm = Ikm::new(secret.to_vec()).unwrap();
        runner.run_one(class, || {
            let _ = extract(&ikm, Pipeline::HkdfSha512).unwrap();
        });
    }
}

/// The full `derive` (extract is done up front; this times expand + the x25519
/// clamp over a secret master key) must be constant-time in the master key.
fn derive_is_secret_independent(runner: &mut CtRunner, rng: &mut BenchRng) {
    let ctx = Context::new(Profile::X25519, "timing", 0).unwrap();
    let prepared: Vec<(Class, _)> = classed_inputs(rng)
        .into_iter()
        .map(|(class, secret)| {
            let ikm = Ikm::new(secret.to_vec()).unwrap();
            (class, extract(&ikm, Pipeline::HkdfSha512).unwrap())
        })
        .collect();

    for (class, master) in prepared {
        runner.run_one(class, || {
            let _ = derive(&master, &ctx).unwrap();
        });
    }
}

ctbench_main!(extract_is_secret_independent, derive_is_secret_independent);
