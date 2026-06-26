//! Platform-independent key derivation for YKDF.
//!
//! `ykdf-core` turns input key material into purpose-specific keys with an
//! extract-then-expand construction (HKDF or SHAKE256). It is deterministic,
//! does no I/O, and uses no randomness: the same inputs always yield the same
//! keys. Reading secrets from a `YubiKey` lives in separate crates; this crate is
//! what the CLI, JNI, and WASM wrappers bind to.
//!
//! The byte-level format is specified in `docs/SPEC.md` and frozen as `v1`.

#![deny(missing_docs)]

// Implementation modules are private; the public API is exactly the curated
// re-exports below. This keeps `ykdf-core`'s surface minimal and stable (it is
// what the JNI/WASM wrappers bind to) and leaves the internals free to change
// without a SemVer break.
mod context;
mod derive;
mod error;
mod expand;
mod extract;
mod pipeline;
mod profile;
mod types;

#[cfg(feature = "argon2")]
mod stretch;

pub use self::context::Context;
pub use self::derive::{derive, derive_raw};
pub use self::error::{Error, Result};
pub use self::expand::expand;
pub use self::extract::{cascade, extract};
pub use self::pipeline::Pipeline;
pub use self::profile::{
    AgeIdentityBytes, Ed25519SeedBytes, MlDsaKeypairBytes, MlKemKeypairBytes, Profile,
    ProfileOutput, RawBytes, SecretKeyBytes,
};
pub use self::types::{ExpandedBytes, Ikm, MIN_IKM_LEN, MasterKey};

#[cfg(feature = "argon2")]
pub use self::stretch::{
    Argon2Params, StretchedPassphrase, cascade_passphrase, stretch_passphrase,
};
