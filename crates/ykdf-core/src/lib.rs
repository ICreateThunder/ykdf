mod error;

pub mod context;
pub mod derive;
pub mod expand;
pub mod extract;
pub mod pipeline;
pub mod profile;
pub mod types;

#[cfg(feature = "argon2")]
pub mod stretch;

pub use self::context::Context;
pub use self::derive::{derive, derive_raw};
pub use self::error::{Error, Result};
pub use self::extract::{cascade, extract};
pub use self::pipeline::Pipeline;
pub use self::profile::{Profile, ProfileOutput};
pub use self::types::{ExpandedBytes, Ikm, MasterKey};

#[cfg(feature = "argon2")]
pub use self::stretch::{Argon2Params, StretchedPassphrase, stretch_passphrase};
