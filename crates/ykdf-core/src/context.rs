use core::fmt;
use core::str::FromStr;

use crate::Result;
use crate::error::Error;
use crate::pipeline::Pipeline;
use crate::profile::Profile;

/// Version identifier for the derivation scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => write!(f, "v1"),
        }
    }
}

/// Validated purpose string. Lowercase ASCII alphanumeric plus hyphens, 1-64 chars.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Purpose(String);

impl Purpose {
    /// # Errors
    ///
    /// Returns `Error::InvalidPurpose` if the string is empty, exceeds 64
    /// characters, contains non-lowercase-alphanumeric/hyphen characters,
    /// or starts/ends with a hyphen.
    pub fn new(s: &str) -> Result<Self> {
        if s.is_empty() || s.len() > 64 {
            return Err(Error::InvalidPurpose {
                purpose: s.to_owned(),
            });
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Error::InvalidPurpose {
                purpose: s.to_owned(),
            });
        }
        if s.starts_with('-') || s.ends_with('-') {
            return Err(Error::InvalidPurpose {
                purpose: s.to_owned(),
            });
        }
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Complete derivation context.
///
/// Encodes the full derivation recipe as a self-describing string:
/// `ykdf:v1:<pipeline>:<profile>:<purpose>:<index>`
///
/// Validated at construction - if you hold a `Context`, it is well-formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    version: Version,
    pipeline: Pipeline,
    profile: Profile,
    purpose: Purpose,
    index: u32,
}

impl Context {
    /// Create a new context with the profile's default pipeline.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPurpose` if the purpose string is invalid.
    pub fn new(profile: Profile, purpose: &str, index: u32) -> Result<Self> {
        let purpose = Purpose::new(purpose)?;
        Ok(Self {
            version: Version::V1,
            pipeline: profile.default_pipeline(),
            profile,
            purpose,
            index,
        })
    }

    /// Create a context with an explicit pipeline override.
    ///
    /// The pipeline must be one the profile accepts (see `Profile::accepts`).
    ///
    /// # Errors
    ///
    /// Returns `Error::PipelineMismatch` if the profile does not accept the
    /// pipeline.
    /// Returns `Error::InvalidPurpose` if the purpose string is invalid.
    pub fn with_pipeline(
        profile: Profile,
        pipeline: Pipeline,
        purpose: &str,
        index: u32,
    ) -> Result<Self> {
        if !profile.accepts(pipeline) {
            return Err(Error::PipelineMismatch {
                profile: profile.as_str(),
                pipeline: pipeline.as_str(),
            });
        }
        let purpose = Purpose::new(purpose)?;
        Ok(Self {
            version: Version::V1,
            pipeline,
            profile,
            purpose,
            index,
        })
    }

    /// Returns the KDF pipeline.
    pub fn pipeline(&self) -> Pipeline {
        self.pipeline
    }

    /// Returns the key profile.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// Returns the purpose label.
    pub fn purpose(&self) -> &str {
        self.purpose.as_str()
    }

    /// Returns the key index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Canonical KDF input binding the full derivation context and output length.
    ///
    /// Appends the output length as a final field so that requests for
    /// different lengths under the same context produce independent key
    /// streams. Both pipelines have the prefix property (HKDF-Expand and
    /// SHAKE output for length `a` is a prefix of the output for length
    /// `b > a`); binding the length here makes that property unreachable.
    /// No field can contain a colon, so the encoding stays unambiguous.
    pub fn kdf_info(&self, len: usize) -> Vec<u8> {
        format!("{self}:{len}").into_bytes()
    }
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ykdf:{}:{}:{}:{}:{}",
            self.version, self.pipeline, self.profile, self.purpose, self.index
        )
    }
}

impl FromStr for Context {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(Error::InvalidContext {
                input: s.to_owned(),
            });
        }

        if parts[0] != "ykdf" {
            return Err(Error::InvalidContext {
                input: s.to_owned(),
            });
        }

        if parts[1] != "v1" {
            return Err(Error::InvalidContext {
                input: s.to_owned(),
            });
        }

        let pipeline =
            Pipeline::from_str_label(parts[2]).ok_or_else(|| Error::InvalidPipeline {
                pipeline: parts[2].to_owned(),
            })?;

        let profile = Profile::from_str_label(parts[3]).ok_or_else(|| Error::InvalidProfile {
            profile: parts[3].to_owned(),
        })?;

        let purpose = Purpose::new(parts[4])?;

        let index: u32 = parts[5].parse().map_err(|_| Error::InvalidIndex {
            index: parts[5].to_owned(),
        })?;

        if !profile.accepts(pipeline) {
            return Err(Error::PipelineMismatch {
                profile: profile.as_str(),
                pipeline: pipeline.as_str(),
            });
        }

        Ok(Self {
            version: Version::V1,
            pipeline,
            profile,
            purpose,
            index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let ctx = Context::new(Profile::X25519, "wg-home", 0).unwrap();
        let s = ctx.to_string();
        assert_eq!(s, "ykdf:v1:hkdf-sha512:x25519:wg-home:0");
        let parsed: Context = s.parse().unwrap();
        assert_eq!(ctx, parsed);
    }

    #[test]
    fn round_trip_sponge() {
        let ctx = Context::new(Profile::MlKem768, "email", 3).unwrap();
        let s = ctx.to_string();
        assert_eq!(s, "ykdf:v1:shake256:mlkem768:email:3");
        let parsed: Context = s.parse().unwrap();
        assert_eq!(ctx, parsed);
    }

    #[test]
    fn classical_profile_accepts_sha3() {
        let ctx =
            Context::with_pipeline(Profile::X25519, Pipeline::HkdfSha3, "wg-home", 0).unwrap();
        let s = ctx.to_string();
        assert_eq!(s, "ykdf:v1:hkdf-sha3-512:x25519:wg-home:0");
        let parsed: Context = s.parse().unwrap();
        assert_eq!(ctx, parsed);
    }

    #[test]
    fn raw_accepts_any_pipeline() {
        assert!(Context::with_pipeline(Profile::Raw, Pipeline::HkdfSha512, "test", 0).is_ok());
        assert!(Context::with_pipeline(Profile::Raw, Pipeline::HkdfSha3, "test", 0).is_ok());
        assert!(Context::with_pipeline(Profile::Raw, Pipeline::Shake256, "test", 0).is_ok());
    }

    #[test]
    fn pipeline_mismatch_rejected() {
        // x25519 is classical: SHAKE256 is not accepted.
        assert!(Context::with_pipeline(Profile::X25519, Pipeline::Shake256, "test", 0).is_err());
        // mlkem requires SHAKE256: an HKDF variant is not accepted.
        assert!(
            Context::with_pipeline(Profile::MlKem768, Pipeline::HkdfSha512, "test", 0).is_err()
        );
    }

    #[test]
    fn invalid_purpose_chars() {
        assert!(Context::new(Profile::X25519, "UPPER", 0).is_err());
        assert!(Context::new(Profile::X25519, "has space", 0).is_err());
        assert!(Context::new(Profile::X25519, "under_score", 0).is_err());
    }

    #[test]
    fn invalid_purpose_boundaries() {
        assert!(Context::new(Profile::X25519, "", 0).is_err());
        assert!(Context::new(Profile::X25519, "-leading", 0).is_err());
        assert!(Context::new(Profile::X25519, "trailing-", 0).is_err());
        let long = "a".repeat(65);
        assert!(Context::new(Profile::X25519, &long, 0).is_err());
    }

    #[test]
    fn valid_purposes() {
        assert!(Context::new(Profile::X25519, "wg-home", 0).is_ok());
        assert!(Context::new(Profile::X25519, "ssh-github", 0).is_ok());
        assert!(Context::new(Profile::X25519, "a", 0).is_ok());
        assert!(Context::new(Profile::X25519, "test123", 0).is_ok());
        let max = "a".repeat(64);
        assert!(Context::new(Profile::X25519, &max, 0).is_ok());
    }

    #[test]
    fn parse_rejects_disallowed_combination() {
        // Valid pipeline and profile *names*, but the profile does not accept
        // the pipeline -> PipelineMismatch (distinct from an unknown-name error).
        assert!("ykdf:v1:shake256:x25519:test:0".parse::<Context>().is_err());
        assert!(
            "ykdf:v1:hkdf-sha512:mlkem768:test:0"
                .parse::<Context>()
                .is_err()
        );
    }

    #[test]
    fn accessors_return_fields() {
        let ctx = Context::new(Profile::Ed25519, "git-signing", 7).unwrap();
        assert_eq!(ctx.profile(), Profile::Ed25519);
        assert_eq!(ctx.pipeline(), Pipeline::HkdfSha512);
        assert_eq!(ctx.purpose(), "git-signing");
        assert_eq!(ctx.index(), 7);
    }

    #[test]
    fn parse_invalid_format() {
        assert!("not:enough:parts".parse::<Context>().is_err());
        assert!(
            "ykdf:v2:hkdf-sha512:x25519:test:0"
                .parse::<Context>()
                .is_err()
        );
        assert!(
            "wrong:v1:hkdf-sha512:x25519:test:0"
                .parse::<Context>()
                .is_err()
        );
        assert!(
            "ykdf:v1:hkdf-sha512:x25519:test:abc"
                .parse::<Context>()
                .is_err()
        );
        assert!("ykdf:v1:bad:x25519:test:0".parse::<Context>().is_err());
        assert!("ykdf:v1:hkdf-sha512:bad:test:0".parse::<Context>().is_err());
    }
}
