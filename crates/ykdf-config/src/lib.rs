//! Named derivation recipes: a labels-only TOML catalogue shared by the CLI and
//! the Android app so both resolve a recipe to the same derivation parameters.
//!
//! A recipe is pure convenience over the `profile` / `purpose` / `pipeline` /
//! `index` a caller could pass by hand. Recipes never hold secrets and never
//! gate re-derivation, so the file is safe to commit to dotfiles, sync, or share
//! as a QR code. Parsing and validation live here (not in `ykdf-core`) so the
//! crypto core stays free of `serde`/`toml`, and every consumer validates a
//! recipe the same way -- by resolving it through the same [`ykdf_core::Context`]
//! a manual derivation would build.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use ykdf_core::{Context, Pipeline, Profile};

/// A parsed recipe catalogue: optional shared defaults plus named recipes.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalogue {
    #[serde(default)]
    defaults: Defaults,
    #[serde(default, rename = "recipe")]
    recipes: BTreeMap<String, RawRecipe>,
}

/// Values applied to every recipe unless the recipe overrides them.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Defaults {
    pipeline: Option<String>,
    index: Option<u32>,
    layered: Option<bool>,
}

/// A recipe exactly as written in the file, before defaults and validation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecipe {
    profile: String,
    purpose: Option<String>,
    pipeline: Option<String>,
    index: Option<u32>,
    layered: Option<bool>,
    description: Option<String>,
}

/// A recipe resolved against `[defaults]` and validated, ready to drive a
/// derivation. `pipeline` is `None` when the profile's default should apply, so
/// a caller can still let an explicit `--pipeline` flag take precedence.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The key profile.
    pub profile: Profile,
    /// An explicit pipeline override, or `None` to use the profile default.
    pub pipeline: Option<Pipeline>,
    /// The derivation purpose (the recipe's `purpose`, or its name by default).
    pub purpose: String,
    /// The rotation index.
    pub index: u32,
    /// Whether to use layered mode (PIV + HMAC).
    pub layered: bool,
    /// Optional human description, shown by `recipe list`.
    pub description: Option<String>,
}

impl Catalogue {
    /// Load the catalogue, resolving the path from (in order) `explicit`, the
    /// `YKDF_CONFIG` environment variable, then the XDG default
    /// (`$XDG_CONFIG_HOME/ykdf/config.toml`, else `$HOME/.config/ykdf/config.toml`).
    ///
    /// A missing file at the *default* location is not an error -- it is an empty
    /// catalogue. A file requested *explicitly* (via `explicit` or `YKDF_CONFIG`)
    /// that does not exist is an error, since the caller named it deliberately.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] on a read failure (including an explicitly
    /// requested file that is missing) and [`ConfigError::Parse`] on malformed
    /// TOML.
    pub fn load(explicit: Option<&Path>) -> Result<Self, ConfigError> {
        let (path, requested) = match explicit {
            Some(p) => (p.to_path_buf(), true),
            None => match std::env::var_os("YKDF_CONFIG").filter(|v| !v.is_empty()) {
                Some(v) => (PathBuf::from(v), true),
                None => match default_path() {
                    Some(p) => (p, false),
                    None => return Ok(Self::default()),
                },
            },
        };

        match std::fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text, Some(&path)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !requested => Ok(Self::default()),
            Err(source) => Err(ConfigError::Io { path, source }),
        }
    }

    /// Parse a catalogue from a TOML string. `path`, when known, is used only to
    /// give parse errors a location.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Parse`] if the TOML is malformed or contains an
    /// unknown field.
    pub fn parse(text: &str, path: Option<&Path>) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.map(Path::to_path_buf),
            source,
        })
    }

    /// The recipe names and their descriptions, in name order, for `recipe list`.
    pub fn recipes(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.recipes
            .iter()
            .map(|(name, r)| (name.as_str(), r.description.as_deref()))
    }

    /// Resolve a recipe by name against `[defaults]`, validating it exactly as a
    /// manual derivation would be validated.
    ///
    /// Precedence within the file is recipe field, then `[defaults]`, then the
    /// profile's built-in default. An omitted `purpose` defaults to the recipe
    /// name. Callers layer their own explicit flags on top of the result.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::UnknownRecipe`] if no such recipe exists,
    /// [`ConfigError::UnknownProfile`] / [`ConfigError::UnknownPipeline`] for an
    /// unrecognised label, [`ConfigError::PipelineNotAccepted`] if the profile
    /// rejects the pipeline, and [`ConfigError::InvalidRecipe`] if the resulting
    /// purpose/index is not a valid derivation context (e.g. a recipe name used
    /// as a purpose that is not `[a-z0-9-]`, 1..=64 chars).
    pub fn resolve(&self, name: &str) -> Result<Resolved, ConfigError> {
        let raw = self
            .recipes
            .get(name)
            .ok_or_else(|| ConfigError::UnknownRecipe(name.to_owned()))?;

        let profile =
            Profile::from_str_label(&raw.profile).ok_or_else(|| ConfigError::UnknownProfile {
                recipe: name.to_owned(),
                profile: raw.profile.clone(),
            })?;

        let pipeline = match raw.pipeline.as_ref().or(self.defaults.pipeline.as_ref()) {
            Some(label) => {
                let pipeline = Pipeline::from_str_label(label).ok_or_else(|| {
                    ConfigError::UnknownPipeline {
                        recipe: name.to_owned(),
                        pipeline: label.clone(),
                    }
                })?;
                if !profile.accepts(pipeline) {
                    return Err(ConfigError::PipelineNotAccepted {
                        recipe: name.to_owned(),
                        profile: profile.as_str(),
                        pipeline: label.clone(),
                    });
                }
                Some(pipeline)
            }
            None => None,
        };

        let purpose = raw.purpose.clone().unwrap_or_else(|| name.to_owned());
        let index = raw.index.or(self.defaults.index).unwrap_or(0);
        let layered = raw.layered.or(self.defaults.layered).unwrap_or(false);

        // Validate the whole combination through the same Context a manual
        // derivation builds. This checks the purpose charset/length (crucial for
        // the name-as-purpose default) using the effective pipeline.
        let effective = pipeline.unwrap_or_else(|| profile.default_pipeline());
        Context::with_pipeline(profile, effective, &purpose, index).map_err(|source| {
            ConfigError::InvalidRecipe {
                recipe: name.to_owned(),
                source,
            }
        })?;

        Ok(Resolved {
            profile,
            pipeline,
            purpose,
            index,
            layered,
            description: raw.description.clone(),
        })
    }
}

/// The XDG default config path: `$XDG_CONFIG_HOME/ykdf/config.toml`, falling back
/// to `$HOME/.config/ykdf/config.toml`. `None` if neither variable is set.
fn default_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(xdg).join("ykdf").join("config.toml"));
    }
    std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(|home| {
            PathBuf::from(home)
                .join(".config")
                .join("ykdf")
                .join("config.toml")
        })
}

/// Errors from loading, parsing, or resolving a recipe catalogue.
#[derive(Debug)]
pub enum ConfigError {
    /// Failed to read the config file.
    Io {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The config file is not valid TOML or has an unknown field.
    Parse {
        /// The file the error came from, if known.
        path: Option<PathBuf>,
        /// The underlying parse error.
        source: toml::de::Error,
    },
    /// No recipe with the requested name exists.
    UnknownRecipe(String),
    /// A recipe names a profile that does not exist.
    UnknownProfile {
        /// The recipe holding the bad value.
        recipe: String,
        /// The unrecognised profile label.
        profile: String,
    },
    /// A recipe names a pipeline that does not exist.
    UnknownPipeline {
        /// The recipe holding the bad value.
        recipe: String,
        /// The unrecognised pipeline label.
        pipeline: String,
    },
    /// A recipe pairs a profile with a pipeline it does not accept.
    PipelineNotAccepted {
        /// The recipe holding the bad pairing.
        recipe: String,
        /// The profile label.
        profile: &'static str,
        /// The pipeline label the profile rejects.
        pipeline: String,
    },
    /// A recipe resolves to an invalid derivation context (e.g. a bad purpose).
    InvalidRecipe {
        /// The recipe that failed validation.
        recipe: String,
        /// The underlying core error.
        source: ykdf_core::Error,
    },
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigError::Io { path, source } => {
                write!(f, "failed to read config {}: {source}", path.display())
            }
            ConfigError::Parse { path, source } => match path {
                Some(p) => write!(f, "failed to parse config {}: {source}", p.display()),
                None => write!(f, "failed to parse config: {source}"),
            },
            ConfigError::UnknownRecipe(name) => write!(f, "no recipe named {name:?}"),
            ConfigError::UnknownProfile { recipe, profile } => {
                write!(f, "recipe {recipe:?} has an unknown profile: {profile:?}")
            }
            ConfigError::UnknownPipeline { recipe, pipeline } => {
                write!(f, "recipe {recipe:?} has an unknown pipeline: {pipeline:?}")
            }
            ConfigError::PipelineNotAccepted {
                recipe,
                profile,
                pipeline,
            } => write!(
                f,
                "recipe {recipe:?}: profile {profile} does not accept the {pipeline} pipeline"
            ),
            ConfigError::InvalidRecipe { recipe, source } => {
                write!(f, "recipe {recipe:?}: {source}")
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io { source, .. } => Some(source),
            ConfigError::Parse { source, .. } => Some(source),
            ConfigError::InvalidRecipe { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Catalogue, ConfigError};
    use ykdf_core::{Pipeline, Profile};

    const SAMPLE: &str = r#"
        [defaults]
        pipeline = "hkdf-sha512"
        index = 0
        layered = false

        [recipe.wg-home]
        profile = "x25519"
        description = "WireGuard home tunnel"

        [recipe.git-signing]
        profile = "ed25519"
        purpose = "commit-signing"
        pipeline = "hkdf-sha3-512"
        index = 2

        [recipe.backup]
        profile = "age-x25519"
        layered = true
    "#;

    fn cat() -> Catalogue {
        Catalogue::parse(SAMPLE, None).unwrap()
    }

    #[test]
    fn purpose_defaults_to_recipe_name() {
        let r = cat().resolve("wg-home").unwrap();
        assert_eq!(r.purpose, "wg-home");
        assert_eq!(r.profile, Profile::X25519);
        assert_eq!(r.description.as_deref(), Some("WireGuard home tunnel"));
    }

    #[test]
    fn explicit_purpose_overrides_name() {
        let r = cat().resolve("git-signing").unwrap();
        assert_eq!(r.purpose, "commit-signing");
        assert_eq!(r.profile, Profile::Ed25519);
        assert_eq!(r.pipeline, Some(Pipeline::HkdfSha3));
        assert_eq!(r.index, 2);
    }

    #[test]
    fn defaults_apply_when_recipe_is_silent() {
        // wg-home sets no index/layered, so the [defaults] values apply.
        let r = cat().resolve("wg-home").unwrap();
        assert_eq!(r.index, 0);
        assert!(!r.layered);
        // The default pipeline label resolves to a concrete pipeline.
        assert_eq!(r.pipeline, Some(Pipeline::HkdfSha512));
    }

    #[test]
    fn recipe_field_overrides_defaults() {
        // backup overrides layered; index falls back to the default (0).
        let r = cat().resolve("backup").unwrap();
        assert!(r.layered);
        assert_eq!(r.index, 0);
    }

    #[test]
    fn unknown_recipe_is_an_error() {
        assert!(matches!(
            cat().resolve("nope"),
            Err(ConfigError::UnknownRecipe(_))
        ));
    }

    #[test]
    fn unknown_profile_is_an_error() {
        let cat = Catalogue::parse("[recipe.x]\nprofile = \"kyber\"\n", None).unwrap();
        assert!(matches!(
            cat.resolve("x"),
            Err(ConfigError::UnknownProfile { .. })
        ));
    }

    #[test]
    fn pipeline_not_accepted_is_an_error() {
        // x25519 is classical; SHAKE256 is a PQC-only pipeline.
        let cat = Catalogue::parse(
            "[recipe.x]\nprofile = \"x25519\"\npipeline = \"shake256\"\n",
            None,
        )
        .unwrap();
        assert!(matches!(
            cat.resolve("x"),
            Err(ConfigError::PipelineNotAccepted { .. })
        ));
    }

    #[test]
    fn recipe_name_used_as_bad_purpose_is_rejected() {
        // No explicit purpose, and the name is not a valid purpose (uppercase).
        let cat = Catalogue::parse("[recipe.BadName]\nprofile = \"x25519\"\n", None).unwrap();
        assert!(matches!(
            cat.resolve("BadName"),
            Err(ConfigError::InvalidRecipe { .. })
        ));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let err = Catalogue::parse(
            "[recipe.x]\nprofile = \"x25519\"\nsecret = \"oops\"\n",
            None,
        );
        assert!(matches!(err, Err(ConfigError::Parse { .. })));
    }

    #[test]
    fn empty_catalogue_has_no_recipes() {
        let cat = Catalogue::parse("", None).unwrap();
        assert_eq!(cat.recipes().count(), 0);
    }

    #[test]
    fn recipes_are_listed_in_name_order() {
        let cat = cat();
        let names: Vec<&str> = cat.recipes().map(|(n, _)| n).collect();
        assert_eq!(names, ["backup", "git-signing", "wg-home"]);
    }

    #[test]
    fn explicitly_requested_missing_file_is_an_error() {
        let missing = std::path::Path::new("/nonexistent/ykdf/config.toml");
        assert!(matches!(
            Catalogue::load(Some(missing)),
            Err(ConfigError::Io { .. })
        ));
    }
}
