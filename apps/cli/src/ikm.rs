use std::path::PathBuf;

use crate::error::CliError;

pub enum IkmSource {
    File(PathBuf),
}

impl IkmSource {
    pub fn load(&self) -> Result<ykdf_core::Ikm, CliError> {
        match self {
            Self::File(path) => {
                let bytes = std::fs::read(path).map_err(|e| CliError::IkmRead {
                    path: path.clone(),
                    source: e,
                })?;
                ykdf_core::Ikm::new(bytes).map_err(CliError::Core)
            }
        }
    }
}
