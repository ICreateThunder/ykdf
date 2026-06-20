#![no_main]
//! Fuzz the IKM entry point and extract. `Ikm::new` must enforce the
//! minimum-length boundary without panicking, and extract must not panic for
//! any pipeline on any accepted IKM.

use libfuzzer_sys::fuzz_target;
use ykdf_core::{extract, Ikm, Pipeline};

fuzz_target!(|data: &[u8]| {
    if let Ok(ikm) = Ikm::new(data.to_vec()) {
        for pipeline in [Pipeline::HkdfSha512, Pipeline::HkdfSha3, Pipeline::Shake256] {
            let _ = extract(&ikm, pipeline);
        }
    }
});
