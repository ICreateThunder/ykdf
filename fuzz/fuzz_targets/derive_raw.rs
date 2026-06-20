#![no_main]
//! Fuzz the full raw-derivation pipeline with structured input: arbitrary IKM,
//! purpose string, index, and output length across all three pipelines. Catches
//! panics in purpose validation, the HKDF expand counter loop / truncation, and
//! the SHAKE squeeze. `raw` accepts any pipeline and any length.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ykdf_core::{derive_raw, extract, Context, Ikm, Pipeline, Profile};

#[derive(Arbitrary, Debug)]
struct Input {
    ikm: Vec<u8>,
    purpose: String,
    index: u32,
    len: u16,
}

fuzz_target!(|input: Input| {
    let Ok(ikm) = Ikm::new(input.ikm) else {
        return;
    };
    // Bound the length to keep iterations fast while still crossing the
    // 64-byte block boundary and exercising multi-block expansion.
    let len = (input.len as usize % 4096) + 1;

    for pipeline in [Pipeline::HkdfSha512, Pipeline::HkdfSha3, Pipeline::Shake256] {
        let Ok(master) = extract(&ikm, pipeline) else {
            continue;
        };
        let Ok(ctx) = Context::with_pipeline(Profile::Raw, pipeline, &input.purpose, input.index)
        else {
            continue;
        };
        let _ = derive_raw(&master, &ctx, len);
    }
});
