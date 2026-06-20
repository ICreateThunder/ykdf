#![no_main]
//! Fuzz the context-string parser. Arbitrary input must never panic, and any
//! context that parses must round-trip: rendering and re-parsing yields an
//! equal context.

use libfuzzer_sys::fuzz_target;
use ykdf_core::Context;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(ctx) = s.parse::<Context>() {
        let rendered = ctx.to_string();
        let reparsed = rendered
            .parse::<Context>()
            .expect("a rendered context must re-parse");
        assert_eq!(ctx, reparsed, "context round-trip diverged");
    }
});
