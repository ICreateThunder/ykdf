# Fuzz targets

Coverage-guided fuzzing of `ykdf-core`'s untrusted-input surfaces, built on
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) / libFuzzer. This crate
is detached from the main workspace (it needs nightly) and is not published.

## Targets

| Target           | Surface                                                            |
|------------------|-------------------------------------------------------------------|
| `context_parse`  | `Context::from_str` — must never panic; parsed contexts round-trip |
| `ikm_extract`    | `Ikm::new` length boundary + `extract` over every pipeline         |
| `derive_raw`     | full raw-derivation pipeline with arbitrary purpose/index/length   |

## Running

```bash
# Install (once)
cargo install cargo-fuzz --locked

# Fuzz a single target (Ctrl-C to stop)
cargo +nightly fuzz run derive_raw

# Bounded run (as CI does)
cargo +nightly fuzz run context_parse -- -runs=100000 -max_total_time=30
```

CI runs a short bounded pass of every target on each change to catch shallow
regressions. Deep/extended fuzzing is a manual activity; commit any
crash-reproducing input found under `corpus/` if you want it kept.
