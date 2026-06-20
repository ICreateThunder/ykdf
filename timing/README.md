# Timing measurement (dudect)

A [dudect](https://github.com/oreparaz/dudect)-style timing-leakage harness
(built on [`dudect-bencher`](https://crates.io/crates/dudect-bencher)) for the
core derivation. It checks that operations on secret material run in time
independent of the secret bytes. This crate is detached from the main workspace
and is a **manual** tool — it is not a CI gate (dudect is statistical and the
t-statistic naturally fluctuates between runs).

## Benchmarks

| Benchmark | Times | Expectation |
|-----------|-------|-------------|
| `extract_is_secret_independent` | `extract` (HMAC-SHA512) over fixed vs random IKM | constant-time |
| `derive_is_secret_independent`  | `derive` (expand + x25519 clamp) over fixed vs random master key | constant-time |

The Argon2id passphrase path is **not** measured: Argon2id is memory-hard with
intentionally data-dependent access patterns, so it would report expected
"leakage" that is by design, not a flaw. The threat model for the passphrase
factor is offline derivation, not an online timing oracle.

## Running

```bash
cargo run --release --manifest-path timing/Cargo.toml
# or, longer, for more confidence:
cargo run --release --manifest-path timing/Cargo.toml -- --continuous derive_is_secret_independent
```

## Interpreting results

Each line reports `max t`, the Welch t-statistic between the two input classes:

- **|t| < ~10** (ideally < 5): no detectable input-dependent timing.
- **|t|** large and growing with more samples: a likely leak — investigate.

A representative run on commodity x86-64:

```
bench derive_is_secret_independent  ... : n == +0.086M, max t = +1.80
bench extract_is_secret_independent ... : n == +0.091M, max t = -1.81
```

Both well under the threshold — no detectable secret-dependent timing. Results
depend on the machine; a noisy or shared host inflates t, so prefer a quiet
box and longer runs when checking a real change.
