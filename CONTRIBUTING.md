# Contributing

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by` trailer (`git commit -s`), asserting
you have the right to submit the contribution under GPLv3.

## Cryptographic Signing

All commits to `main` must be GPG- or SSH-signed.

```bash
git config commit.gpgsign true
```

## Conventional Commits

PR titles follow [Conventional Commits 1.0](https://www.conventionalcommits.org/):

```
<type>(<scope>): <summary>
```

Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `ci`, `build`, `perf`, `security`, `style`, `revert`

Breaking changes: append `!` and include `BREAKING CHANGE:` in the body.

## PR Process

1. Fork or branch from `main`
2. Branch naming: `feat/<short>`, `fix/<short>`, `chore/<short>`
3. Commit early; PRs are squash-merged
4. Open draft PRs early for discussion

### Checklist

- [ ] DCO sign-off on every commit
- [ ] Cryptographic signature on every commit
- [ ] Conventional Commits PR title
- [ ] Tests added or updated
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo deny check`
- [ ] No telemetry or network calls
- [ ] Documentation updated if needed

## Development Setup

- Rust 1.87+ (edition 2024)
- Tools: `gitleaks`, `typos`, `cargo-audit`, `cargo-deny`

```bash
cargo build --workspace
cargo test --workspace
```

## Test Coverage

We measure `ykdf-core` coverage with
[`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov); CI reports it on
every change (informationally, not as a gate):

```bash
cargo install cargo-llvm-cov --locked   # once
cargo llvm-cov --package ykdf-core --features argon2 --summary-only
cargo llvm-cov --package ykdf-core --features argon2 --html   # detailed report
```

Aim to keep region coverage above ~95%. New behaviour should come with tests
that cover both the happy path and the failure paths.

The handful of intentionally-uncovered lines are **unreachable defensive
arms**: `map_err` on operations that cannot fail given the crate's invariants
(HMAC construction accepts any key length; the ML-KEM seed is length-checked
before `Seed::try_from`; bech32 encoding of a fixed 32-byte key; Argon2 with the
locked, always-valid parameters; the stretch descriptor never exceeds 255
bytes). These are kept for safety but cannot be triggered through the public
API, so they are not chased to 100%.

## What We Want

- Bug fixes, tests, documentation
- Features (discuss in an issue first)
- Security improvements

## What We Do Not Want

- Telemetry or phone-home of any kind
- Whitespace-only changes
- Non-GPL-compatible dependencies
