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

## What We Want

- Bug fixes, tests, documentation
- Features (discuss in an issue first)
- Security improvements

## What We Do Not Want

- Telemetry or phone-home of any kind
- Whitespace-only changes
- Non-GPL-compatible dependencies
