# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x (pre-1.0) | Latest minor only |
| 1.x+ | Latest minor + previous minor |

## Reporting a Vulnerability

**Preferred:** [GitHub Private Security Advisories](../../security/advisories/new)

**Fallback:** robert@shalders.co.uk (PGP-encrypted)

### Response Timeline

- **48 hours** - acknowledgment
- **5 business days** - initial assessment
- **90 days** - coordinated disclosure

### PGP Key

```
Primary UID : Robert Shalders <robert@shalders.co.uk>
Fingerprint : 1A44 8CE4 18BD 8D37 1D12  B697 418D 45B7 1F57 D61F
Type        : Ed25519/Curve25519, hardware-token-backed
```

Available via:
- `gpg --keyserver keys.openpgp.org --recv-keys 1A448CE418BD8D371D12B697418D45B71F57D61F`
- [keys.openpgp.org](https://keys.openpgp.org/search?q=robert%40shalders.co.uk)

## Scope

**In scope:**
- Source code in this repository
- Published release artifacts (crates.io, AUR, APK)
- Security-relevant documentation

**Out of scope:**
- Third-party dependencies (report upstream, file an issue here if it affects YKDF)
- Physical access to the machine running YKDF
- YubiKey firmware vulnerabilities (report to Yubico)

## Threat Model

YKDF handles cryptographic key material. Relevant threats:

- **Memory exposure** - derived keys exist in memory during use; YKDF zeroizes on drop
- **Side channels** - constant-time operations for all key-sensitive paths
- **Supply chain** - cargo-deny allowlist, cargo-audit in CI, signed tags, reproducible builds (goal)
- **Dependency compromise** - minimal dependency surface, audited crates preferred

## No Telemetry

YKDF does not phone home. No usage analytics, no error reporting, no network calls beyond YubiKey USB communication. This is a contribution requirement.

## Bounty

None currently. Reports acknowledged in CHANGELOG and release notes.
