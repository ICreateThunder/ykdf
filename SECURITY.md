# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x (pre-1.0) | Latest minor only |
| 1.x+ | Latest minor + previous minor |

## Reporting a Vulnerability

**Preferred:** [GitHub Private Security Advisories](../../security/advisories/new)

**Fallback:** robert@shalders.co.uk (PGP-encrypted)

### Response process

Once a report is received, the maintainer follows this process:

1. **Acknowledge** the report within 48 hours.
2. **Assess** validity and severity within 5 business days, and confirm or
   decline the report to the reporter.
3. **Fix** confirmed issues on a private branch, with a regression test where
   feasible.
4. **Disclose** in coordination with the reporter, by default within 90 days:
   publish a fix, a GitHub Security Advisory, and a CHANGELOG / release-note
   entry.
5. **Credit** the reporter (see below).

These are target deadlines: 48 hours to acknowledge, 5 business days to assess,
90 days to coordinated disclosure.

### Credit

Reporters are credited by name (or handle) in the GitHub Security Advisory,
CHANGELOG, and release notes for any confirmed vulnerability, unless they ask to
remain anonymous. We will honour a request for anonymity.

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

## Cryptographic Algorithm Notes

YKDF derives keys using only published, peer-reviewed primitives. The default
derivation path uses HKDF (RFC 5869) over SHA-512 or SHA3-512, the SHAKE256
sponge, X25519/Ed25519 (RFC 7748/8032), ML-KEM (FIPS 203), and Argon2id
(RFC 9106) for optional passphrase stretching. All key and nonce generation
uses the operating system CSPRNG.

### SHA-1 in optional layered mode

The optional `--layered` mode reads a second hardware factor from a YubiKey OTP
slot using HMAC-SHA1 challenge-response. SHA-1 appears here only because it is
the algorithm that the YubiKey HMAC-SHA1 slot implements; it is not a YKDF
design choice and is not part of the default derivation path.

This usage is not affected by SHA-1's known weaknesses:

- SHA-1's broken property is **collision resistance**. YKDF never relies on
  SHA-1 for collision resistance, integrity, or signatures.
- The 20-byte HMAC-SHA1 response is treated purely as additional **input key
  material**: it is concatenated with the primary PIV ECDH shared secret
  (`ecdh_secret || hmac_response`) and the combined value is fed into an
  HKDF/SHAKE256 extract under a fixed domain-separation salt; the resulting
  master key is SHA-512/SHA3-512/SHAKE256.
- The relevant security property is HMAC-SHA1's strength as a **pseudorandom
  function**, which remains unbroken, not SHA-1 collision resistance.

An attacker able to compute SHA-1 collisions gains nothing against this
construction. Users who prefer to avoid SHA-1 entirely can simply omit
`--layered`, leaving only the PIV P-256 ECDH factor.

## No Telemetry

YKDF does not phone home. No usage analytics, no error reporting, no network calls beyond YubiKey USB communication. This is a contribution requirement.

## Bounty

None currently. Reports acknowledged in CHANGELOG and release notes.
