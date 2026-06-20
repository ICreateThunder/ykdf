# YKDF Security Assurance Case

This document is a structured argument that YKDF meets its security
requirements. It states the top-level security claim, decomposes it into
sub-claims, and links each sub-claim to concrete evidence in the repository. It
is intended to satisfy the OpenSSF Best Practices `assurance_case` criterion and
to give reviewers a single map from "why we believe this is secure" to "where to
check."

It complements, and does not replace:

- [SECURITY.md](../SECURITY.md) - threat model, reporting, algorithm notes
- [docs/SPEC.md](SPEC.md) - the byte-level v1 derivation format
- [vectors/v1.json](../vectors/v1.json) - cross-platform golden vectors

## Top-level claim

> Given a YubiKey-held root secret, YKDF derives cryptographic keys that are
> **deterministic** (the same inputs always reproduce the same key),
> **confidential** (keys cannot be recovered or predicted without the hardware
> secret), and **domain-separated** (keys for different purposes are
> computationally independent), and it does so without weakening, storing, or
> leaking that key material.

The argument below shows why each italicised property holds.

## Trust boundaries and assumptions

YKDF's security rests on assumptions that are explicitly *outside* its trust
boundary. These are not claims YKDF can prove; they are the foundation it builds
on.

- **The YubiKey hardware is trusted.** The PIV slot 9d private key (and, in
  layered mode, the OTP slot 2 HMAC secret) are held by the token. YKDF assumes
  the device performs ECDH / HMAC correctly and does not exfiltrate secrets.
  YubiKey firmware vulnerabilities are explicitly out of scope (see SECURITY.md).
- **The operating system CSPRNG is trusted.** Provisioning-time key and nonce
  generation uses `OsRng` (the `getrandom(2)` syscall). YKDF assumes the OS RNG
  is not predictable.
- **The host executing YKDF is trusted at the moment of derivation.** Derived
  keys necessarily exist in host RAM while in use. A host compromised at
  derivation time (malicious kernel, RAM scraping, a debugger attached to the
  process) is outside YKDF's control. YKDF's obligation is to minimise the
  window and surface (see C4).

The trust boundary therefore runs: **trusted [YubiKey + OS RNG] -> YKDF code
(the subject of this assurance case) -> derived key handed to the caller.** The
attacker is assumed to have YKDF's source (it is public), the derivation context
strings, and any number of *outputs*, but not the YubiKey secret or the host
memory at derivation time.

## Sub-claims and evidence

### C1 - The derivation is cryptographically sound

**Argument.** YKDF uses only published, peer-reviewed primitives and composes
them in the standard extract-then-expand (HKDF / TLS 1.3) pattern: HKDF over
SHA-512 or SHA3-512, the SHAKE256 sponge, X25519/Ed25519 (RFC 7748/8032), ML-KEM
(FIPS 203), and Argon2id (RFC 9106) for optional passphrase stretching. No
cryptographic primitive is home-grown; all are delegated to established
RustCrypto / dalek crates. The exact byte-level construction is frozen and
specified.

**Evidence.**
- [docs/SPEC.md](SPEC.md) - the normative byte-level format.
- [vectors/v1.json](../vectors/v1.json) + `crates/ykdf-core/tests/vectors.rs` -
  golden vectors plus an *independent* RFC 5869 cross-check using the `hkdf`
  crate, which passes (our hand-rolled HKDF is byte-correct).
- SECURITY.md "Cryptographic Algorithm Notes".

### C2 - Outputs are unpredictable without the hardware secret

**Argument.** Every derived key is the output of HKDF-Expand or SHAKE256 keyed,
through the extract step, on the YubiKey-held input key material. Under the
standard PRF/XOF security assumptions, the output is computationally
indistinguishable from random to anyone without that IKM. Keys are never written
to disk; only the public half (where one exists) is persisted, in the slot 9d
carrier certificate.

**Evidence.** SPEC.md (extract-then-expand definition); the no-disk-write
property is enforced by the CLI design (derived secrets go to stdout/ephemeral
use only) and documented in the README.

### C3 - Distinct purposes yield independent keys

**Argument.** The derivation context string
`ykdf:v1:<pipeline>:<profile>:<purpose>:<index>` is bound into every expansion,
and the requested output length is bound into `kdf_info` as a trailing field.
This length-binding defeats the HKDF/XOF prefix property: a request for *n*
bytes is not a prefix of a request for *m > n* bytes. Different purposes,
profiles, indices, or lengths therefore produce computationally independent
outputs. Sponge pipelines additionally use domain-separation tags (0x01 extract,
0x02 cascade).

**Evidence.** `crates/ykdf-core/tests/properties.rs` - a proptest asserting the
length-binding non-prefix property (a security property, not just a smoke test),
context round-trip, determinism, and domain separation;
`crates/ykdf-core/tests/format_invariants.rs` pins the context/`kdf_info` shape.

### C4 - Secret material does not leak through memory, timing, or side outputs

**Argument.** Secret-bearing types are zeroized on drop (`ZeroizeOnDrop` /
`Zeroizing`). Key-sensitive comparisons and the derivation path are written to be
data-independent in their control flow, and this is *measured*, not just
asserted. YKDF makes no network calls and emits no telemetry.

**Evidence.**
- `timing/` - a dudect-bencher measurement rig; `extract_is_secret_independent`
  and `derive_is_secret_independent` report a Welch t-statistic of ~1.8 (well
  below the ~10 leakage threshold), i.e. no measurable secret-dependent timing.
- Zeroization on the secret payload structs in `crates/ykdf-core`.
- SECURITY.md "No Telemetry"; the CLI never persists derived private keys.

### C5 - The implementation is memory-safe

**Argument.** The entire workspace forbids `unsafe`, so the classic memory-safety
weakness classes (buffer overflow, use-after-free, uninitialised reads) are
unreachable by construction in YKDF's own code. This is checked dynamically as
well as statically.

**Evidence.** `unsafe_code = "forbid"` workspace-wide; `cargo-fuzz` targets
(`context_parse`, `ikm_extract`, `derive_raw`) under a CI fuzz job; a Miri job
(`crates/ykdf-core/tests/miri_core.rs`) that runs the core derivation under the
UB detector with no findings.

### C6 - Untrusted input is validated

**Argument.** The only attacker-influenced inputs to the core are the derivation
context string, the IKM length, and (optionally) a user-supplied hex scalar /
passphrase. Context parsing validates the vocabulary and rejects disallowed
pipeline/profile combinations; IKM and output lengths are bounds-checked; hex
imports are length-validated before use. Parser robustness is fuzzed.

**Evidence.** `context_parse` fuzz target; the disallowed-combination and
boundary tests in `crates/ykdf-core/tests`; CLI hex/length validation in the
`ykdf` app.

### C7 - The supply chain and releases have integrity

**Argument.** Dependencies are minimal, license- and advisory-gated, and
monitored; commits and tags are signed; release artifacts are signed and
verifiable.

**Evidence.** `cargo-deny` (licenses + advisories + bans) and `osv-scanner` in
CI; OpenSSF Scorecard; Dependabot; GPG-signed commits and tags; keyless cosign
signatures on release artifacts (Sigstore bundle), with verification documented
in the README; `gitleaks` guarding against committed credentials.

### C8 - The one legacy primitive (SHA-1) is used safely

**Argument.** SHA-1 appears only in optional `--layered` mode, because that is
what the YubiKey HMAC-SHA1 slot implements. The 20-byte response is used purely
as additional input key material (concatenated with the PIV ECDH secret, then
extracted under a fixed salt). The construction relies on HMAC-SHA1's strength as
a PRF, which is unbroken - never on SHA-1 collision resistance, which is. Users
who wish to avoid SHA-1 entirely can omit `--layered`.

**Evidence.** SECURITY.md "SHA-1 in optional layered mode"; the concatenation is
in `crates/ykdf-core` and pinned by the format-invariant tests.

## Secure design principles applied

- **Least privilege / minimal surface.** Small dependency set; the public API was
  deliberately narrowed (only `Context`/`extract`/`expand`/`cascade` and the
  payload types are exported). No network, no telemetry, no disk persistence of
  secrets.
- **Defense in depth.** Hardware factor + optional layered HMAC factor + optional
  Argon2id-stretched passphrase factor, cascaded.
- **Fail safe / fail closed.** Disallowed pipeline/profile combinations are
  rejected rather than silently coerced; input lengths are checked before use.
- **Economy of mechanism.** One frozen, specified construction (extract-then-
  expand) reused across all profiles, rather than per-profile bespoke logic.
- **Complete mediation of versioning.** The format is versioned inside the
  context string (`v1`); a future `v2` re-namespaces *all* outputs, so format
  changes cannot silently collide with v1 keys.

## Common implementation weaknesses countered

| Weakness class | How YKDF counters it |
|---|---|
| Memory-safety (overflow, UAF) | `unsafe` forbidden; Miri; fuzzing (C5) |
| Weak/biased randomness | OS CSPRNG (`getrandom(2)`) for all generation |
| Key reuse across contexts | Context + length binding; non-prefix property (C3) |
| Secret left in memory | Zeroize on drop (C4) |
| Timing side channels | Data-independent paths, measured with dudect (C4) |
| Injection via malformed input | Validated parsing, fuzzed (C6) |
| Broken/legacy crypto | Published primitives only; SHA-1 confined to PRF use (C1, C8) |
| Supply-chain tampering | Signed commits/tags/releases; deny + osv + Scorecard (C7) |
| Credential leakage in VCS | gitleaks in CI (C7) |

## Residual risks (knowingly accepted)

- **Host compromise at derivation time** is out of scope (see trust boundaries);
  derived keys must exist in RAM to be usable.
- **Secrets passed as CLI arguments** (`--hmac-secret`, `--mgmt-key`, `--import`)
  are visible in the process table; moving these to file/stdin/fd input is a
  tracked follow-up (`docs/ideas.md`).
- **Single maintainer (bus factor).** Acknowledged in
  [GOVERNANCE.md](../GOVERNANCE.md), with a documented transition plan; this is
  the reason the project does not claim the OpenSSF Gold level.

## Maintenance

This assurance case is reviewed whenever the derivation format, threat model, or
dependency posture changes materially, and at each minor release.
