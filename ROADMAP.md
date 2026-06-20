# Roadmap

This roadmap describes the intended direction of YKDF. It is indicative, not a
commitment: priorities shift, and items may move between milestones. Dated
releases and concrete history live in [CHANGELOG.md](CHANGELOG.md).

## Guiding principle

The byte-level v1 derivation format is **frozen** (see [docs/SPEC.md](docs/SPEC.md)
and the golden vectors in [vectors/v1.json](vectors/v1.json)). Everything below
is additive within v1 or strictly out-of-process (new platforms, tooling). A
format change would be a new `v2` namespace, not a silent modification of v1
outputs.

## Now - 0.1.x (maintenance)

- Bug fixes and documentation improvements.
- OpenSSF Best Practices: achieve and maintain the Silver level.
- Move secrets currently passed as CLI arguments (`--hmac-secret`, `--mgmt-key`,
  `--import`) to file/stdin/fd input, to keep them out of the process table.
- Run the hardware shared-backup acceptance test (two devices, same scalar + HMAC
  secret, assert byte-identical derivation).

## Next - 0.2.0 (platform reach, core unchanged)

- **WebAssembly:** package the already-`wasm32`-clean core for use from the
  browser / JS runtimes. The core is the smaller, lower-risk first port.
- Tooling and ergonomics improvements to the CLI that do not touch the format.

## Later - Android

- JNI + Kotlin bindings over the core, with NFC-based YubiKey access.
- Branching to platforms happens only after the core surface is consolidated and
  stable, to avoid re-porting churn.

## 1.0.0 - conformance-gated

1.0.0 is gated on **a second, independent implementation passing the golden
vectors** in `vectors/v1.json`. That cross-implementation conformance is the
signal that the v1 format is genuinely portable and stable enough to promise
long-term compatibility.

## Explicitly out of scope

- Telemetry or any phone-home behaviour.
- Non-GPL-compatible dependencies.
- Format changes that would silently alter existing v1 derivations.

Larger speculative ideas are tracked in [docs/ideas.md](docs/ideas.md).
