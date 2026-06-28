# Verifying a release

Release tags are GPG-signed (`git verify-tag vX.Y.Z`). Each release artifact
ships with SHA-256/512 checksums, a [Sigstore](https://www.sigstore.dev/) keyless
signature bundle (`.sigstore.json`), and SLSA build provenance (`.intoto.jsonl`).
Both the signature and the provenance are produced by the release workflow's
GitHub OIDC identity and logged in the public Rekor transparency log.

A [CycloneDX](https://cyclonedx.org/) software bill of materials for the binary's
full dependency graph also ships, as `ykdf-vX.Y.Z-x86_64-linux.cdx.json`, with its
own checksums and Sigstore bundle (verify it exactly like the archive below,
substituting the `.cdx.json` name).

```bash
# Checksums
sha256sum -c ykdf-vX.Y.Z-x86_64-linux.tar.gz.sha256

# Signature (requires cosign)
cosign verify-blob \
  --bundle ykdf-vX.Y.Z-x86_64-linux.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ICreateThunder/ykdf/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ykdf-vX.Y.Z-x86_64-linux.tar.gz

# Build provenance (requires slsa-verifier)
slsa-verifier verify-artifact \
  --provenance-path ykdf-vX.Y.Z-x86_64-linux.tar.gz.intoto.jsonl \
  --source-uri github.com/ICreateThunder/ykdf \
  ykdf-vX.Y.Z-x86_64-linux.tar.gz
```

The v0.1.0 release ships the Sigstore bundle as `.bundle` (same content, verify
the same way) and carries no provenance; later releases use the names above.
