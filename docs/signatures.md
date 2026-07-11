# YKDF signature formats

`ykdf sign` produces a detached signature over a message using a derived key.
`ykdf verify` checks one against a supplied public key, with no derivation and no
hardware. Two formats are used, one per key type, and `verify` detects which from
the signature itself.

## ed25519: OpenSSH SSHSIG

An `ed25519` signature is an OpenSSH signature in the `SSHSIG` format (OpenSSH's
`PROTOCOL.sshsig`), so `ssh-keygen -Y verify` validates it and, in the other
direction, `ykdf verify` validates `ssh-keygen -Y sign` output. The byte layout
is defined by that protocol document. YKDF defaults the namespace to `file` and
the message hash to `sha512` (`--hash sha256` is also accepted); the verifier
must supply the same namespace. ed25519 signing is deterministic (RFC 8032).

## ML-DSA: `ykdf-sig:v1`

No widely deployed detached-signature standard for ML-DSA (FIPS 204) exists, so
YKDF defines one, frozen as `v1`.

### Container

A single line:

    ykdf-sig:v1:<profile>:<base64(signature)>

- `<profile>` is `mldsa44`, `mldsa65`, or `mldsa87`.
- `<base64(signature)>` is the raw FIPS 204 signature (2420, 3309, or 4627 bytes
  respectively), standard base64 with padding.

The verifying key is supplied out of band to `verify`, the base64 string that
`ykdf pubkey --profile mldsaXX` prints, so the container stays compact.

### What is signed

The signature is a pure ML-DSA signature (FIPS 204 `ML-DSA.Sign`) with:

- **Context string** `ctx = "ykdf-sig:v1"` (11 ASCII bytes). This is FIPS 204's
  native domain-separation input. It binds the format version into every
  signature, so a signature cannot be lifted to another version or accepted by a
  generic empty-context ML-DSA verifier.
- **Message** the framed blob below, each field encoded as an OpenSSH `string`
  (a big-endian `uint32` length followed by that many bytes):

      string  namespace          (default "file")
      string  "sha512"
      string  SHA-512(message)   (64 bytes)

The message is pre-hashed with SHA-512 so the signed blob is a fixed size
regardless of message length. SHA-512's 256-bit collision resistance meets or
exceeds every ML-DSA level, so message binding is never the weak link.

The profile is not repeated inside the blob: it is fixed by the key. A signature
made under one level fails to decode against another level's verifying key
because the byte lengths differ, so a mislabelled container is rejected rather
than verified wrongly.

### Determinism

Signing is deterministic: FIPS 204 with the 32-byte `rnd` set to zero, so the
same key and message always produce the same signature. This matches YKDF's
derivation, which is itself deterministic from the YubiKey.

### Verifying

Parse `<profile>` and the base64 signature from the container, base64-decode the
supplied verifying key, rebuild the framed blob from the namespace and
`SHA-512(message)`, and run FIPS 204 `ML-DSA.Verify` with `ctx = "ykdf-sig:v1"`.
`ykdf verify` does this automatically, choosing the ed25519 path for a
`-----BEGIN SSH SIGNATURE-----` block and the ML-DSA path for a `ykdf-sig:v1:`
prefix.
