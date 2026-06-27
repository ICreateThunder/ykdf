/*
 * YKDF v1 derivation - C reference implementation.
 *
 * An independent reimplementation of the YKDF v1 key-derivation format
 * (docs/SPEC.md), written to corroborate the canonical Rust core: both must
 * reproduce every byte in vectors/v1.json. Only the deterministic
 * IKM -> extract -> expand -> derive pipeline is covered; the YubiKey transport
 * that produces the IKM is out of scope.
 *
 * The extract/expand construction (HKDF per RFC 5869, the SHAKE256 sponge per
 * FIPS 202) is written by hand so a passing vector run is evidence the format is
 * portable, not an artifact of a shared library. Heavy standardised primitives
 * are delegated to battle-tested libraries on a different stack than the Rust or
 * Go references use: Argon2id (libsodium) and ML-KEM / ML-DSA key generation
 * (OpenSSL >= 3.5).
 *
 * Every function returns 0 on success and -1 on failure.
 */
#ifndef YKDF_H
#define YKDF_H

#include <stddef.h>
#include <stdint.h>

#define YKDF_MASTER_LEN 64
#define YKDF_VERSION "v1"

typedef enum {
	YKDF_HKDF_SHA512 = 0,
	YKDF_HKDF_SHA3_512,
	YKDF_SHAKE256,
	YKDF_PIPELINE_INVALID
} ykdf_pipeline;

typedef enum {
	YKDF_X25519 = 0,
	YKDF_ED25519,
	YKDF_AGE_X25519,
	YKDF_SYMMETRIC,
	YKDF_MLKEM512,
	YKDF_MLKEM768,
	YKDF_MLKEM1024,
	YKDF_MLDSA44,
	YKDF_MLDSA65,
	YKDF_MLDSA87,
	YKDF_RAW,
	YKDF_PROFILE_INVALID
} ykdf_profile;

/* Label parsing for the conformance harness. Return the *_INVALID sentinel on
 * an unknown label. */
ykdf_pipeline ykdf_pipeline_from_str(const char *s);
ykdf_profile ykdf_profile_from_str(const char *s);

/* Accept policy (SPEC §Accept policy): 1 if the profile accepts the pipeline. */
int ykdf_accepts(ykdf_profile profile, ykdf_pipeline pipeline);

/* Fixed expand length for a profile, or -1 for raw (caller-chosen). */
int ykdf_expand_length(ykdf_profile profile);

/* Extract: IKM -> 64-byte master key (SPEC §2). Rejects IKM < 16 bytes. */
int ykdf_extract(ykdf_pipeline pipeline, const uint8_t *ikm, size_t ikm_len,
                 uint8_t master[YKDF_MASTER_LEN]);

/* Cascade: fold a stretched passphrase into the master key in place (SPEC §3).
 * Runs after extract and before expand. */
int ykdf_cascade(ykdf_pipeline pipeline, uint8_t master[YKDF_MASTER_LEN],
                 const char *passphrase);

/* Build the canonical context string ykdf:v1:<pipeline>:<profile>:<purpose>:<index>. */
int ykdf_context(char *buf, size_t buf_len, ykdf_pipeline pipeline,
                 ykdf_profile profile, const char *purpose, uint32_t index);

/* Expand: master key -> length bytes bound to context (SPEC §5). */
int ykdf_expand(ykdf_pipeline pipeline, const uint8_t master[YKDF_MASTER_LEN],
                const char *context, size_t length, uint8_t *out);

/* Curve25519 clamp in place (RFC 7748). */
void ykdf_clamp_x25519(uint8_t key[32]);

/* Bech32 (not Bech32m) age identity for a 32-byte clamped secret, upper-cased:
 * AGE-SECRET-KEY-1... Writes a NUL-terminated string. */
int ykdf_age_identity(const uint8_t clamped[32], char *out, size_t out_len);

/* ML-KEM key generation from the 64-byte (d || z) seed (OpenSSL, FIPS 203).
 * Writes the encoded encapsulation key and sets *ek_len. */
int ykdf_mlkem_ek(ykdf_profile profile, const uint8_t seed[64], uint8_t *ek,
                  size_t ek_cap, size_t *ek_len);

/* ML-DSA key generation from the 32-byte seed xi (OpenSSL, FIPS 204).
 * Writes the encoded verifying key and sets *vk_len. */
int ykdf_mldsa_vk(ykdf_profile profile, const uint8_t seed[32], uint8_t *vk,
                  size_t vk_cap, size_t *vk_len);

#endif /* YKDF_H */
