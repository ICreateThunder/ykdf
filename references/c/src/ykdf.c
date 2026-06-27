/* YKDF v1 derivation core. See include/ykdf.h. */
#include "ykdf.h"
#include "bech32.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <sodium.h>

#include <stdio.h>
#include <string.h>

/* SPEC §Constants. */
static const char EXTRACT_SALT[] = "ykdf-v1";
static const char ARGON_SALT[] = "ykdf-v1-argon2id"; /* 16 bytes */
static const char STRETCH_DESCRIPTOR[] = "argon2id:m=131072,t=3,p=1";
static const uint8_t EXTRACT_TAG = 0x01;
static const uint8_t CASCADE_TAG = 0x02;
#define MIN_IKM_LEN 16

static const char *const PIPELINE_LABEL[] = {
	[YKDF_HKDF_SHA512] = "hkdf-sha512",
	[YKDF_HKDF_SHA3_512] = "hkdf-sha3-512",
	[YKDF_SHAKE256] = "shake256",
};

static const char *const PROFILE_LABEL[] = {
	[YKDF_X25519] = "x25519",      [YKDF_ED25519] = "ed25519",
	[YKDF_AGE_X25519] = "age-x25519", [YKDF_SYMMETRIC] = "symmetric",
	[YKDF_MLKEM512] = "mlkem512",  [YKDF_MLKEM768] = "mlkem768",
	[YKDF_MLKEM1024] = "mlkem1024", [YKDF_MLDSA44] = "mldsa44",
	[YKDF_MLDSA65] = "mldsa65",    [YKDF_MLDSA87] = "mldsa87",
	[YKDF_RAW] = "raw",
};

ykdf_pipeline ykdf_pipeline_from_str(const char *s)
{
	for (int i = 0; i <= YKDF_SHAKE256; i++)
		if (strcmp(s, PIPELINE_LABEL[i]) == 0)
			return (ykdf_pipeline)i;
	return YKDF_PIPELINE_INVALID;
}

ykdf_profile ykdf_profile_from_str(const char *s)
{
	for (int i = 0; i <= YKDF_RAW; i++)
		if (strcmp(s, PROFILE_LABEL[i]) == 0)
			return (ykdf_profile)i;
	return YKDF_PROFILE_INVALID;
}

int ykdf_accepts(ykdf_profile profile, ykdf_pipeline pipeline)
{
	switch (profile) {
	case YKDF_X25519:
	case YKDF_ED25519:
	case YKDF_AGE_X25519:
	case YKDF_SYMMETRIC:
		return pipeline == YKDF_HKDF_SHA512 || pipeline == YKDF_HKDF_SHA3_512;
	case YKDF_MLKEM512:
	case YKDF_MLKEM768:
	case YKDF_MLKEM1024:
	case YKDF_MLDSA44:
	case YKDF_MLDSA65:
	case YKDF_MLDSA87:
		return pipeline == YKDF_SHAKE256;
	case YKDF_RAW:
		return pipeline == YKDF_HKDF_SHA512 ||
		       pipeline == YKDF_HKDF_SHA3_512 || pipeline == YKDF_SHAKE256;
	default:
		return 0;
	}
}

int ykdf_expand_length(ykdf_profile profile)
{
	switch (profile) {
	case YKDF_X25519:
	case YKDF_ED25519:
	case YKDF_AGE_X25519:
	case YKDF_SYMMETRIC:
	case YKDF_MLDSA44:
	case YKDF_MLDSA65:
	case YKDF_MLDSA87:
		return 32;
	case YKDF_MLKEM512:
	case YKDF_MLKEM768:
	case YKDF_MLKEM1024:
		return 64;
	default:
		return -1; /* raw: caller-chosen */
	}
}

/* HKDF digest name for OpenSSL, NULL for the sponge pipeline. */
static const char *hkdf_md(ykdf_pipeline pipeline)
{
	switch (pipeline) {
	case YKDF_HKDF_SHA512:
		return "SHA512";
	case YKDF_HKDF_SHA3_512:
		return "SHA3-512";
	default:
		return NULL;
	}
}

/* One-shot HMAC. Writes exactly 64 bytes (both digests are 512-bit). */
static int hmac(const char *md, const uint8_t *key, size_t key_len,
                const uint8_t *msg, size_t msg_len, uint8_t out[YKDF_MASTER_LEN])
{
	int rc = -1;
	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	EVP_MAC_CTX *ctx = mac ? EVP_MAC_CTX_new(mac) : NULL;
	if (!ctx)
		goto out;
	OSSL_PARAM params[2] = {
		OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)md, 0),
		OSSL_PARAM_construct_end(),
	};
	size_t got = 0;
	if (EVP_MAC_init(ctx, key, key_len, params) != 1 ||
	    EVP_MAC_update(ctx, msg, msg_len) != 1 ||
	    EVP_MAC_final(ctx, out, &got, YKDF_MASTER_LEN) != 1 ||
	    got != YKDF_MASTER_LEN)
		goto out;
	rc = 0;
out:
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(mac);
	return rc;
}

/* SHAKE256: absorb in, squeeze out_len bytes. */
static int shake256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len)
{
	int rc = -1;
	EVP_MD *md = EVP_MD_fetch(NULL, "SHAKE256", NULL);
	EVP_MD_CTX *ctx = md ? EVP_MD_CTX_new() : NULL;
	if (!ctx)
		goto out;
	if (EVP_DigestInit_ex(ctx, md, NULL) != 1 ||
	    EVP_DigestUpdate(ctx, in, in_len) != 1 ||
	    EVP_DigestFinalXOF(ctx, out, out_len) != 1)
		goto out;
	rc = 0;
out:
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(md);
	return rc;
}

/* HKDF-Expand (RFC 5869 §2.3) with PRK = master key. */
static int hkdf_expand(const char *md, const uint8_t prk[YKDF_MASTER_LEN],
                       const uint8_t *info, size_t info_len, uint8_t *out,
                       size_t out_len)
{
	uint8_t prev[YKDF_MASTER_LEN];
	size_t prev_len = 0, done = 0;
	for (unsigned i = 1; done < out_len; i++) {
		/* T(i) = HMAC(prk, T(i-1) || info || byte(i)). */
		EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
		EVP_MAC_CTX *ctx = mac ? EVP_MAC_CTX_new(mac) : NULL;
		OSSL_PARAM params[2] = {
			OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
			                                 (char *)md, 0),
			OSSL_PARAM_construct_end(),
		};
		uint8_t blk = (uint8_t)i;
		size_t got = 0;
		int ok = ctx &&
		         EVP_MAC_init(ctx, prk, YKDF_MASTER_LEN, params) == 1 &&
		         EVP_MAC_update(ctx, prev, prev_len) == 1 &&
		         EVP_MAC_update(ctx, info, info_len) == 1 &&
		         EVP_MAC_update(ctx, &blk, 1) == 1 &&
		         EVP_MAC_final(ctx, prev, &got, sizeof prev) == 1 &&
		         got == YKDF_MASTER_LEN;
		EVP_MAC_CTX_free(ctx);
		EVP_MAC_free(mac);
		if (!ok)
			return -1;
		prev_len = YKDF_MASTER_LEN;
		size_t take = out_len - done < YKDF_MASTER_LEN ? out_len - done
		                                               : YKDF_MASTER_LEN;
		memcpy(out + done, prev, take);
		done += take;
	}
	sodium_memzero(prev, sizeof prev);
	return 0;
}

int ykdf_extract(ykdf_pipeline pipeline, const uint8_t *ikm, size_t ikm_len,
                 uint8_t master[YKDF_MASTER_LEN])
{
	if (ikm_len < MIN_IKM_LEN)
		return -1;
	const char *md = hkdf_md(pipeline);
	if (md) /* HKDF-Extract: HMAC(salt = "ykdf-v1", IKM). */
		return hmac(md, (const uint8_t *)EXTRACT_SALT, strlen(EXTRACT_SALT),
		            ikm, ikm_len, master);
	if (pipeline != YKDF_SHAKE256)
		return -1;
	/* SHAKE256(0x01 || "ykdf-v1" || IKM), squeeze 64. */
	size_t salt_len = strlen(EXTRACT_SALT);
	size_t n = 1 + salt_len + ikm_len;
	uint8_t *in = OPENSSL_malloc(n);
	if (!in)
		return -1;
	in[0] = EXTRACT_TAG;
	memcpy(in + 1, EXTRACT_SALT, salt_len);
	memcpy(in + 1 + salt_len, ikm, ikm_len);
	int rc = shake256(in, n, master, YKDF_MASTER_LEN);
	sodium_memzero(in, n);
	OPENSSL_free(in);
	return rc;
}

/* Argon2id stretch (SPEC §3.1): 64-byte output, fixed cost. */
static int stretch(const char *passphrase, uint8_t out[YKDF_MASTER_LEN])
{
	/* libsodium fixes parallelism at 1, matching p=1; memlimit is in bytes. */
	return crypto_pwhash(out, YKDF_MASTER_LEN, passphrase, strlen(passphrase),
	                     (const unsigned char *)ARGON_SALT,
	                     3 /* t */, (size_t)131072 * 1024 /* 128 MiB */,
	                     crypto_pwhash_ALG_ARGON2ID13);
}

int ykdf_cascade(ykdf_pipeline pipeline, uint8_t master[YKDF_MASTER_LEN],
                 const char *passphrase)
{
	uint8_t stretched[YKDF_MASTER_LEN];
	if (stretch(passphrase, stretched) != 0)
		return -1;

	/* cascade_ikm = len(descriptor) || descriptor || stretched(64). */
	size_t desc_len = strlen(STRETCH_DESCRIPTOR);
	size_t cascade_len = 1 + desc_len + YKDF_MASTER_LEN;
	uint8_t *cascade = OPENSSL_malloc(cascade_len);
	if (!cascade) {
		sodium_memzero(stretched, sizeof stretched);
		return -1;
	}
	cascade[0] = (uint8_t)desc_len;
	memcpy(cascade + 1, STRETCH_DESCRIPTOR, desc_len);
	memcpy(cascade + 1 + desc_len, stretched, YKDF_MASTER_LEN);

	int rc = -1;
	const char *md = hkdf_md(pipeline);
	if (md) {
		/* HMAC(key = master, msg = cascade_ikm). */
		rc = hmac(md, master, YKDF_MASTER_LEN, cascade, cascade_len, master);
	} else if (pipeline == YKDF_SHAKE256) {
		/* SHAKE256(0x02 || master || cascade_ikm), squeeze 64. */
		size_t n = 1 + YKDF_MASTER_LEN + cascade_len;
		uint8_t *in = OPENSSL_malloc(n);
		if (in) {
			in[0] = CASCADE_TAG;
			memcpy(in + 1, master, YKDF_MASTER_LEN);
			memcpy(in + 1 + YKDF_MASTER_LEN, cascade, cascade_len);
			rc = shake256(in, n, master, YKDF_MASTER_LEN);
			sodium_memzero(in, n);
			OPENSSL_free(in);
		}
	}

	sodium_memzero(stretched, sizeof stretched);
	sodium_memzero(cascade, cascade_len);
	OPENSSL_free(cascade);
	return rc;
}

int ykdf_context(char *buf, size_t buf_len, ykdf_pipeline pipeline,
                 ykdf_profile profile, const char *purpose, uint32_t index)
{
	if (pipeline > YKDF_SHAKE256 || profile > YKDF_RAW)
		return -1;
	int n = snprintf(buf, buf_len, "ykdf:%s:%s:%s:%s:%u", YKDF_VERSION,
	                 PIPELINE_LABEL[pipeline], PROFILE_LABEL[profile], purpose,
	                 index);
	return (n < 0 || (size_t)n >= buf_len) ? -1 : 0;
}

int ykdf_expand(ykdf_pipeline pipeline, const uint8_t master[YKDF_MASTER_LEN],
                const char *context, size_t length, uint8_t *out)
{
	if (length < 1 || length > 255 * 64)
		return -1;
	/* kdf_info = "<context>:<length>". */
	char info[256];
	int n = snprintf(info, sizeof info, "%s:%zu", context, length);
	if (n < 0 || (size_t)n >= sizeof info)
		return -1;
	size_t info_len = (size_t)n;

	const char *md = hkdf_md(pipeline);
	if (md)
		return hkdf_expand(md, master, (const uint8_t *)info, info_len, out,
		                   length);
	if (pipeline != YKDF_SHAKE256)
		return -1;
	/* SHAKE256(master || kdf_info), squeeze length. */
	size_t in_len = YKDF_MASTER_LEN + info_len;
	uint8_t *in = OPENSSL_malloc(in_len);
	if (!in)
		return -1;
	memcpy(in, master, YKDF_MASTER_LEN);
	memcpy(in + YKDF_MASTER_LEN, info, info_len);
	int rc = shake256(in, in_len, out, length);
	sodium_memzero(in, in_len);
	OPENSSL_free(in);
	return rc;
}

void ykdf_clamp_x25519(uint8_t key[32])
{
	key[0] &= 0xF8;
	key[31] &= 0x7F;
	key[31] |= 0x40;
}

int ykdf_age_identity(const uint8_t clamped[32], char *out, size_t out_len)
{
	if (ykdf_bech32_encode("age-secret-key-", clamped, 32, out, out_len) != 0)
		return -1;
	for (char *p = out; *p; p++)
		if (*p >= 'a' && *p <= 'z')
			*p = (char)(*p - 'a' + 'A');
	return 0;
}
