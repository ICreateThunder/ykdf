/* ML-KEM / ML-DSA key generation from a YKDF seed, via OpenSSL >= 3.5.
 *
 * OpenSSL's providers run FIPS 203 / 204 key generation deterministically from
 * the standard seed (ML-KEM's 64-byte (d || z), ML-DSA's 32-byte xi) when the
 * "seed" parameter is supplied, and expose the encoded public key (the
 * encapsulation key / verifying key) as the raw public key. See include/ykdf.h.
 */
#include "ykdf.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>

#include <string.h>

/* Generate a keypair from seed and copy the raw public key into out. */
static int keygen_pub(const char *alg, const uint8_t *seed, size_t seed_len,
                      uint8_t *out, size_t out_cap, size_t *out_len)
{
	int rc = -1;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
	EVP_PKEY *pkey = NULL;
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0)
		goto out;
	OSSL_PARAM params[2] = {
		OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
		                                  (void *)seed, seed_len),
		OSSL_PARAM_construct_end(),
	};
	/* OSSL_PKEY_PARAM_ML_DSA_SEED and OSSL_PKEY_PARAM_ML_KEM_SEED are both the
	 * literal "seed"; one constant covers KEM and signature alike. */
	if (EVP_PKEY_CTX_set_params(ctx, params) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0)
		goto out;
	size_t need = 0;
	if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0,
	                                    &need) <= 0 ||
	    need > out_cap ||
	    EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, out,
	                                    out_cap, out_len) <= 0)
		goto out;
	rc = 0;
out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	return rc;
}

int ykdf_mlkem_ek(ykdf_profile profile, const uint8_t seed[64], uint8_t *ek,
                  size_t ek_cap, size_t *ek_len)
{
	const char *alg;
	switch (profile) {
	case YKDF_MLKEM512:
		alg = "ML-KEM-512";
		break;
	case YKDF_MLKEM768:
		alg = "ML-KEM-768";
		break;
	case YKDF_MLKEM1024:
		alg = "ML-KEM-1024";
		break;
	default:
		return -1;
	}
	return keygen_pub(alg, seed, 64, ek, ek_cap, ek_len);
}

int ykdf_mldsa_vk(ykdf_profile profile, const uint8_t seed[32], uint8_t *vk,
                  size_t vk_cap, size_t *vk_len)
{
	const char *alg;
	switch (profile) {
	case YKDF_MLDSA44:
		alg = "ML-DSA-44";
		break;
	case YKDF_MLDSA65:
		alg = "ML-DSA-65";
		break;
	case YKDF_MLDSA87:
		alg = "ML-DSA-87";
		break;
	default:
		return -1;
	}
	return keygen_pub(alg, seed, 32, vk, vk_cap, vk_len);
}
