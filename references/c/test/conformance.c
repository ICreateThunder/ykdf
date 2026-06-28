/* YKDF C reference conformance runner.
 *
 * Recomputes every vector in vectors/v1.json stage by stage (master key, then
 * expanded output, then the profile output) and compares against the canonical
 * values, so a mismatch pinpoints the diverging stage. Exit status is non-zero
 * if any vector fails.
 */
#define _POSIX_C_SOURCE 200809L /* for strdup under -std=c11 */

#include "ykdf.h"

#include <sodium.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	const char *field;
	const char *value;
} expected_t;

typedef struct {
	const char *name;
	const char *pipeline;
	const char *profile;
	const char *purpose;
	uint32_t index;
	int length; /* raw only; 0 otherwise */
	const char *ikm_hex;
	const char *passphrase;
	const char *master_key_hex;
	const char *expanded_hex;
	expected_t outputs[2];
} vector_t;

#include "vectors_data.h"

static size_t from_hex(const char *hex, uint8_t *out, size_t out_cap)
{
	size_t n = strlen(hex) / 2;
	if (n > out_cap)
		return 0;
	for (size_t i = 0; i < n; i++) {
		unsigned byte;
		if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
			return 0;
		out[i] = (uint8_t)byte;
	}
	return n;
}

/* Lower-case hex of buf into a freshly allocated NUL-terminated string. */
static char *to_hex(const uint8_t *buf, size_t len)
{
	char *out = malloc(2 * len + 1);
	if (!out)
		return NULL;
	for (size_t i = 0; i < len; i++)
		sprintf(out + 2 * i, "%02x", buf[i]);
	out[2 * len] = '\0';
	return out;
}

/* Build the named profile outputs into results, mirroring SPEC §6. Returns the
 * count, or -1 on error. Caller frees each results[i].value. */
static int compute_outputs(ykdf_profile profile, const uint8_t *okm,
                           size_t okm_len, expected_t *results)
{
	uint8_t key[32], pub[4096];
	size_t pub_len = 0;
	char age[128];
	switch (profile) {
	case YKDF_X25519:
		memcpy(key, okm, 32);
		ykdf_clamp_x25519(key);
		results[0] = (expected_t){ "secret_key_hex", to_hex(key, 32) };
		return 1;
	case YKDF_ED25519:
		results[0] = (expected_t){ "ed25519_seed_hex", to_hex(okm, okm_len) };
		return 1;
	case YKDF_AGE_X25519:
		memcpy(key, okm, 32);
		ykdf_clamp_x25519(key);
		if (ykdf_age_identity(key, age, sizeof age) != 0)
			return -1;
		results[0] = (expected_t){ "age_secret_key_hex", to_hex(key, 32) };
		results[1] = (expected_t){ "age_identity", strdup(age) };
		return 2;
	case YKDF_SYMMETRIC:
		results[0] = (expected_t){ "secret_key_hex", to_hex(okm, okm_len) };
		return 1;
	case YKDF_MLKEM512:
	case YKDF_MLKEM768:
	case YKDF_MLKEM1024:
		if (ykdf_mlkem_ek(profile, okm, pub, sizeof pub, &pub_len) != 0)
			return -1;
		results[0] = (expected_t){ "mlkem_dk_hex", to_hex(okm, okm_len) };
		results[1] = (expected_t){ "mlkem_ek_hex", to_hex(pub, pub_len) };
		return 2;
	case YKDF_MLDSA44:
	case YKDF_MLDSA65:
	case YKDF_MLDSA87:
		if (ykdf_mldsa_vk(profile, okm, pub, sizeof pub, &pub_len) != 0)
			return -1;
		results[0] = (expected_t){ "mldsa_sk_hex", to_hex(okm, okm_len) };
		results[1] = (expected_t){ "mldsa_vk_hex", to_hex(pub, pub_len) };
		return 2;
	case YKDF_RAW:
		results[0] = (expected_t){ "raw_hex", to_hex(okm, okm_len) };
		return 1;
	default:
		return -1;
	}
}

static int run_vector(const vector_t *v)
{
	ykdf_pipeline pipeline = ykdf_pipeline_from_str(v->pipeline);
	ykdf_profile profile = ykdf_profile_from_str(v->profile);
	if (pipeline == YKDF_PIPELINE_INVALID || profile == YKDF_PROFILE_INVALID) {
		fprintf(stderr, "%s: unknown pipeline/profile\n", v->name);
		return -1;
	}
	if (!ykdf_accepts(profile, pipeline)) {
		fprintf(stderr, "%s: profile rejects pipeline\n", v->name);
		return -1;
	}

	uint8_t ikm[64];
	size_t ikm_len = from_hex(v->ikm_hex, ikm, sizeof ikm);
	uint8_t master[YKDF_MASTER_LEN];
	if (ikm_len == 0 || ykdf_extract(pipeline, ikm, ikm_len, master) != 0) {
		fprintf(stderr, "%s: extract failed\n", v->name);
		return -1;
	}
	if (v->passphrase[0] && ykdf_cascade(pipeline, master, v->passphrase) != 0) {
		fprintf(stderr, "%s: cascade failed\n", v->name);
		return -1;
	}

	char *master_hex = to_hex(master, sizeof master);
	int ok = master_hex && strcmp(master_hex, v->master_key_hex) == 0;
	if (!ok)
		fprintf(stderr, "%s: master mismatch\n  got %s\n want %s\n", v->name,
		        master_hex ? master_hex : "(alloc)", v->master_key_hex);
	free(master_hex);
	if (!ok)
		return -1;

	size_t length = profile == YKDF_RAW ? (size_t)v->length
	                                    : (size_t)ykdf_expand_length(profile);
	uint8_t okm[256];
	char context[160];
	if (ykdf_context(context, sizeof context, pipeline, profile, v->purpose,
	                 v->index) != 0 ||
	    length > sizeof okm ||
	    ykdf_expand(pipeline, master, context, length, okm) != 0) {
		fprintf(stderr, "%s: expand failed\n", v->name);
		return -1;
	}

	char *exp_hex = to_hex(okm, length);
	ok = exp_hex && strcmp(exp_hex, v->expanded_hex) == 0;
	if (!ok)
		fprintf(stderr, "%s: expanded mismatch\n  got %s\n want %s\n", v->name,
		        exp_hex ? exp_hex : "(alloc)", v->expanded_hex);
	free(exp_hex);
	if (!ok)
		return -1;

	expected_t results[2] = { { 0 } };
	int nres = compute_outputs(profile, okm, length, results);
	if (nres < 0) {
		fprintf(stderr, "%s: post-processing failed\n", v->name);
		return -1;
	}
	int rc = 0;
	for (int i = 0; i < 2 && v->outputs[i].field; i++) {
		const char *want = v->outputs[i].value;
		const char *got = NULL;
		for (int j = 0; j < nres; j++)
			if (strcmp(results[j].field, v->outputs[i].field) == 0)
				got = results[j].value;
		if (!got || strcmp(got, want) != 0) {
			fprintf(stderr, "%s: output %s mismatch\n  got %s\n want %s\n",
			        v->name, v->outputs[i].field, got ? got : "(missing)", want);
			rc = -1;
		}
	}
	for (int j = 0; j < nres; j++)
		free((void *)results[j].value);
	return rc;
}

int main(void)
{
	if (sodium_init() < 0) {
		fprintf(stderr, "libsodium init failed\n");
		return 2;
	}
	if (strcmp(VECTORS_VERSION, YKDF_VERSION) != 0) {
		fprintf(stderr, "vector file is %s, implementation targets %s\n",
		        VECTORS_VERSION, YKDF_VERSION);
		return 2;
	}

	size_t passed = 0, failed = 0;
	for (size_t i = 0; i < VECTORS_LEN; i++) {
		if (run_vector(&VECTORS[i]) == 0) {
			printf("ok   %s\n", VECTORS[i].name);
			passed++;
		} else {
			printf("FAIL %s\n", VECTORS[i].name);
			failed++;
		}
	}
	printf("\n%zu passed, %zu failed (of %zu)\n", passed, failed, VECTORS_LEN);
	return failed == 0 ? 0 : 1;
}
