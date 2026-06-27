/* Bech32 encoder (BIP-173) for age identities. See bech32.h. */
#include "bech32.h"

#include <string.h>

static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t polymod(const uint8_t *values, size_t len)
{
	static const uint32_t gen[5] = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa,
	                                 0x3d4233dd, 0x2a1462b3 };
	uint32_t chk = 1;
	for (size_t i = 0; i < len; i++) {
		uint32_t top = chk >> 25;
		chk = ((chk & 0x1ffffff) << 5) ^ values[i];
		for (int j = 0; j < 5; j++)
			if ((top >> j) & 1)
				chk ^= gen[j];
	}
	return chk;
}

/* Regroup 8-bit bytes into 5-bit groups, padding the tail. Returns the count. */
static size_t convert_bits(const uint8_t *data, size_t data_len, uint8_t *out)
{
	uint32_t acc = 0;
	int bits = 0;
	size_t n = 0;
	for (size_t i = 0; i < data_len; i++) {
		acc = (acc << 8) | data[i];
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			out[n++] = (acc >> bits) & 31;
		}
	}
	if (bits > 0)
		out[n++] = (acc << (5 - bits)) & 31;
	return n;
}

int ykdf_bech32_encode(const char *hrp, const uint8_t *data, size_t data_len,
                       char *out, size_t out_len)
{
	size_t hrp_len = strlen(hrp);

	/* 5-bit data part. Worst case ceil(data_len*8/5) groups. */
	uint8_t conv[1024];
	if (data_len * 8 / 5 + 1 > sizeof conv)
		return -1;
	size_t conv_len = convert_bits(data, data_len, conv);

	/* Checksum input: hrp_expand || conv || 6 zero symbols. */
	uint8_t values[2048];
	size_t vi = 0;
	if (hrp_len * 2 + 1 + conv_len + 6 > sizeof values)
		return -1;
	for (size_t i = 0; i < hrp_len; i++)
		values[vi++] = (uint8_t)hrp[i] >> 5;
	values[vi++] = 0;
	for (size_t i = 0; i < hrp_len; i++)
		values[vi++] = (uint8_t)hrp[i] & 31;
	for (size_t i = 0; i < conv_len; i++)
		values[vi++] = conv[i];
	for (int i = 0; i < 6; i++)
		values[vi++] = 0;

	uint32_t mod = polymod(values, vi) ^ 1;
	uint8_t checksum[6];
	for (int i = 0; i < 6; i++)
		checksum[i] = (mod >> (5 * (5 - i))) & 31;

	/* hrp || "1" || data symbols || checksum symbols || NUL. */
	size_t need = hrp_len + 1 + conv_len + 6 + 1;
	if (need > out_len)
		return -1;
	size_t oi = 0;
	memcpy(out, hrp, hrp_len);
	oi = hrp_len;
	out[oi++] = '1';
	for (size_t i = 0; i < conv_len; i++)
		out[oi++] = CHARSET[conv[i]];
	for (int i = 0; i < 6; i++)
		out[oi++] = CHARSET[checksum[i]];
	out[oi] = '\0';
	return 0;
}
