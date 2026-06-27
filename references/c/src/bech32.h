#ifndef YKDF_BECH32_H
#define YKDF_BECH32_H

#include <stddef.h>
#include <stdint.h>

/* Encode data as a lower-case Bech32 string (BIP-173, checksum constant 1, not
 * Bech32m) under the given human-readable part. Writes a NUL-terminated string.
 * Returns 0 on success, -1 if the output buffer is too small. */
int ykdf_bech32_encode(const char *hrp, const uint8_t *data, size_t data_len,
                       char *out, size_t out_len);

#endif /* YKDF_BECH32_H */
