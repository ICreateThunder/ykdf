package ykdf

import (
	"fmt"
	"strings"
)

// AgeIdentity encodes a 32-byte clamped X25519 secret as an age private key:
// Bech32 (not Bech32m) over HRP "age-secret-key-", then upper-cased, yielding
// AGE-SECRET-KEY-1... (§age-x25519).
func AgeIdentity(secret []byte) (string, error) {
	s, err := bech32Encode("age-secret-key-", secret)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(s), nil
}

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32Polymod is the BIP-173 checksum generator.
func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// bech32HRPExpand expands the human-readable part for checksum input.
func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

// bech32Checksum computes the 6-symbol Bech32 (constant 1) checksum.
func bech32Checksum(hrp string, data []byte) []byte {
	expanded := bech32HRPExpand(hrp)
	// Build the polymod input in a dedicated buffer so the result never depends
	// on whether append happens to reallocate any of the inputs.
	values := make([]byte, 0, len(expanded)+len(data)+6)
	values = append(values, expanded...)
	values = append(values, data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = byte(polymod>>uint(5*(5-i))) & 31
	}
	return out
}

// convertBits regroups bytes from 8-bit to 5-bit groups, padding the tail.
func convertBits(data []byte) []byte {
	var acc uint32
	var bits uint
	out := make([]byte, 0, len(data)*8/5+1)
	for _, b := range data {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, byte(acc>>bits)&31)
		}
	}
	if bits > 0 {
		out = append(out, byte(acc<<(5-bits))&31)
	}
	return out
}

// bech32Encode produces the lower-case Bech32 string for hrp and raw data.
func bech32Encode(hrp string, data []byte) (string, error) {
	conv := convertBits(data)
	checksum := bech32Checksum(hrp, conv)
	combined := make([]byte, 0, len(conv)+len(checksum))
	combined = append(combined, conv...)
	combined = append(combined, checksum...)
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, d := range combined {
		if int(d) >= len(bech32Charset) {
			return "", fmt.Errorf("ykdf: bech32 symbol %d out of range", d)
		}
		sb.WriteByte(bech32Charset[d])
	}
	return sb.String(), nil
}
