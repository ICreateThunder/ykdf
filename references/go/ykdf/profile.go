package ykdf

import (
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// ExpandLength returns the fixed expand length for a profile, or 0 for raw,
// whose length is caller-chosen.
func ExpandLength(profile Profile) int {
	switch profile {
	case ProfileX25519, ProfileEd25519, ProfileAgeX25519, ProfileSymmetric,
		ProfileMLDSA44, ProfileMLDSA65, ProfileMLDSA87:
		return 32
	case ProfileMLKEM512, ProfileMLKEM768, ProfileMLKEM1024:
		return 64
	case ProfileRaw:
		return 0
	default:
		return 0
	}
}

// DefaultPipeline returns a profile's default pipeline (§Accept policy).
func DefaultPipeline(profile Profile) Pipeline {
	switch profile {
	case ProfileMLKEM512, ProfileMLKEM768, ProfileMLKEM1024,
		ProfileMLDSA44, ProfileMLDSA65, ProfileMLDSA87:
		return SHAKE256
	default:
		return HKDFSHA512
	}
}

// AcceptsPipeline reports whether a profile accepts a pipeline (§Accept policy).
func AcceptsPipeline(profile Profile, pipeline Pipeline) bool {
	switch profile {
	case ProfileX25519, ProfileEd25519, ProfileAgeX25519, ProfileSymmetric:
		return pipeline == HKDFSHA512 || pipeline == HKDFSHA3512
	case ProfileMLKEM512, ProfileMLKEM768, ProfileMLKEM1024,
		ProfileMLDSA44, ProfileMLDSA65, ProfileMLDSA87:
		return pipeline == SHAKE256
	case ProfileRaw:
		return pipeline == HKDFSHA512 || pipeline == HKDFSHA3512 || pipeline == SHAKE256
	default:
		return false
	}
}

// ClampX25519 applies Curve25519 clamping (RFC 7748) to a 32-byte secret,
// returning a fresh slice.
func ClampX25519(okm []byte) []byte {
	key := make([]byte, 32)
	copy(key, okm)
	key[0] &= 0xF8
	key[31] &= 0x7F
	key[31] |= 0x40
	return key
}

// MLKEMEncapsulationKey runs FIPS 203 key generation on the 64-byte (d || z)
// seed and returns the encoded encapsulation key for the named profile.
func MLKEMEncapsulationKey(profile Profile, seed []byte) ([]byte, error) {
	var scheme kem.Scheme
	switch profile {
	case ProfileMLKEM512:
		scheme = mlkem512.Scheme()
	case ProfileMLKEM768:
		scheme = mlkem768.Scheme()
	case ProfileMLKEM1024:
		scheme = mlkem1024.Scheme()
	default:
		return nil, fmt.Errorf("ykdf: %q is not an ML-KEM profile", profile)
	}
	if len(seed) != scheme.SeedSize() {
		return nil, fmt.Errorf("ykdf: %s seed is %d bytes, want %d", profile, len(seed), scheme.SeedSize())
	}
	pub, _ := scheme.DeriveKeyPair(seed)
	return pub.MarshalBinary()
}

// MLDSAVerifyingKey runs FIPS 204 key generation on the 32-byte seed xi and
// returns the encoded verifying key for the named profile.
func MLDSAVerifyingKey(profile Profile, seed []byte) ([]byte, error) {
	var scheme sign.Scheme
	switch profile {
	case ProfileMLDSA44:
		scheme = mldsa44.Scheme()
	case ProfileMLDSA65:
		scheme = mldsa65.Scheme()
	case ProfileMLDSA87:
		scheme = mldsa87.Scheme()
	default:
		return nil, fmt.Errorf("ykdf: %q is not an ML-DSA profile", profile)
	}
	if len(seed) != scheme.SeedSize() {
		return nil, fmt.Errorf("ykdf: %s seed is %d bytes, want %d", profile, len(seed), scheme.SeedSize())
	}
	pub, _ := scheme.DeriveKey(seed)
	return pub.MarshalBinary()
}
