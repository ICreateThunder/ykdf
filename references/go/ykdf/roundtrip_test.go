package ykdf

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// The vector test proves the encoded public keys match the canonical bytes.
// These round-trips prove the derived seeds yield genuinely usable keypairs:
// an ML-KEM seed encapsulates and decapsulates to the same shared secret, and
// an ML-DSA seed produces a signature its own verifying key accepts. This
// mirrors the cross-checks in the Rust suite (docs/SPEC.md §Test vectors).

// seedFor runs the real pipeline for a profile, returning the post-expand seed.
func seedFor(t *testing.T, pipeline Pipeline, profile Profile) []byte {
	t.Helper()
	ikm := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	master, err := Extract(pipeline, ikm)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	okm, err := Expand(pipeline, master, Context(pipeline, profile, "test", 0), ExpandLength(profile))
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	return okm
}

func mlkemScheme(profile Profile) kem.Scheme {
	switch profile {
	case ProfileMLKEM512:
		return mlkem512.Scheme()
	case ProfileMLKEM768:
		return mlkem768.Scheme()
	default:
		return mlkem1024.Scheme()
	}
}

func mldsaScheme(profile Profile) sign.Scheme {
	switch profile {
	case ProfileMLDSA44:
		return mldsa44.Scheme()
	case ProfileMLDSA65:
		return mldsa65.Scheme()
	default:
		return mldsa87.Scheme()
	}
}

func TestMLKEMRoundTrip(t *testing.T) {
	for _, profile := range []Profile{ProfileMLKEM512, ProfileMLKEM768, ProfileMLKEM1024} {
		t.Run(string(profile), func(t *testing.T) {
			scheme := mlkemScheme(profile)
			pub, priv := scheme.DeriveKeyPair(seedFor(t, SHAKE256, profile))
			ct, ss1, err := scheme.Encapsulate(pub)
			if err != nil {
				t.Fatalf("encapsulate: %v", err)
			}
			ss2, err := scheme.Decapsulate(priv, ct)
			if err != nil {
				t.Fatalf("decapsulate: %v", err)
			}
			if !bytes.Equal(ss1, ss2) {
				t.Fatal("shared secrets differ: ML-KEM round-trip failed")
			}
		})
	}
}

func TestMLDSARoundTrip(t *testing.T) {
	msg := []byte("ykdf reference round-trip")
	for _, profile := range []Profile{ProfileMLDSA44, ProfileMLDSA65, ProfileMLDSA87} {
		t.Run(string(profile), func(t *testing.T) {
			scheme := mldsaScheme(profile)
			pub, priv := scheme.DeriveKey(seedFor(t, SHAKE256, profile))
			sig := scheme.Sign(priv, msg, nil)
			if !scheme.Verify(pub, msg, sig, nil) {
				t.Fatalf("%s signature rejected", profile)
			}
		})
	}
}
