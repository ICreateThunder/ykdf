package ykdf

import (
	"crypto/hmac"
	"crypto/sha3"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/argon2"
)

// hashFor returns the HMAC hash constructor for an HKDF pipeline.
func hashFor(pipeline Pipeline) func() hash.Hash {
	if pipeline == HKDFSHA3512 {
		return func() hash.Hash { return sha3.New512() }
	}
	return sha512.New
}

// hkdfExtract is HKDF-Extract (RFC 5869 §2.2): HMAC-H(salt, IKM). It is also
// the cascade step, where the prior master key takes the salt position.
func hkdfExtract(pipeline Pipeline, salt, ikm []byte) []byte {
	mac := hmac.New(hashFor(pipeline), salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpand is HKDF-Expand (RFC 5869 §2.3) with PRK = master key:
//
//	T(i) = HMAC-H(prk, T(i-1) || info || byte(i)),  okm = T(1)||T(2)||... [:length]
func hkdfExpand(pipeline Pipeline, prk, info []byte, length int) []byte {
	h := hashFor(pipeline)
	okm := make([]byte, 0, length)
	var prev []byte
	for i := 1; len(okm) < length; i++ {
		mac := hmac.New(h, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		prev = mac.Sum(nil)
		okm = append(okm, prev...)
	}
	return okm[:length]
}

// shake256 absorbs input and squeezes length bytes (FIPS 202).
func shake256(input []byte, length int) []byte {
	return sha3.SumSHAKE256(input, length)
}

// stretch runs the fixed-cost Argon2id passphrase stretch (§3.1), 64-byte out.
func stretch(passphrase string) []byte {
	return argon2.IDKey(
		[]byte(passphrase),
		[]byte(argonSalt),
		argonTime,
		argonMemory,
		argonThreads,
		masterKeyLen,
	)
}
