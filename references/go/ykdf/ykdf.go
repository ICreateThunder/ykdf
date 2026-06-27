// Package ykdf is an independent Go reference implementation of the YKDF v1
// key-derivation format (see docs/SPEC.md in the repository root).
//
// It exists to corroborate the canonical Rust implementation: both must
// reproduce, byte for byte, every vector pinned in vectors/v1.json. The format
// covers only the deterministic IKM -> extract -> expand -> derive pipeline;
// the YubiKey transport that produces the IKM is out of scope here.
//
// The extract and expand primitives are hand-written straight from the spec
// prose (HKDF per RFC 5869, the SHAKE256 sponge per FIPS 202) rather than
// reusing a higher-level KDF, so that a passing vector run is genuine evidence
// the format is portable and unambiguous, not an artifact of a shared library.
// Only the heavy primitives are delegated: Argon2id (golang.org/x/crypto) and
// ML-KEM / ML-DSA key generation (Cloudflare circl).
package ykdf

import (
	"errors"
	"fmt"
	"strconv"
)

// Format constants. These are frozen by docs/SPEC.md §Constants.
const (
	// Version is the format version embedded in every context string.
	Version = "v1"

	extractSalt       = "ykdf-v1"
	argonSalt         = "ykdf-v1-argon2id"
	stretchDescriptor = "argon2id:m=131072,t=3,p=1"

	masterKeyLen = 64
	minIKMLen    = 16
	maxExpandLen = 255 * 64 // HKDF-Expand's 255-block ceiling (16320 bytes).

	extractTag byte = 0x01 // domain tag for the sponge extract.
	cascadeTag byte = 0x02 // domain tag for the sponge passphrase cascade.

	// Argon2id cost parameters (fixed, not configurable).
	argonTime    = 3
	argonMemory  = 131072 // KiB == 128 MiB.
	argonThreads = 1
)

// Pipeline names the extract/expand primitive pair.
type Pipeline string

// The three v1 pipelines.
const (
	HKDFSHA512  Pipeline = "hkdf-sha512"
	HKDFSHA3512 Pipeline = "hkdf-sha3-512"
	SHAKE256    Pipeline = "shake256"
)

// Profile names the output length and post-processing.
type Profile string

// The v1 profiles.
const (
	ProfileX25519    Profile = "x25519"
	ProfileEd25519   Profile = "ed25519"
	ProfileAgeX25519 Profile = "age-x25519"
	ProfileSymmetric Profile = "symmetric"
	ProfileMLKEM512  Profile = "mlkem512"
	ProfileMLKEM768  Profile = "mlkem768"
	ProfileMLKEM1024 Profile = "mlkem1024"
	ProfileMLDSA44   Profile = "mldsa44"
	ProfileMLDSA65   Profile = "mldsa65"
	ProfileMLDSA87   Profile = "mldsa87"
	ProfileRaw       Profile = "raw"
)

// ErrShortIKM is returned by Extract when the IKM is below the 16-byte floor.
var ErrShortIKM = errors.New("ykdf: IKM must be at least 16 bytes")

// Context builds the canonical context string
//
//	ykdf:v1:<pipeline>:<profile>:<purpose>:<index>
//
// It does not validate the fields; callers that accept untrusted input should
// use ValidatePurpose and the accept policy (see AcceptsPipeline) first.
func Context(pipeline Pipeline, profile Profile, purpose string, index uint32) string {
	return fmt.Sprintf("ykdf:%s:%s:%s:%s:%d", Version, pipeline, profile, purpose, index)
}

// kdfInfo binds the requested output length into the context, per §4.
func kdfInfo(context string, length int) string {
	return context + ":" + strconv.Itoa(length)
}

// Extract maps IKM to the 64-byte master key (§2). It does not apply the
// optional passphrase cascade; call Cascade afterwards when a passphrase is
// supplied.
func Extract(pipeline Pipeline, ikm []byte) ([]byte, error) {
	if len(ikm) < minIKMLen {
		return nil, ErrShortIKM
	}
	switch pipeline {
	case HKDFSHA512, HKDFSHA3512:
		// HKDF-Extract: HMAC-H(salt = "ykdf-v1", IKM).
		return hkdfExtract(pipeline, []byte(extractSalt), ikm), nil
	case SHAKE256:
		// SHAKE256(0x01 || "ykdf-v1" || IKM), squeeze 64.
		input := make([]byte, 0, 1+len(extractSalt)+len(ikm))
		input = append(input, extractTag)
		input = append(input, extractSalt...)
		input = append(input, ikm...)
		defer wipe(input)
		return shake256(input, masterKeyLen), nil
	default:
		return nil, fmt.Errorf("ykdf: unknown pipeline %q", pipeline)
	}
}

// Cascade folds a stretched passphrase into the master key (§3), returning the
// replacement master key. It must run after Extract and before Expand.
func Cascade(pipeline Pipeline, masterKey []byte, passphrase string) ([]byte, error) {
	stretched := stretch(passphrase)
	defer wipe(stretched)

	// cascade_ikm = len(descriptor) || descriptor || stretched(64).
	cascadeIKM := make([]byte, 0, 1+len(stretchDescriptor)+len(stretched))
	cascadeIKM = append(cascadeIKM, byte(len(stretchDescriptor)))
	cascadeIKM = append(cascadeIKM, stretchDescriptor...)
	cascadeIKM = append(cascadeIKM, stretched...)
	defer wipe(cascadeIKM)

	switch pipeline {
	case HKDFSHA512, HKDFSHA3512:
		// HMAC-H(key = master_key, msg = cascade_ikm).
		return hkdfExtract(pipeline, masterKey, cascadeIKM), nil
	case SHAKE256:
		// SHAKE256(0x02 || master_key || cascade_ikm), squeeze 64.
		input := make([]byte, 0, 1+len(masterKey)+len(cascadeIKM))
		input = append(input, cascadeTag)
		input = append(input, masterKey...)
		input = append(input, cascadeIKM...)
		defer wipe(input)
		return shake256(input, masterKeyLen), nil
	default:
		return nil, fmt.Errorf("ykdf: unknown pipeline %q", pipeline)
	}
}

// Expand stretches the master key to length bytes, bound to the context (§5).
func Expand(pipeline Pipeline, masterKey []byte, context string, length int) ([]byte, error) {
	if length < 1 || length > maxExpandLen {
		return nil, fmt.Errorf("ykdf: expand length %d out of range [1, %d]", length, maxExpandLen)
	}
	info := kdfInfo(context, length)
	switch pipeline {
	case HKDFSHA512, HKDFSHA3512:
		return hkdfExpand(pipeline, masterKey, []byte(info), length), nil
	case SHAKE256:
		// SHAKE256(master_key || kdf_info), squeeze length.
		input := make([]byte, 0, len(masterKey)+len(info))
		input = append(input, masterKey...)
		input = append(input, info...)
		defer wipe(input)
		return shake256(input, length), nil
	default:
		return nil, fmt.Errorf("ykdf: unknown pipeline %q", pipeline)
	}
}

// wipe best-effort zeroes a secret-bearing intermediate buffer once it is no
// longer needed. Go has no equivalent of the Rust core's Zeroizing/ZeroizeOnDrop
// guarantees (the compiler may elide the writes, and earlier copies may linger),
// so this is a courtesy, not a hard scrub. This reference exists for byte-level
// conformance; production secret handling is the canonical implementation's job.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
