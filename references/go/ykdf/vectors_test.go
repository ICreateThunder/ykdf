package ykdf

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// vectorFile is the canonical conformance suite, shared with the Rust
// implementation. There is one source of truth; this reference reads it in
// place rather than vendoring a copy.
const vectorFile = "../../../vectors/v1.json"

type vector struct {
	Name         string            `json:"name"`
	Pipeline     Pipeline          `json:"pipeline"`
	Profile      Profile           `json:"profile"`
	Purpose      string            `json:"purpose"`
	Index        uint32            `json:"index"`
	Length       int               `json:"length"`
	IKMHex       string            `json:"ikm_hex"`
	Passphrase   string            `json:"passphrase"`
	MasterKeyHex string            `json:"master_key_hex"`
	ExpandedHex  string            `json:"expanded_hex"`
	Output       map[string]string `json:"output"`
}

type suite struct {
	Version string   `json:"version"`
	Vectors []vector `json:"vectors"`
}

func loadSuite(t *testing.T) suite {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(vectorFile))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var s suite
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if s.Version != Version {
		t.Fatalf("vector file is %q, this implementation targets %q", s.Version, Version)
	}
	if len(s.Vectors) == 0 {
		t.Fatal("no vectors loaded")
	}
	return s
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// expandLengthFor resolves the output length: raw carries its own, every other
// profile is fixed by the spec.
func expandLengthFor(v vector) int {
	if v.Profile == ProfileRaw {
		return v.Length
	}
	return ExpandLength(v.Profile)
}

// derive walks the pipeline stage by stage so a mismatch pinpoints which stage
// diverged, returning the master key, expanded okm, and named profile outputs.
func derive(t *testing.T, v vector) (master, okm []byte, outputs map[string]string) {
	t.Helper()
	ikm := mustHex(t, v.IKMHex)

	master, err := Extract(v.Pipeline, ikm)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if v.Passphrase != "" {
		master, err = Cascade(v.Pipeline, master, v.Passphrase)
		if err != nil {
			t.Fatalf("cascade: %v", err)
		}
	}

	okm, err = Expand(v.Pipeline, master, Context(v.Pipeline, v.Profile, v.Purpose, v.Index), expandLengthFor(v))
	if err != nil {
		t.Fatalf("expand: %v", err)
	}

	outputs = profileOutputs(t, v.Profile, okm)
	return master, okm, outputs
}

// profileOutputs applies the profile post-processing, keyed by the same field
// names the vector file uses.
func profileOutputs(t *testing.T, profile Profile, okm []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	switch profile {
	case ProfileX25519:
		out["secret_key_hex"] = hex.EncodeToString(ClampX25519(okm))
	case ProfileEd25519:
		out["ed25519_seed_hex"] = hex.EncodeToString(okm)
	case ProfileAgeX25519:
		clamped := ClampX25519(okm)
		out["age_secret_key_hex"] = hex.EncodeToString(clamped)
		id, err := AgeIdentity(clamped)
		if err != nil {
			t.Fatalf("age identity: %v", err)
		}
		out["age_identity"] = id
	case ProfileSymmetric:
		out["secret_key_hex"] = hex.EncodeToString(okm)
	case ProfileMLKEM512, ProfileMLKEM768, ProfileMLKEM1024:
		out["mlkem_dk_hex"] = hex.EncodeToString(okm)
		ek, err := MLKEMEncapsulationKey(profile, okm)
		if err != nil {
			t.Fatalf("ml-kem keygen: %v", err)
		}
		out["mlkem_ek_hex"] = hex.EncodeToString(ek)
	case ProfileMLDSA44, ProfileMLDSA65, ProfileMLDSA87:
		out["mldsa_sk_hex"] = hex.EncodeToString(okm)
		vk, err := MLDSAVerifyingKey(profile, okm)
		if err != nil {
			t.Fatalf("ml-dsa keygen: %v", err)
		}
		out["mldsa_vk_hex"] = hex.EncodeToString(vk)
	case ProfileRaw:
		out["raw_hex"] = hex.EncodeToString(okm)
	default:
		t.Fatalf("unknown profile %q", profile)
	}
	return out
}

func TestVectors(t *testing.T) {
	s := loadSuite(t)
	for _, v := range s.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if !AcceptsPipeline(v.Profile, v.Pipeline) {
				t.Fatalf("vector pairs profile %q with disallowed pipeline %q", v.Profile, v.Pipeline)
			}

			master, okm, outputs := derive(t, v)

			if got := hex.EncodeToString(master); got != v.MasterKeyHex {
				t.Fatalf("master key mismatch\n got %s\nwant %s", got, v.MasterKeyHex)
			}
			if got := hex.EncodeToString(okm); got != v.ExpandedHex {
				t.Fatalf("expanded mismatch\n got %s\nwant %s", got, v.ExpandedHex)
			}
			for field, want := range v.Output {
				got, ok := outputs[field]
				if !ok {
					t.Fatalf("vector expects output %q the implementation did not produce", field)
				}
				if got != want {
					t.Fatalf("output %s mismatch\n got %s\nwant %s", field, got, want)
				}
			}
		})
	}
}
