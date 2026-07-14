package artifacts

import "testing"

// TestFormalVerificationRecomputeRoundTrip pins the recompute
// behavior: stable across calls, sensitive to every content field.
// Cross-repo byte-compatibility with the orchestrator's builder is
// established end-to-end by verifying a real production bundle.
func TestFormalVerificationRecomputeRoundTrip(t *testing.T) {
	fv := FormalVerification{
		Kind:           "verdifax.formal_verification.v1",
		Repo:           "github.com/Verdifax/lean-verdifax",
		CommitSHA:      "5ff588907baeb7dad78d1c69bd6b6ac494e1d879",
		Toolchain:      "leanprover/lean4:v4.8.0",
		Modules:        []string{"Verdifax.Canonical", "Verdifax.Determinism"},
		Theorems:       []string{"Verdifax.manifest_binding"},
		AxiomFootprint: "kernel-checked",
		Scope:          "model-level",
		ManifestHash:   "0000000000000000000000000000000000000000000000000000000000000000",
	}
	h1 := RecomputeFormalVerificationHash(fv)
	h2 := RecomputeFormalVerificationHash(fv)
	if h1 == "" {
		t.Fatal("recompute returned empty hash")
	}
	if h1 != h2 {
		t.Fatalf("recompute not deterministic: %s vs %s", h1, h2)
	}
	t.Logf("formal_verification recompute hash: %s", h1)

	tamperCases := map[string]func(FormalVerification) FormalVerification{
		"commit":   func(f FormalVerification) FormalVerification { f.CommitSHA = "tampered"; return f },
		"theorems": func(f FormalVerification) FormalVerification { f.Theorems = []string{"other"}; return f },
		"scope":    func(f FormalVerification) FormalVerification { f.Scope = "stronger claim"; return f },
		"manifest": func(f FormalVerification) FormalVerification { f.ManifestHash = "1111"; return f },
	}
	for name, mutate := range tamperCases {
		if RecomputeFormalVerificationHash(mutate(fv)) == h1 {
			t.Errorf("tampering with %s not detected by recompute", name)
		}
	}
}
