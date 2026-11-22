package policyhash

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/psleval"
)

// Round 64 (v0.38.0): testdata/round64/round64_parity.json was written by the
// server's own psl.Parse and psl.PolicyHash (verdifax-orchestrator
// internal/pepg/psl, round 64 build of 2026-11-17): a policy using each new
// field, and each malformed form the server refuses. The verifier must hash
// every accepted one exactly as the server does and refuse every refused one.
func TestRound64PoliciesHashAsTheServerDoes(t *testing.T) {
	raw, readErr := os.ReadFile(filepath.Join("testdata", "round64", "round64_parity.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	var vectors []struct {
		Name     string `json:"name"`
		Document string `json:"document"`
		Hash     string `json:"policy_hash"`
		Refused  string `json:"refused"`
	}
	if decodeErr := json.Unmarshal(raw, &vectors); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	accepted, refused := 0, 0
	for _, v := range vectors {
		got, err := FromDocument([]byte(v.Document))
		switch {
		case v.Refused != "" && err == nil:
			t.Errorf("%s: the server refuses it (%s), and the verifier hashed it as %s", v.Name, v.Refused, got.PolicyHash)
		case v.Refused != "":
			refused++
		case err != nil:
			t.Errorf("%s: refused: %v", v.Name, err)
		case got.PolicyHash != v.Hash:
			t.Errorf("%s: policy hash %s, the server's %s", v.Name, got.PolicyHash, v.Hash)
		default:
			accepted++
		}
	}
	if accepted < 15 || refused < 20 {
		t.Fatalf("the vector file holds %d accepted and %d refused policies; it was cut short", accepted, refused)
	}
}

// The round 64 vector policy, which uses every new field, hashes to the hash
// the server pins (psl.Round64VectorHash), and its review date reads back.
func TestTheRound64VectorHashesAsTheServerPins(t *testing.T) {
	doc, readErr := os.ReadFile(filepath.Join("testdata", "round64", "round64_vector.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	got, err := FromDocument(doc)
	if err != nil || got.PolicyHash != "d0fb2a62f58a45f060ea8e99f611eb1f77e347dabf0e6d7554a26c9d1f1b7ceb" {
		t.Fatalf("policy hash %s (%v)", got.PolicyHash, err)
	}
	by, days, declared, reviewErr := ReviewDeclaration(doc)
	if reviewErr != nil || !declared || by != "" || days != 90 {
		t.Fatalf("review %q %d %v %v", by, days, declared, reviewErr)
	}
	if _, _, declared, _ := ReviewDeclaration([]byte(signOffVectorPolicy)); declared {
		t.Fatal("a policy with no review declares none")
	}
}

// The setup facts a watch may name are the decision code's, in its order.
func TestSetupFactNamesAreTheDecisionsFacts(t *testing.T) {
	if strings.Join(setupFactNames, ",") != strings.Join(psleval.SetupFacts, ",") {
		t.Fatalf("policyhash names %v, the decision code %v", setupFactNames, psleval.SetupFacts)
	}
}
