package rekorverify

import (
	"errors"
	"strings"
	"testing"
)

// The body is the only thing the Merkle proof covers, so it alone ties
// a claimed leaf hash to the log. Through v0.9.0 nothing compared the
// two; these tests hold the comparison in place.
func TestEntryBodyNamesLeaf(t *testing.T) {
	leaf := strings.Repeat("ab", 32)
	body := func(kind, alg, value string) []byte {
		return []byte(`{"apiVersion":"0.0.1","kind":"` + kind + `","spec":{"data":{"hash":` +
			`{"algorithm":"` + alg + `","value":"` + value + `"}}}}`)
	}
	if err := EntryBodyNamesLeaf(body("hashedrekord", "sha256", leaf), leaf); err != nil {
		t.Fatalf("matching body refused: %v", err)
	}
	if err := EntryBodyNamesLeaf(body("hashedrekord", "sha256", strings.ToUpper(leaf)), leaf); err != nil {
		t.Fatalf("hex comparison must be case-insensitive: %v", err)
	}
	for name, b := range map[string][]byte{
		"other leaf":    body("hashedrekord", "sha256", strings.Repeat("cd", 32)),
		"empty value":   body("hashedrekord", "sha256", ""),
		"other kind":    body("rekord", "sha256", leaf),
		"other alg":     body("hashedrekord", "sha512", leaf),
		"not json":      []byte("not json"),
		"empty object":  []byte("{}"),
		"leaf prefixed": body("hashedrekord", "sha256", leaf+"00"),
	} {
		if EntryBodyNamesLeaf(b, leaf) == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

func TestVerifyAnchorWithoutEntryBodyIsNotVerifiable(t *testing.T) {
	in := AnchorInput{
		LeafHashHex:   strings.Repeat("ab", 32),
		LogIndex:      0,
		TreeSize:      1,
		RootHashHex:   strings.Repeat("ab", 32),
		InclusionPath: nil,
		Checkpoint:    "x",
		LogID:         strings.Repeat("00", 32),
	}
	if err := VerifyAnchor(in); !errors.Is(err, ErrNoEntryBody) {
		t.Fatalf("an anchor with no body must report ErrNoEntryBody, got %v", err)
	}
}
