package artifacts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// golden-bundle-run-208.json is a real sealed audit bundle produced by
// the production orchestrator (run 208). It lives in the data room as an
// acquisition artifact. These tests prove the open-source verifier can
// (a) parse a genuine production bundle with its own types and
// (b) recompute the bundle-level canonical hash and match the sealed
// value — i.e. that the trust anchor actually verifies real output, not
// just synthetic fixtures.

func loadGoldenBundle(t *testing.T) *AuditBundle {
	t.Helper()
	path := filepath.Join("testdata", "golden-bundle-run-208.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden bundle: %v", err)
	}
	var b AuditBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("verifier types cannot parse production bundle: %v", err)
	}
	return &b
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TestGoldenBundle_Parses proves the verifier's own AuditBundle type
// round-trips a real production bundle without losing the core sealed
// fields. A failure here means the shipped verifier is schema-
// incompatible with the orchestrator's output — a trust-anchor break.
func TestGoldenBundle_Parses(t *testing.T) {
	b := loadGoldenBundle(t)
	if !hex64.MatchString(b.ManifestHash) {
		t.Fatalf("manifest_hash not a 64-hex digest: %q", b.ManifestHash)
	}
	if !hex64.MatchString(b.BundleHash) {
		t.Fatalf("bundle_hash not a 64-hex digest: %q", b.BundleHash)
	}
	if b.RunID <= 0 {
		t.Fatalf("run_id not populated: %d", b.RunID)
	}
	if !hex64.MatchString(b.Envelope.Hash) {
		t.Fatalf("envelope.hash not recomputed-shaped: %q", b.Envelope.Hash)
	}
}

// TestGoldenBundle_RecomputeMatchesSeal is the core trust-anchor proof:
// recompute the bundle-level canonical hash from the bundle's own
// contents and require it to equal the sealed bundle_hash. If this
// passes, the open-source verifier demonstrably verifies a real
// production run offline. If it fails, the shipped verifier cannot
// verify a bundle already in the data room — which is itself a critical
// finding worth surfacing before a buyer's engineer does.
func TestGoldenBundle_RecomputeMatchesSeal(t *testing.T) {
	b := loadGoldenBundle(t)
	got := RecomputeBundleHash(b)
	if got != b.BundleHash {
		t.Fatalf("bundle hash recompute does not match sealed value:\n"+
			"  sealed     %s\n  recomputed %s\n"+
			"The verifier cannot verify this production bundle. Investigate "+
			"schema drift between the orchestrator that sealed run 208 and "+
			"this verifier version (%s).", b.BundleHash, got, "see main.Version")
	}
}
