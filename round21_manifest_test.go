package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// manifestVector is production run 249's manifest hash preimage, read
// from the production database. The manifest hash is otherwise
// recomputed only on the Verdifax server; this vector lets anyone
// recompute it, and ties its parts to the public bundle.
type manifestVector struct {
	RunID                 int      `json:"run_id"`
	ManifestHash          string   `json:"manifest_hash"`
	Separator             string   `json:"separator"`
	Parts                 []string `json:"parts"`
	ExecutionRecordFields []string `json:"execution_record_fields"`
}

func TestR21Run249ManifestHashRecomputesFromItsPreimage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "manifest-vectors", "run-249-manifest-preimage.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v manifestVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(strings.Join(v.Parts, v.Separator)))
	if hex.EncodeToString(sum[:]) != v.ManifestHash {
		t.Fatal("the parts do not recompute the manifest hash")
	}

	// The last part is the execution record group: each field as its
	// byte length, a colon and the field, concatenated, then SHA-256.
	var b strings.Builder
	for _, f := range v.ExecutionRecordFields {
		fmt.Fprintf(&b, "%d:%s", len(f), f)
	}
	group := sha256.Sum256([]byte(b.String()))
	if hex.EncodeToString(group[:]) != v.Parts[len(v.Parts)-1] {
		t.Fatal("the execution record fields do not recompute the last part")
	}

	// Only the constant domain tag contains the separator, so the join
	// cannot be split two ways.
	if v.Parts[0] != "orchestrator.manifest.v1" {
		t.Fatalf("first part = %q", v.Parts[0])
	}
	for i, p := range v.Parts[1:] {
		if strings.Contains(p, v.Separator) {
			t.Errorf("part %d contains the separator: %q", i+1, p)
		}
	}

	// The vector belongs to the public record: same manifest hash, and
	// the bundle's own values appear among the parts.
	bundleRaw, err := os.ReadFile(filepath.Join("testdata", "round18", "run-249-production.json"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := artifacts.DecodeBundleStrict(bundleRaw)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.ManifestHash != v.ManifestHash {
		t.Fatalf("bundle manifest hash %s != vector %s", bundle.ManifestHash, v.ManifestHash)
	}
	has := map[string]bool{}
	for _, p := range v.Parts {
		has[p] = true
	}
	for name, want := range map[string]string{
		"envelope_id":      bundle.Envelope.EnvelopeID,
		"rekor leaf hash":  bundle.RekorAnchor.LeafHashHex,
		"rekor log entry":  bundle.RekorAnchor.LogEntryID,
		"actor id":         bundle.Nrep.ActorID,
		"actor public key": bundle.Nrep.PublicKey,
		"actor signature":  bundle.Nrep.Signature,
	} {
		if want == "" || !has[want] {
			t.Errorf("%s %q is not a manifest part", name, want)
		}
	}
	if bundle.ExecutionRecord == nil || v.ExecutionRecordFields[2] != bundle.ExecutionRecord.InputHash {
		t.Error("the execution record's input hash does not match the bundle's")
	}
}
