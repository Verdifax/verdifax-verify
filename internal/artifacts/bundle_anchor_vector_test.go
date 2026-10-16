package artifacts

// Shared golden vector for the anchored record digest and the bundle
// leaf. THIS TEST AND ITS FIXTURE ARE IDENTICAL IN THE ORCHESTRATOR
// AND THE PUBLIC VERIFIER (internal/artifacts in both repositories),
// with the same pinned hex, so the producer and the verifier cannot
// drift apart without a failure on each side.
//
// The fixture is the live run 237 record with synthetic SEV-SNP
// evidence (including a verification claim), an inline payload, and
// a scaffold note containing characters JSON escapes, so every pair
// of the recipe is exercised with non-empty input. The pinned values
// were also reproduced by an independent implementation of the recipe
// written without Go (Python, json.dumps with Go's HTML escaping), so
// the recipe comment in bundle_anchor.go is sufficient to rebuild it.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const (
	vectorAnchoredDigest = "47b3acb69b74b33c904da04e3df2e5edf97f88b8009cd273bbb35464882e4f26"
	vectorBundleLeaf     = "bac80efef6aab88f77c7c6c3922ebd5f4ce39dc66c843e703c5661601f928775"
)

var vectorPairs = map[string]string{
	"bundle_hash":         "9ad8417869cc4a06b348354b64fface1ec2968cd1096965ec7ba074549dd988f",
	"pre_anchor_digest":   "59d7faafa3490f27ba8318f5a5213215f5a84b7b557f2fbdc8adead2f577c8e6",
	"nrep_section":        "bb8da8f2a0a4b18eb139eaa8574d9d44082db63ab3e5a85f7cf35346ee2ef2a5",
	"aivp_t4_section":     "10ec84fe96c0a8a8f9fc1faa89c8153d6741ab3ff45d1d8b282d2e0242c472bf",
	"formal_verification": "9746d12073dc3e26d32d729d5341b9fa8423be949e5d397cdba06b4b2a5b4134",
	"execution_record":    "0da330cfa0a3833f4ad84030701d938151cfa4bd3dc641287a1fb4f706a59d61",
	"runtime_timing":      "f63b1bcfa13dd96756955cb92427f697f270fd8045137ab039cdf6587d2f13fb",
	"hardware_evidence":   "ef64d0dd104d1476159b74f94b4f2decbc317e63896b2cf49f38df31d615621e",
	"pote_ledger":         "7c9826f49347e1cae82a18467433fc7899447433a3bf970ecad681ea78e0103e",
	"scaffold_notes":      "0006078ad5b8b38a59d8c459d2edab3cc53d78d6df906506714d69418211ea90",
	"seal_references":     "2b715eb0399123c996686dd82ab32640277f686648b86a878fd8b64f251acb81",
	"section_residue":     "830d8ab1f2ddcb678a2365aaa50e21a3cdf31dafa4b3caee3dca67f068fadf43",
	"record_metadata":     "0cf9658bb0a7620f74ec4e8c9b0a97e000f47cc2252e4ee594062383cf9f6004",
}

func TestBundleAnchorGoldenVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "bundle-anchor-vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var b AuditBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if b.HardwareAttestation.Verification == nil {
		t.Fatal("vector must carry a verification claim")
	}
	pairs := AnchoredRecordPairs(&b)
	if len(pairs) != len(AnchoredRecordNames) || len(pairs) != 13 {
		t.Fatalf("recipe has %d pairs, frozen at 13", len(pairs))
	}
	for i, p := range pairs {
		if p.Name != AnchoredRecordNames[i] {
			t.Errorf("pair %d is %q, frozen order says %q", i, p.Name, AnchoredRecordNames[i])
		}
		if want := vectorPairs[p.Name]; p.Value != want {
			t.Errorf("%s = %s, pinned %s", p.Name, p.Value, want)
		}
	}
	digest := ComputeAnchoredRecordDigest(&b)
	if digest != vectorAnchoredDigest {
		t.Fatalf("anchored record digest = %s, pinned %s", digest, vectorAnchoredDigest)
	}
	if err := ValidateBundleLeafFields(b.Envelope.EnvelopeID, digest); err != nil {
		t.Fatalf("leaf fields: %v", err)
	}
	if got, want := BundleLeafPreimage(b.Envelope.EnvelopeID, digest),
		"verdifax.ledger.bundle.v1."+b.Envelope.EnvelopeID+"."+digest; got != want {
		t.Fatalf("leaf preimage = %q, want %q", got, want)
	}
	if leaf := ComputeBundleLeafHash(b.Envelope.EnvelopeID, digest); leaf != vectorBundleLeaf {
		t.Fatalf("bundle leaf = %s, pinned %s", leaf, vectorBundleLeaf)
	}
}

func TestBundleLeafFieldsRejectAmbiguousInput(t *testing.T) {
	good := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for name, c := range map[string][2]string{
		"empty envelope": {"", good},
		"dotted id":      {"env-1.2", good},
		"short digest":   {"env-1", "abc"},
		"upper digest":   {"env-1", "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"},
		"dotted digest":  {"env-1", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde."},
	} {
		if ValidateBundleLeafFields(c[0], c[1]) == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	if err := ValidateBundleLeafFields("env-0123456789abcdef", good); err != nil {
		t.Errorf("valid fields refused: %v", err)
	}
}
