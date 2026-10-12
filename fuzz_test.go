package main

// Fuzz harness for the verifier's untrusted-input path: bytes in,
// verdict out. The property under test is the robustness half of the
// threat model: arbitrary input must never panic the parse or verify
// path (a crash in a batch pipeline could mask a failing bundle), and
// every parsed bundle must yield a non-nil report whose evidence
// summary builds in both normal and strict mode. Verdict-integrity
// properties (a mutated sealed field must fail) are covered by the
// known-answer and golden-bundle tests; this harness covers the
// input space those tests cannot enumerate.
//
// Run locally:   go test -fuzz=FuzzVerify -fuzztime=60s .
// CI runs this weekly for longer; see .github/workflows/fuzz.yml.

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

func FuzzVerify(f *testing.F) {
	// The production golden bundle is the richest seed: every
	// mutation the fuzzer derives from it starts structurally close
	// to a real bundle, which is where parser bugs live.
	if golden, err := os.ReadFile("internal/artifacts/testdata/golden-bundle-run-208.json"); err == nil {
		f.Add(golden)
	}

	// Minimal shapes that pass the readBundle gate, so the fuzzer
	// reaches verify() from the first generation onward.
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"kind":"aer.v1","manifest_hash":"ab"}`))
	f.Add([]byte(`{"kind":"aer.v1","manifest_hash":"ab","hardware_attestation":{"quote_b64":"!!!not-base64!!!"}}`))
	f.Add([]byte(`{"kind":"aer.v1","manifest_hash":"ab","rekor_anchor":{"log_entry_id":"x","inclusion_proof":{"hashes":["zz"]}}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var b artifacts.AuditBundle
		if err := json.Unmarshal(data, &b); err != nil {
			return // rejected input is a correct outcome
		}
		if b.Kind == "" || b.ManifestHash == "" {
			return // readBundle's gate rejects these before verify
		}
		r := verify(&b)
		if r == nil {
			t.Fatal("verify returned a nil report for a parsed bundle")
		}
		_ = buildEvidenceSummary(&b, r, false)
		_ = buildEvidenceSummary(&b, r, true)
	})
}
