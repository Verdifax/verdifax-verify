package main

// Shared golden vector for pre-anchor table v2 and leaf v6. THE FIXTURE
// (testdata/leaf-v6-vector.json) AND THE PINNED HEX BELOW ARE IDENTICAL
// IN THE ORCHESTRATOR (internal/adapters/testdata/leaf-v6-vector.json
// and leaf_v6_vector_test.go there), where the same hex is checked
// against every built-in ledger adapter, so the producer and this
// verifier cannot drift apart without a failure on each side.
//
// Inputs are live run 238's anchored values (a v5 record) with the
// requirement row appended; the expected values are synthetic. They
// were also reproduced by an independent implementation written
// without Go (Python hashlib) from the recipe comments alone, and the
// same script reproduces run 238's stored v1 digest.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

const (
	vectorPreAnchorDigestV2 = "6f5a5b4d8cdf36253b95f82c36b7d612c4942a1d1664994a3eb986398dbeb0f9"
	vectorLeafV6            = "9216b749c8c9fcf4d3cd4146edd7a6278d51a5d8f7faa0f6de983d54e1ea0d68"
)

// pinnedPreAnchorNamesV2 restates the frozen v2 name list; the
// orchestrator pins the same list.
var pinnedPreAnchorNamesV2 = []string{
	"program_id", "route_id", "registry_record_hash", "clock_epoch",
	"attested_digest", "input_hash", "envelope_id", "envelope_hash",
	"transport_hash", "epa_hash", "efa_hash", "aer_hash", "execution_ids",
	"pepg_outcome", "allow_token_hash", "deny_receipt_hash",
	"aivp_outcome", "aivp_adapter_id", "aivp_pia_hash",
	"aivp_ai_output_hash", "aivp_halt_receipt_hash", "transcript_hash",
	"hardware_attestation_hash", "leakage_bundle_hash", "zksp_binding_hash",
	"formal_verifier_status", "migration_token_hash", "replay_fingerprint",
	"nrep_actor_id", "nrep_public_key", "nrep_signature", "nrep_signed_at",
	"scaffold_flags_hash", "complete_record_anchor",
}

func TestLeafV6GoldenVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "leaf-v6-vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v struct {
		EnvelopeID      string                     `json:"envelope_id"`
		AerHash         string                     `json:"aer_hash"`
		ZkspBindingHash string                     `json:"zksp_binding_hash"`
		InputNonce      string                     `json:"input_nonce"`
		PreAnchor       []artifacts.PreAnchorEntry `json:"pre_anchor"`
		WantDigest      string                     `json:"expected_pre_anchor_digest_v2"`
		WantPreimage    string                     `json:"expected_leaf_preimage"`
		WantLeaf        string                     `json:"expected_leaf_hash"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if v.WantDigest != vectorPreAnchorDigestV2 || v.WantLeaf != vectorLeafV6 {
		t.Fatal("fixture expectations disagree with the pinned constants")
	}

	if len(artifacts.PreAnchorNamesV2) != len(pinnedPreAnchorNamesV2) {
		t.Fatalf("v2 list has %d names, pinned %d", len(artifacts.PreAnchorNamesV2), len(pinnedPreAnchorNamesV2))
	}
	for i, n := range pinnedPreAnchorNamesV2 {
		if artifacts.PreAnchorNamesV2[i] != n || v.PreAnchor[i].Name != n {
			t.Fatalf("row %d: list %q, vector %q, pinned %q", i, artifacts.PreAnchorNamesV2[i], v.PreAnchor[i].Name, n)
		}
	}
	// The v2 list is the v1 list plus one row, unchanged before it.
	for i, n := range artifacts.PreAnchorNames {
		if artifacts.PreAnchorNamesV2[i] != n {
			t.Fatalf("v2 row %d %q departs from v1 %q", i, artifacts.PreAnchorNamesV2[i], n)
		}
	}

	if got := artifacts.ComputePreAnchorDigestV2FromTable(v.PreAnchor); got != vectorPreAnchorDigestV2 {
		t.Fatalf("v2 digest = %s, pinned %s", got, vectorPreAnchorDigestV2)
	}
	const run238V1Digest = "98854a347f1a9d83d6427d192f233fbba28dd4563d1ab0e79d717ab77c6d2f1d"
	if got := artifacts.ComputePreAnchorDigestFromTable(v.PreAnchor[:33]); got != run238V1Digest {
		t.Fatalf("v1 digest of the first 33 rows = %s, run 238 stored %s", got, run238V1Digest)
	}

	nonce, err := strconv.ParseInt(v.InputNonce, 10, 64)
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	if got := joinLeafParts(leafDomainV6, v.EnvelopeID, v.AerHash, v.ZkspBindingHash,
		v.InputNonce, vectorPreAnchorDigestV2); got != v.WantPreimage {
		t.Fatalf("preimage = %q, want %q", got, v.WantPreimage)
	}
	b := &artifacts.AuditBundle{
		Envelope:    artifacts.Envelope{EnvelopeID: v.EnvelopeID},
		AER:         artifacts.AER{Seal: artifacts.SealReference{SealedHash: v.AerHash}},
		ZkspBinding: artifacts.ZkspBinding{Seal: artifacts.SealReference{SealedHash: v.ZkspBindingHash}},
		RekorAnchor: artifacts.RekorAnchor{Backend: "rekor", LeafHashHex: vectorLeafV6,
			InputNonce: artifacts.FlexInt64(nonce)},
		PreAnchor:       v.PreAnchor,
		PreAnchorDigest: vectorPreAnchorDigestV2,
	}
	got := verifyLeafBinding(b)
	if got.Form != leafDomainV6 || got.Computed != vectorLeafV6 || !got.Match {
		t.Fatalf("leaf binding: form %s computed %s, pinned %s (%s)", got.Form, got.Computed, vectorLeafV6, got.Reason)
	}
}
