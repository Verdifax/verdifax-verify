package artifacts

import "testing"

// goldenDenyReceipt is a fixed DenyReceipt whose canonical hash is
// frozen below. The expected hash was computed independently (outside
// Go) from the compact-JSON preimage, so this test is a genuine
// known-answer check, not a tautology that would pass even if the
// canonical algorithm silently changed.
func goldenDenyReceipt() *DenyReceipt {
	return &DenyReceipt{
		DecisionReasonCode: "RULE_DENIED",
		DenyClock:          "2026-05-15T12:00:00Z",
		EnvelopeID:         "env-golden-0001",
		EvaluationHash:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		EvaluatorVersion:   "pepg-0.1.0",
		FiredRuleID:        "rule-block-pii",
		MCDFindingHash:     "",
		PolicyHash:         "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Version:            "vfa.deny_receipt.v1",
	}
}

const goldenDenyReceiptHash = "4fef2f62cbb2557ea9b381c61cfcd374ff4e57ed6a3d94ef997f2e250d7a541a"

// TestBuildDenyReceiptHash_Golden pins the canonical hash of a fixed
// DenyReceipt. A change here means the verifier's canonical-hash
// algorithm drifted — which would make it reject bundles the
// orchestrator considers valid. That is exactly the trust-anchor
// failure this test exists to catch.
func TestBuildDenyReceiptHash_Golden(t *testing.T) {
	r := goldenDenyReceipt()
	got, err := BuildDenyReceiptHash(r)
	if err != nil {
		t.Fatalf("BuildDenyReceiptHash returned error: %v", err)
	}
	if got != goldenDenyReceiptHash {
		t.Fatalf("golden deny-receipt hash mismatch:\n  want %s\n  got  %s",
			goldenDenyReceiptHash, got)
	}
	if r.Hash != got {
		t.Fatalf("Hash field not populated: field=%q returned=%q", r.Hash, got)
	}
}

// TestVerifyDenyReceiptHash_RoundTrip proves Build then Verify agree,
// and that the Hash field is not part of its own preimage (Verify must
// zero it, recompute, and match).
func TestVerifyDenyReceiptHash_RoundTrip(t *testing.T) {
	r := goldenDenyReceipt()
	if _, err := BuildDenyReceiptHash(r); err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := VerifyDenyReceiptHash(r); err != nil {
		t.Fatalf("verify of freshly-built receipt failed: %v", err)
	}
}

// TestVerifyDenyReceiptHash_DetectsTamper proves a mutated field is
// caught. If any preimage field is altered after sealing, Verify must
// fail — otherwise the receipt would be forgeable.
func TestVerifyDenyReceiptHash_DetectsTamper(t *testing.T) {
	r := goldenDenyReceipt()
	if _, err := BuildDenyReceiptHash(r); err != nil {
		t.Fatalf("build: %v", err)
	}
	r.FiredRuleID = "rule-allow-everything" // tamper after sealing
	if err := VerifyDenyReceiptHash(r); err == nil {
		t.Fatal("Verify accepted a tampered receipt; must reject")
	}
}

// TestBuildDenyReceiptHash_Deterministic proves repeated builds of the
// same input produce the same hash (no map iteration or time leakage).
func TestBuildDenyReceiptHash_Deterministic(t *testing.T) {
	h1, err := BuildDenyReceiptHash(goldenDenyReceipt())
	if err != nil {
		t.Fatal(err)
	}
	h2, err := BuildDenyReceiptHash(goldenDenyReceipt())
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("non-deterministic hash: %s vs %s", h1, h2)
	}
}
