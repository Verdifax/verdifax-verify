package artifacts

// Shared vectors for the AI review block. THIS FILE IS IDENTICAL IN THE
// ORCHESTRATOR AND THE PUBLIC VERIFIER (internal/artifacts in both
// repositories), with the same pinned hex, so the producer and the verifier
// cannot drift apart without a failure on each side.

import "testing"

func reviewVector() *AivpReview {
	return &AivpReview{
		Formula: AivpReviewFormulaV1, PromptID: "statements-v1", Model: "claude-opus-5-5",
		TraceHash:         "5f1c9b8de2a4a6a6f1f0e3c7d0b8a9e2c4d6f8a0b2c4d6e8f0a2b4c6d8e0f2a4",
		CheckerID:         "keyword-v1",
		ContradictionMode: "record", ContradictionOutcome: "recorded",
		Finding: &AivpFinding{NodeA: "node-0001", NodeB: "node-0003", Term: "always", Opposite: "never"},
	}
}

func reviewSection(review *AivpReview) AivpT4Section {
	return AivpT4Section{
		Outcome: "release", Decision: "release", AdapterID: "live-claude-api",
		PiaHash:      "92b2f476e1c4db499dd5559a256fc6d4ef1c6d48fd1abe39705fd45eeac44101",
		AiOutputHash: "55c98007c3d54f2baadfcdf730173f0140190cc4acb963d932320f6fe3053ff4",
		Review:       review,
	}
}

func TestAivpReviewSectionVector(t *testing.T) {
	const withoutReview = "f1265be4ff2863b0229f5b37cd8fa4ddd3f5402c8560de11c27fe480ef9cd15f"
	const withReview = "b902b63c467448078e846d6395cd1e1a850aebb86d2c642cd0850ecd0f600bad"
	if got := ComputeAivpT4SectionHash(reviewSection(nil)); got != withoutReview {
		t.Errorf("section without a review block = %s, pinned %s", got, withoutReview)
	}
	if got := ComputeAivpT4SectionHash(reviewSection(reviewVector())); got != withReview {
		t.Errorf("section with a review block = %s, pinned %s", got, withReview)
	}
	clean := reviewVector()
	clean.ContradictionOutcome, clean.Finding = "clean", nil
	if ComputeAivpT4SectionHash(reviewSection(clean)) == withReview {
		t.Error("the finding and the outcome must be bound into the section hash")
	}
}

func TestAivpReviewHaltReceiptVector(t *testing.T) {
	receipt := func(review *AivpReview, version string) *AivpT4HaltReceipt {
		return &AivpT4HaltReceipt{
			AdapterID: "live-claude-api", AiOutputHash: "55c98007c3d54f2baadfcdf730173f0140190cc4acb963d932320f6fe3053ff4",
			AllowTokenHash: "b3565fd7ca760a89bebc0cb33b2a4d4747ea73ded8033bf45dab6e75a0842dc9", AnchorRequired: true,
			DecisionKind: "halt", DecisionReason: "POLICY_ALLOW · CONTRADICTION · contradiction detected",
			EnvelopeID: "env-ec661802adb850e4", EvaluatorVersion: "aivp-t4-1.0.0",
			HaltClock: "2026-11-09T00:00:00.000000000Z", HaltReasonCode: "AIVP_T4_HALT",
			PiaHash: "92b2f476e1c4db499dd5559a256fc6d4ef1c6d48fd1abe39705fd45eeac44101",
			Version: version, Review: review,
		}
	}
	const v1 = "83aecb32690aef3b7eecbe4bc01257a1e60fa2466c9ce73d5ce56551482318d4"
	const v2 = "35f816aeff105fd2191d989d42cfa3e1c4617b64c22304fbe37b6e9b48cc7e4d"
	halted := reviewVector()
	halted.ContradictionMode, halted.ContradictionOutcome = "halt", "halted"
	if got, _ := BuildAivpT4HaltReceiptHash(receipt(nil, "vfa.aivp_t4_halt.v1")); got != v1 {
		t.Errorf("v1 receipt = %s, pinned %s", got, v1)
	}
	if got, _ := BuildAivpT4HaltReceiptHash(receipt(halted, "vfa.aivp_t4_halt.v2")); got != v2 {
		t.Errorf("v2 receipt = %s, pinned %s", got, v2)
	}
}
