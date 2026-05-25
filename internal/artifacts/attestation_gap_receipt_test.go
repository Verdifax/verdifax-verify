package artifacts

import (
	"reflect"
	"testing"
)

func newTestGapReceipt() *AttestationGapReceipt {
	return &AttestationGapReceipt{
		Version:            "vfa.attestation_gap_receipt.v1",
		DecisionReasonCode: "ATTESTATION_GAP",
		EnvelopeID:         "abc123",
		EvaluatorVersion:   "pepg-0.1.0",
		GapClock:           "2026-05-08T00:00:00.000Z",
		MissingFields:      []string{"actor_role", "model_provider"},
		PolicyHash:         "deadbeef",
		PolicyID:           "healthcare-baseline-v1",
		PolicyName:         "Healthcare Baseline",
		ProfileTag:         "healthcare_baseline_v1",
		RequiredFields:     []string{"actor_id", "actor_role", "model_provider"},
	}
}

// 1. Hash is deterministic, same input → same output.
func TestBuildAttestationGapReceiptHash_Deterministic(t *testing.T) {
	r1 := newTestGapReceipt()
	r2 := newTestGapReceipt()
	h1, err := BuildAttestationGapReceiptHash(r1)
	if err != nil {
		t.Fatalf("hash 1: %v", err)
	}
	h2, err := BuildAttestationGapReceiptHash(r2)
	if err != nil {
		t.Fatalf("hash 2: %v", err)
	}
	if h1 != h2 {
		t.Errorf("non-deterministic hash: h1=%s h2=%s", h1, h2)
	}
	if r1.Hash != h1 {
		t.Errorf("Hash field not populated: got %q want %q", r1.Hash, h1)
	}
}

// 2. Verify round-trips on a freshly-built receipt.
func TestVerifyAttestationGapReceiptHash_RoundTrip(t *testing.T) {
	r := newTestGapReceipt()
	if _, err := BuildAttestationGapReceiptHash(r); err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := VerifyAttestationGapReceiptHash(r); err != nil {
		t.Errorf("verify failed: %v", err)
	}
}

// 3. Tampering with any sealed field invalidates the hash.
func TestVerifyAttestationGapReceiptHash_TamperDetection(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r *AttestationGapReceipt)
	}{
		{"missing fields", func(r *AttestationGapReceipt) {
			r.MissingFields = []string{"different"}
		}},
		{"required fields", func(r *AttestationGapReceipt) {
			r.RequiredFields = []string{"actor_id"}
		}},
		{"policy hash", func(r *AttestationGapReceipt) { r.PolicyHash = "tampered" }},
		{"policy id", func(r *AttestationGapReceipt) { r.PolicyID = "different-policy" }},
		{"profile tag", func(r *AttestationGapReceipt) { r.ProfileTag = "different_tag" }},
		{"envelope id", func(r *AttestationGapReceipt) { r.EnvelopeID = "tampered" }},
		{"gap clock", func(r *AttestationGapReceipt) { r.GapClock = "2026-12-25T00:00:00.000Z" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestGapReceipt()
			if _, err := BuildAttestationGapReceiptHash(r); err != nil {
				t.Fatalf("build: %v", err)
			}
			tc.mutate(r)
			if err := VerifyAttestationGapReceiptHash(r); err == nil {
				t.Errorf("verify did not catch tampering with %s", tc.name)
			}
		})
	}
}

// 4. Hash is stable across slice ordering, passing unsorted slices
// produces the same hash as passing pre-sorted ones (defensive sort
// inside the builder).
func TestBuildAttestationGapReceiptHash_StableAcrossSliceOrdering(t *testing.T) {
	sorted := newTestGapReceipt()
	if _, err := BuildAttestationGapReceiptHash(sorted); err != nil {
		t.Fatalf("hash sorted: %v", err)
	}

	unsorted := newTestGapReceipt()
	unsorted.MissingFields = []string{"model_provider", "actor_role"} // reverse order
	unsorted.RequiredFields = []string{"model_provider", "actor_role", "actor_id"} // reverse order
	if _, err := BuildAttestationGapReceiptHash(unsorted); err != nil {
		t.Fatalf("hash unsorted: %v", err)
	}

	if sorted.Hash != unsorted.Hash {
		t.Errorf("hash changed under slice reorder: sorted=%s unsorted=%s",
			sorted.Hash, unsorted.Hash)
	}
}

// 5. HumanSummary produces non-empty buyer-readable text when there's a gap.
func TestAttestationGapReceipt_HumanSummary(t *testing.T) {
	r := newTestGapReceipt()
	got := r.HumanSummary()
	if got == "" {
		t.Error("HumanSummary returned empty string")
	}
	// Sanity: should mention each missing field by name.
	for _, f := range r.MissingFields {
		if !contains(got, f) {
			t.Errorf("HumanSummary did not mention missing field %q; got: %q", f, got)
		}
	}
	// Should mention the profile tag.
	if !contains(got, r.ProfileTag) {
		t.Errorf("HumanSummary did not mention profile tag %q; got: %q", r.ProfileTag, got)
	}
}

// 6. HumanSummary on nil / empty-missing receipt returns the no-gap line.
func TestAttestationGapReceipt_HumanSummary_NoGap(t *testing.T) {
	if got := (*AttestationGapReceipt)(nil).HumanSummary(); got == "" {
		t.Error("nil receipt should return non-empty summary")
	}
	r := &AttestationGapReceipt{}
	if got := r.HumanSummary(); !contains(got, "complete") {
		t.Errorf("empty-missing receipt should describe completion; got %q", got)
	}
}

// 7. Hash building canonically sorts the slices inside the receipt
// itself (so a later JSON marshal / re-hash uses the sorted form too).
func TestBuildAttestationGapReceiptHash_NormalizesSliceOrder(t *testing.T) {
	r := &AttestationGapReceipt{
		Version:            "vfa.attestation_gap_receipt.v1",
		DecisionReasonCode: "ATTESTATION_GAP",
		EnvelopeID:         "x",
		EvaluatorVersion:   "pepg-0.1.0",
		GapClock:           "2026-05-08T00:00:00.000Z",
		MissingFields:      []string{"z", "a", "m"},
		PolicyHash:         "h",
		PolicyID:           "id",
		PolicyName:         "name",
		RequiredFields:     []string{"z", "a", "m"},
	}
	if _, err := BuildAttestationGapReceiptHash(r); err != nil {
		t.Fatalf("hash: %v", err)
	}
	wantSorted := []string{"a", "m", "z"}
	if !reflect.DeepEqual(r.MissingFields, wantSorted) {
		t.Errorf("MissingFields not sorted in place: got %v want %v", r.MissingFields, wantSorted)
	}
	if !reflect.DeepEqual(r.RequiredFields, wantSorted) {
		t.Errorf("RequiredFields not sorted in place: got %v want %v", r.RequiredFields, wantSorted)
	}
}

// (substring helper `contains` is shared with maturity_test.go in this
// same package; no local copy needed here)
