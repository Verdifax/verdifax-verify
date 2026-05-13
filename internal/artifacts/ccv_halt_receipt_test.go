package artifacts

import (
	"errors"
	"testing"
)

func sampleCCVHaltReceipt() *CCVHaltReceipt {
	return &CCVHaltReceipt{
		Version:              "vfa.ccv_halt.v1",
		EnvelopeID:           "env-test-001",
		AllowTokenHash:       "1111111111111111111111111111111111111111111111111111111111111111",
		BudgetHash:           "2222222222222222222222222222222222222222222222222222222222222222",
		ConstraintType:       "token_budget",
		HaltReasonCode:       "TOKEN_BUDGET_EXCEEDED",
		BudgetLimit:          1000,
		ConsumedAtHalt:       1500,
		PartialExecutionHash: "3333333333333333333333333333333333333333333333333333333333333333",
		EvaluatorVersion:     "ccv-0.1.0-test",
		HaltClock:            "2026-05-15T12:00:00Z",
	}
}

func ccvHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func TestBuildCCVHaltReceiptHash_PopulatesHash(t *testing.T) {
	r := sampleCCVHaltReceipt()
	hash, err := BuildCCVHaltReceiptHash(r)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !ccvHex64(hash) {
		t.Errorf("not §0-compliant: %q", hash)
	}
	if r.Hash != hash {
		t.Errorf("r.Hash = %q, want %q", r.Hash, hash)
	}
}

func TestBuildCCVHaltReceiptHash_Deterministic(t *testing.T) {
	a := sampleCCVHaltReceipt()
	b := sampleCCVHaltReceipt()
	hA, _ := BuildCCVHaltReceiptHash(a)
	hB, _ := BuildCCVHaltReceiptHash(b)
	if hA != hB {
		t.Errorf("non-deterministic: %s vs %s", hA, hB)
	}
}

func TestVerifyCCVHaltReceiptHash_Pristine(t *testing.T) {
	r := sampleCCVHaltReceipt()
	if _, err := BuildCCVHaltReceiptHash(r); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := VerifyCCVHaltReceiptHash(r); err != nil {
		t.Errorf("pristine receipt failed verification: %v", err)
	}
}

func TestVerifyCCVHaltReceiptHash_DetectsTampering(t *testing.T) {
	good := sampleCCVHaltReceipt()
	if _, err := BuildCCVHaltReceiptHash(good); err != nil {
		t.Fatalf("Build: %v", err)
	}

	mutations := []struct {
		field  string
		mutate func(r *CCVHaltReceipt)
	}{
		{"EnvelopeID", func(r *CCVHaltReceipt) { r.EnvelopeID = "env-tampered" }},
		{"AllowTokenHash", func(r *CCVHaltReceipt) {
			r.AllowTokenHash = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"BudgetHash", func(r *CCVHaltReceipt) {
			r.BudgetHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}},
		{"ConstraintType", func(r *CCVHaltReceipt) { r.ConstraintType = "cost_budget" }},
		{"HaltReasonCode", func(r *CCVHaltReceipt) { r.HaltReasonCode = "TIME_BUDGET_EXCEEDED" }},
		{"BudgetLimit", func(r *CCVHaltReceipt) { r.BudgetLimit = 9999 }},
		{"ConsumedAtHalt", func(r *CCVHaltReceipt) { r.ConsumedAtHalt = 999 }},
		{"PartialExecutionHash", func(r *CCVHaltReceipt) {
			r.PartialExecutionHash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		}},
		{"EvaluatorVersion", func(r *CCVHaltReceipt) { r.EvaluatorVersion = "ccv-malicious-0.0.0" }},
		{"HaltClock", func(r *CCVHaltReceipt) { r.HaltClock = "1999-01-01T00:00:00Z" }},
		{"Version", func(r *CCVHaltReceipt) { r.Version = "vfa.ccv_halt.v999" }},
	}

	for _, m := range mutations {
		m := m
		t.Run("tampered_"+m.field, func(t *testing.T) {
			tampered := *good
			m.mutate(&tampered)
			err := VerifyCCVHaltReceiptHash(&tampered)
			if err == nil {
				t.Fatalf("tampering with %s went undetected", m.field)
			}
			if !errors.Is(err, ErrCCVHaltReceiptHashMismatch) {
				t.Errorf("expected ErrCCVHaltReceiptHashMismatch, got %v", err)
			}
		})
	}
}
