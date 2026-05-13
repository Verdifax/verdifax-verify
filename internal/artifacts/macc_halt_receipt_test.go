package artifacts

import (
	"errors"
	"testing"
)

func sampleMACCHaltReceipt() *MACCHaltReceipt {
	return &MACCHaltReceipt{
		Version:           "vfa.macc_halt.v1",
		EnvelopeID:        "env-test-001",
		TenantID:          "tenant-acme",
		AllowTokenHash:    "1111111111111111111111111111111111111111111111111111111111111111",
		BudgetHash:        "2222222222222222222222222222222222222222222222222222222222222222",
		ConstraintType:    "cumulative_token_budget",
		HaltReasonCode:    "CUMULATIVE_TOKEN_BUDGET_EXCEEDED",
		BudgetLimit:       1000,
		CumulativeAtHalt:  1500,
		PerRunConsumption: 500,
		WindowStart:       "2026-05-15T00:00:00Z",
		EvaluatorVersion:  "macc-0.1.0-test",
		HaltClock:         "2026-05-15T12:00:00Z",
	}
}

func maccHex64(s string) bool {
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

func TestBuildMACCHaltReceiptHash_PopulatesHash(t *testing.T) {
	r := sampleMACCHaltReceipt()
	hash, err := BuildMACCHaltReceiptHash(r)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !maccHex64(hash) {
		t.Errorf("not §0-compliant: %q", hash)
	}
	if r.Hash != hash {
		t.Errorf("r.Hash = %q, want %q", r.Hash, hash)
	}
}

func TestBuildMACCHaltReceiptHash_Deterministic(t *testing.T) {
	a := sampleMACCHaltReceipt()
	b := sampleMACCHaltReceipt()
	hA, _ := BuildMACCHaltReceiptHash(a)
	hB, _ := BuildMACCHaltReceiptHash(b)
	if hA != hB {
		t.Errorf("non-deterministic: %s vs %s", hA, hB)
	}
}

func TestVerifyMACCHaltReceiptHash_Pristine(t *testing.T) {
	r := sampleMACCHaltReceipt()
	if _, err := BuildMACCHaltReceiptHash(r); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := VerifyMACCHaltReceiptHash(r); err != nil {
		t.Errorf("pristine receipt failed verification: %v", err)
	}
}

func TestVerifyMACCHaltReceiptHash_DetectsTampering(t *testing.T) {
	good := sampleMACCHaltReceipt()
	if _, err := BuildMACCHaltReceiptHash(good); err != nil {
		t.Fatalf("Build: %v", err)
	}

	mutations := []struct {
		field  string
		mutate func(r *MACCHaltReceipt)
	}{
		{"EnvelopeID", func(r *MACCHaltReceipt) { r.EnvelopeID = "env-tampered" }},
		{"TenantID", func(r *MACCHaltReceipt) { r.TenantID = "tenant-attacker" }},
		{"AllowTokenHash", func(r *MACCHaltReceipt) {
			r.AllowTokenHash = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"BudgetHash", func(r *MACCHaltReceipt) {
			r.BudgetHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}},
		{"ConstraintType", func(r *MACCHaltReceipt) { r.ConstraintType = "cumulative_cost_budget" }},
		{"HaltReasonCode", func(r *MACCHaltReceipt) { r.HaltReasonCode = "CUMULATIVE_COST_BUDGET_EXCEEDED" }},
		{"BudgetLimit", func(r *MACCHaltReceipt) { r.BudgetLimit = 99999 }},
		{"CumulativeAtHalt", func(r *MACCHaltReceipt) { r.CumulativeAtHalt = 1 }},
		{"PerRunConsumption", func(r *MACCHaltReceipt) { r.PerRunConsumption = 9999 }},
		{"WindowStart", func(r *MACCHaltReceipt) { r.WindowStart = "1999-01-01T00:00:00Z" }},
		{"EvaluatorVersion", func(r *MACCHaltReceipt) { r.EvaluatorVersion = "macc-malicious-0.0.0" }},
		{"HaltClock", func(r *MACCHaltReceipt) { r.HaltClock = "1999-01-01T00:00:00Z" }},
		{"Version", func(r *MACCHaltReceipt) { r.Version = "vfa.macc_halt.v999" }},
	}

	for _, m := range mutations {
		m := m
		t.Run("tampered_"+m.field, func(t *testing.T) {
			tampered := *good
			m.mutate(&tampered)
			err := VerifyMACCHaltReceiptHash(&tampered)
			if err == nil {
				t.Fatalf("tampering with %s went undetected", m.field)
			}
			if !errors.Is(err, ErrMACCHaltReceiptHashMismatch) {
				t.Errorf("expected ErrMACCHaltReceiptHashMismatch, got %v", err)
			}
		})
	}
}
