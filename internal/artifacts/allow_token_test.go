package artifacts

import (
	"errors"
	"testing"
)

// hex64 returns true when s is a 64-char lowercase hex string.
func hex64Token(s string) bool {
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

func sampleAllowToken() *AllowToken {
	return &AllowToken{
		Version:            "vfa.allow_token.v1",
		EnvelopeID:         "env-test-001",
		PolicyHash:         "1111111111111111111111111111111111111111111111111111111111111111",
		EvaluationHash:     "2222222222222222222222222222222222222222222222222222222222222222",
		FiredRuleID:        "allow-internal-summarize",
		DecisionReasonCode: "RULE_ALLOWED",
		EvaluatorVersion:   "pepg-0.1.0-test",
		AllowClock:         "2026-05-15T12:00:00Z",
	}
}

// ── Build/Verify happy paths ─────────────────────────────────────────────────

func TestBuildAllowTokenHash_PopulatesHash(t *testing.T) {
	token := sampleAllowToken()
	hash, err := BuildAllowTokenHash(token)
	if err != nil {
		t.Fatalf("BuildAllowTokenHash: %v", err)
	}
	if !hex64Token(hash) {
		t.Errorf("hash not §0-compliant: %q", hash)
	}
	if token.Hash != hash {
		t.Errorf("token.Hash = %q, want %q", token.Hash, hash)
	}
}

func TestBuildAllowTokenHash_Deterministic(t *testing.T) {
	a := sampleAllowToken()
	b := sampleAllowToken()
	hashA, _ := BuildAllowTokenHash(a)
	hashB, _ := BuildAllowTokenHash(b)
	if hashA != hashB {
		t.Errorf("non-deterministic: %s vs %s", hashA, hashB)
	}
}

func TestVerifyAllowTokenHash_Pristine(t *testing.T) {
	token := sampleAllowToken()
	if _, err := BuildAllowTokenHash(token); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := VerifyAllowTokenHash(token); err != nil {
		t.Errorf("pristine token failed verification: %v", err)
	}
}

// ── Tamper-evidence: every substantive field bound into the seal ─────────────

func TestVerifyAllowTokenHash_DetectsTampering(t *testing.T) {
	good := sampleAllowToken()
	if _, err := BuildAllowTokenHash(good); err != nil {
		t.Fatalf("Build: %v", err)
	}

	mutations := []struct {
		field  string
		mutate func(t *AllowToken)
	}{
		{"EnvelopeID", func(t *AllowToken) { t.EnvelopeID = "env-tampered" }},
		{"PolicyHash", func(t *AllowToken) {
			t.PolicyHash = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"EvaluationHash", func(t *AllowToken) {
			t.EvaluationHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}},
		{"FiredRuleID", func(t *AllowToken) { t.FiredRuleID = "rule-injected" }},
		{"DecisionReasonCode", func(t *AllowToken) { t.DecisionReasonCode = "RULE_DENIED" }},
		{"AllowClock", func(t *AllowToken) { t.AllowClock = "1999-01-01T00:00:00Z" }},
		{"EvaluatorVersion", func(t *AllowToken) { t.EvaluatorVersion = "pepg-0.0.0-malicious" }},
		{"Version", func(t *AllowToken) { t.Version = "vfa.allow_token.v999" }},
	}

	for _, m := range mutations {
		m := m
		t.Run("tampered_"+m.field, func(t *testing.T) {
			tampered := *good
			m.mutate(&tampered)
			err := VerifyAllowTokenHash(&tampered)
			if err == nil {
				t.Fatalf("tampering with %s went undetected", m.field)
			}
			if !errors.Is(err, ErrAllowTokenHashMismatch) {
				t.Errorf("expected ErrAllowTokenHashMismatch, got %v", err)
			}
		})
	}
}

// ── Hash uniqueness: different tokens produce different hashes ───────────────

func TestBuildAllowTokenHash_DifferentTokensDifferentHashes(t *testing.T) {
	a := sampleAllowToken()
	b := sampleAllowToken()
	b.EnvelopeID = "env-other"
	hashA, _ := BuildAllowTokenHash(a)
	hashB, _ := BuildAllowTokenHash(b)
	if hashA == hashB {
		t.Errorf("different tokens collided: %s", hashA)
	}
}
