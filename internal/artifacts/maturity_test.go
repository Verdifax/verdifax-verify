package artifacts

import (
	"testing"
)

// 1. Live AIVP → REAL.
func TestMaturity_AIVPLive(t *testing.T) {
	r := BuildMaturityReport(MaturityInputs{
		AivpAdapterID:        "live-claude-api",
		LedgerBackend:        "rekor",
		FormalVerifierStatus: "VERIFIED_SOUND_COMPLETE_ZK",
		HardwareAttestationHash: "a",
	})
	row := findRow(r, "AIVP")
	if row == nil {
		t.Fatal("AIVP row missing")
	}
	if row.Flag != MaturityReal {
		t.Errorf("AIVP flag = %s, want REAL", row.Flag)
	}
}

// 2. mock-claude AIVP → MOCK.
func TestMaturity_AIVPMock(t *testing.T) {
	r := BuildMaturityReport(MaturityInputs{
		AivpAdapterID: "mock-claude",
	})
	row := findRow(r, "AIVP")
	if row.Flag != MaturityMock {
		t.Errorf("AIVP flag = %s, want MOCK", row.Flag)
	}
}

// 3. Empty AIVP adapter ID → UNKNOWN (run didn't carry AI output).
func TestMaturity_AIVPUnknown(t *testing.T) {
	r := BuildMaturityReport(MaturityInputs{})
	row := findRow(r, "AIVP")
	if row.Flag != MaturityUnknown {
		t.Errorf("AIVP flag = %s, want UNKNOWN", row.Flag)
	}
}

// 4. Rekor ledger → REAL; mock ledger → MOCK.
func TestMaturity_LedgerClassification(t *testing.T) {
	for _, c := range []struct {
		backend string
		want    MaturityFlag
	}{
		{"rekor", MaturityReal},
		{"mock", MaturityMock},
		{"", MaturityUnknown},
		{"REKOR", MaturityReal}, // case-insensitive
	} {
		r := BuildMaturityReport(MaturityInputs{LedgerBackend: c.backend})
		row := findRow(r, "Ledger")
		if row.Flag != c.want {
			t.Errorf("backend=%q: flag = %s, want %s", c.backend, row.Flag, c.want)
		}
	}
}

// 5. ZKSP defaults to PARTIAL when status is non-empty.
func TestMaturity_ZKSPPartial(t *testing.T) {
	r := BuildMaturityReport(MaturityInputs{
		FormalVerifierStatus: "VERIFIED_SOUND_COMPLETE_ZK",
	})
	row := findRow(r, "ZKSP")
	if row.Flag != MaturityPartial {
		t.Errorf("ZKSP flag = %s, want PARTIAL (real_zk not yet shipped)", row.Flag)
	}
}

// 6. Hardware shows PARTIAL when hash present, UNKNOWN otherwise.
func TestMaturity_Hardware(t *testing.T) {
	withHash := BuildMaturityReport(MaturityInputs{HardwareAttestationHash: "abc"})
	if findRow(withHash, "HRE").Flag != MaturityPartial {
		t.Error("HRE with hash should be PARTIAL")
	}
	withoutHash := BuildMaturityReport(MaturityInputs{})
	if findRow(withoutHash, "HRE").Flag != MaturityUnknown {
		t.Error("HRE without hash should be UNKNOWN")
	}
}

// 7. Phase-1-4 stages always REAL, these are pure orchestrator.
func TestMaturity_AlwaysRealStages(t *testing.T) {
	r := BuildMaturityReport(MaturityInputs{}) // empty, worst case
	for _, stage := range []string{"DOG", "DTL", "DKEC", "AER", "DLA"} {
		row := findRow(r, stage)
		if row == nil {
			t.Errorf("%s row missing", stage)
			continue
		}
		if row.Flag != MaturityReal {
			t.Errorf("%s flag = %s, want REAL (always)", stage, row.Flag)
		}
	}
}

// 8. Notes always carry a buyer-readable description that explains
// what drove the classification. The note must NOT expose internal
// adapter identifiers like "aivp-t4-subprocess-empty", those stay
// in backend logs and the sealed manifest. The user-facing note shows
// a friendly label; verifiers re-derive the raw value from the bundle.
func TestMaturity_NotesCarrySignal(t *testing.T) {
	r := BuildMaturityReport(MaturityInputs{
		AivpAdapterID: "live-claude-api",
		LedgerBackend: "rekor",
	})
	aivp := findRow(r, "AIVP")
	if !contains(aivp.Note, "Live Anthropic Claude API") {
		t.Errorf("AIVP note should mention the live model in friendly form; got %q", aivp.Note)
	}
	ledger := findRow(r, "Ledger")
	if !contains(ledger.Note, "LedgerBackend") {
		t.Errorf("Ledger note should mention LedgerBackend; got %q", ledger.Note)
	}
}

// helpers ──────────────────────────────────────────────────────

func findRow(r *MaturityReport, stagePrefix string) *MaturityRow {
	for i := range r.Rows {
		if startsWith(r.Rows[i].Stage, stagePrefix) {
			return &r.Rows[i]
		}
	}
	return nil
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
