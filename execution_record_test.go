package main

import (
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

func recordBundle(t *testing.T) *artifacts.AuditBundle {
	t.Helper()
	ids := []string{
		strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64),
		strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64),
	}
	rec := artifacts.ExecutionRecord{
		Kind:                    artifacts.ExecutionRecordKind,
		Formula:                 artifacts.AerFormulaV1,
		InputHash:               strings.Repeat("a", 64),
		TransportHash:           strings.Repeat("b", 64),
		ExecutionControlHash:    strings.Repeat("c", 64),
		ProgramHash:             strings.Repeat("d", 64),
		KernelOutputIDs:         ids,
		HardwareAttestationHash: artifacts.NoHardwareAttestationHash,
	}
	var err error
	rec.AerHash, rec.ProofHash, err = artifacts.RecomputeExecutionRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	b := &artifacts.AuditBundle{ExecutionRecord: &rec}
	b.AER.ExecutionIDs = append([]string(nil), ids...)
	b.FinalVFA.AerHash = rec.AerHash
	return b
}

func TestExecutionRecordRowsMatchForAnIntactRecord(t *testing.T) {
	rows := verifyExecutionRecord(recordBundle(t))
	if len(rows) != 5 {
		t.Fatalf("got %d rows, want 5", len(rows))
	}
	for _, c := range rows {
		if !c.Match {
			t.Errorf("%s: recorded %s, computed %s", c.Name, c.Recorded, c.Computed)
		}
	}
}

func TestExecutionRecordEditsAreCaught(t *testing.T) {
	edits := map[string]func(*artifacts.AuditBundle){
		"input":   func(b *artifacts.AuditBundle) { b.ExecutionRecord.InputHash = strings.Repeat("0", 64) },
		"kernel":  func(b *artifacts.AuditBundle) { b.ExecutionRecord.KernelOutputIDs[3] = strings.Repeat("0", 64) },
		"claim":   func(b *artifacts.AuditBundle) { b.ExecutionRecord.HardwareAttested = true },
		"binding": func(b *artifacts.AuditBundle) { b.FinalVFA.AerHash = strings.Repeat("0", 64) },
		"formula": func(b *artifacts.AuditBundle) { b.ExecutionRecord.Formula = "aer.v2" },
	}
	for name, edit := range edits {
		b := recordBundle(t)
		edit(b)
		failed := false
		for _, c := range verifyExecutionRecord(b) {
			if !c.Match {
				failed = true
			}
		}
		if !failed {
			t.Errorf("%s: edit was not caught", name)
		}
	}
}
