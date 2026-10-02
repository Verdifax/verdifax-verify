package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
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

// attestedRecordBundle is recordBundle with a hardware-attested record
// whose hardware slot holds the hash of the real AMD quote in testdata.
func attestedRecordBundle(t *testing.T) *artifacts.AuditBundle {
	t.Helper()
	raw, err := os.ReadFile("internal/sevsnp/testdata/report.bin")
	if err != nil {
		t.Fatal(err)
	}
	b := recordBundle(t)
	sum := sha256.Sum256(raw)
	rec := b.ExecutionRecord
	rec.HardwareAttestationHash = hex.EncodeToString(sum[:])
	rec.HardwareAttested = true
	rec.AerHash, rec.ProofHash, err = artifacts.RecomputeExecutionRecord(*rec)
	if err != nil {
		t.Fatal(err)
	}
	b.FinalVFA.AerHash = rec.AerHash
	b.HardwareAttestation.AttestationMode = "sev_snp"
	b.HardwareAttestation.QuoteB64 = base64.StdEncoding.EncodeToString(raw)
	return b
}

func hardwareRow(t *testing.T, b *artifacts.AuditBundle) HashCheck {
	t.Helper()
	for _, c := range verifyExecutionRecord(b) {
		if c.Name == "execution_record_hardware" {
			return c
		}
	}
	t.Fatal("no execution_record_hardware row")
	return HashCheck{}
}

func TestAttestedRecordHoldsTheQuoteHash(t *testing.T) {
	row := hardwareRow(t, attestedRecordBundle(t))
	if !row.Match || row.Scaffold {
		t.Errorf("recorded %s, computed %s, scaffold %t", row.Recorded, row.Computed, row.Scaffold)
	}
}

func TestAttestedRecordWithAnotherQuoteFails(t *testing.T) {
	b := attestedRecordBundle(t)
	b.HardwareAttestation.QuoteB64 = base64.StdEncoding.EncodeToString([]byte("some other report"))
	if hardwareRow(t, b).Match {
		t.Error("a record verified against a quote other than the one it hashed")
	}
	b = attestedRecordBundle(t)
	b.HardwareAttestation.QuoteB64 = ""
	if hardwareRow(t, b).Match {
		t.Error("a record claiming hardware verified with no quote in the bundle")
	}
}

// The real quote was bound to a different value, so checking it against
// this record's pre-record binding must fail: the verifier uses the
// pre-record recipe for attested records, never the post-run one.
func TestAttestedRecordQuoteIsCheckedAgainstThePreRecordBinding(t *testing.T) {
	b := attestedRecordBundle(t)
	vlek, _ := os.ReadFile("internal/sevsnp/testdata/vlek.pem")
	chain, _ := os.ReadFile("internal/sevsnp/testdata/cert_chain.pem")
	b.HardwareAttestation.VLEKCertPEM = string(vlek)
	b.HardwareAttestation.CertChainPEM = string(chain)
	if c := verifySevSnpQuote(b); c.Match || !strings.Contains(c.Computed, "report_data") {
		t.Errorf("got %q, want a report_data binding failure", c.Computed)
	}
}
