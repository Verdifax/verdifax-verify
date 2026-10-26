package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func readTestRecord(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// On a complete-record anchored production record every single change
// and deletion fails verification.
func TestTamperTestRejectsEveryChangeToACompleteRecord(t *testing.T) {
	var out bytes.Buffer
	code := runTamperTest(&out, readTestRecord(t, "testdata/round18/run-249-production.json"), verifyForTamper)
	if code != 0 || !strings.Contains(out.String(), " 0 accepted") {
		t.Fatalf("exit %d, output:\n%s", code, out.String())
	}
}

// A verifier that accepted everything must be reported, with exit 1.
func TestTamperTestReportsAcceptedChanges(t *testing.T) {
	var out bytes.Buffer
	code := runTamperTest(&out, readTestRecord(t, "testdata/round18/run-249-production.json"), func([]byte) bool { return true })
	if code != 1 || !strings.Contains(out.String(), "ACCEPTED:") {
		t.Fatalf("exit %d, output:\n%s", code, out.String())
	}
}

func TestTamperTestRefusesARecordThatDoesNotVerify(t *testing.T) {
	var out bytes.Buffer
	if code := runTamperTest(&out, []byte(`{"kind":"x"}`), verifyForTamper); code != 1 {
		t.Fatalf("exit %d, output:\n%s", code, out.String())
	}
}

// The October 2026 hardware run predates the complete-record anchor.
// Its report must name the fields no hash covers, including the AI review
// summary and the attestation summary, and must not name fields that are
// covered (the execution record's decision, the raw SEV-SNP report).
func TestUncoveredFieldsOfThePreV5HardwareRun(t *testing.T) {
	data := readTestRecord(t, "testdata/round40/hardware-run-2026-10.json")
	b, err := decodeBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	r := verify(b)
	got := map[string]bool{}
	for _, f := range uncoveredFields(data, r) {
		got[f] = true
	}
	for _, want := range []string{"aivp_t4.decision", "aivp_t4.adapter_id", "hardware_attestation.verification.chain_verified", "status", "run_id", "generated_at"} {
		if !got[want] {
			t.Errorf("uncovered fields must include %s", want)
		}
	}
	for f := range got {
		if strings.HasPrefix(f, "aer.decision") || f == "hardware_attestation.quote_b64" || f == "hardware_attestation.enclave_measurement" || strings.HasPrefix(f, "execution_record") {
			t.Errorf("%s is covered and must not be listed", f)
		}
	}
}

func TestNoUncoveredFieldsOnACompleteRecord(t *testing.T) {
	data := readTestRecord(t, "testdata/round18/run-249-production.json")
	b, err := decodeBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	if f := uncoveredFields(data, verify(b)); len(f) != 0 {
		t.Fatalf("a complete-record anchored record has no uncovered fields, got %v", f)
	}
}
