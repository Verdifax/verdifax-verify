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

// Round 40: the harness must also change empty, false, zero and null
// values, delete whole sections, and add keys and list items. On a
// complete record each of those fails; deleting a key that holds an
// empty value is not tried, since the record reads the same without it.
func TestTamperTestCoversEmptyValuesSectionsAndAdditions(t *testing.T) {
	data := readTestRecord(t, "testdata/round18/run-249-production.json")
	root, readErr := tamperDecode(data)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var changes []tamperChange
	tamperChanges(root, nil, &changes)
	seen := map[string]bool{}
	for _, c := range changes {
		seen[c.kind+" "+tamperPathString(c.path)] = true
	}
	for _, want := range []string{
		"changed $.authorization_chain.human_in_loop.performed", // false
		"changed $.aivp_t4.ai_output_hash",                      // ""
		"deleted $.aivp_t4",                                     // a whole section
		"added $.request_substance",                             // an unknown key
		"removed $.rekor_anchor.inclusion_path[0]",              // a list item
		"appended $.rekor_anchor.inclusion_path",                // an added list item
	} {
		if !seen[want] {
			t.Errorf("the harness must try %q", want)
		}
	}
	if seen["deleted $.authorization_chain.human_in_loop.performed"] {
		t.Error("deleting a key holding false leaves the record's meaning unchanged and must not be tried")
	}
	accepted, tried, ok := tamperAccepted(data, verifyForTamper)
	if !ok || tried < 1200 || len(accepted) != 0 {
		t.Fatalf("complete record: tried %d, accepted %d (ok=%v)", tried, len(accepted), ok)
	}
}

func TestHardwareRunUncoveredIncludesSectionsAndScaffoldFlags(t *testing.T) {
	data := readTestRecord(t, "testdata/round40/hardware-run-2026-10.json")
	b, decodeErr := decodeBundle(data)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	got := map[string]bool{}
	for _, f := range uncoveredFields(data, verify(b)) {
		got[f] = true
	}
	for _, want := range []string{"aivp_t4", "nrep", "hardware_attestation.scaffold.is_scaffold", "aivp_t4.halt_receipt_hash"} {
		if !got[want] {
			t.Errorf("uncovered fields must include %s", want)
		}
	}
	if len(got) != 82 {
		t.Errorf("the hardware run has %d uncovered fields; the disclosure states 82", len(got))
	}
}
