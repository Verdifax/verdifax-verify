package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
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

func TestTamperReportNamesWhichCheckCaughtEachChange(t *testing.T) {
	var out bytes.Buffer
	code := runTamperTestJudged(&out, readTestRecord(t, "testdata/round18/run-249-production.json"), judgeForTamper, false)
	if code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, out.String())
	}
	for _, want := range []string{"Caught by", catchCompleteEntry, catchFirstEntry, catchInternal} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report does not name %q:\n%s", want, out.String())
		}
	}
}

func TestRecomputeHashesStopsEveryChangeOnACompleteRecord(t *testing.T) {
	var out bytes.Buffer
	code := runTamperTestJudged(&out, readTestRecord(t, "testdata/round18/run-249-production.json"), judgeForTamper, true)
	if code != 0 || !strings.Contains(out.String(), " 0 not stopped.") {
		t.Fatalf("exit %d, want every change stopped by a check no rewrite can satisfy:\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "NOT STOPPED") {
		t.Fatalf("a change survived a full rewrite:\n%s", out.String())
	}
}

// TestRecomputeHashesReportsACoverageSlip plays the regression the mode
// exists to catch: if the complete-record entry stopped covering the
// record, rewriting the record's own hashes would carry most changes
// past every other check, and the mode must say so.
func TestRecomputeHashesReportsACoverageSlip(t *testing.T) {
	withoutSecondEntry := func(data []byte) tamperVerdict {
		v := judgeForTamper(data)
		var kept []string
		for _, g := range v.caughtBy {
			if g != catchCompleteEntry {
				kept = append(kept, g)
			}
		}
		if len(kept) == 0 && !v.accepted {
			return tamperVerdict{accepted: true}
		}
		v.caughtBy = kept
		return v
	}
	o, ok := tamperRun(readTestRecord(t, "testdata/round18/run-249-production.json"), withoutSecondEntry, true)
	if !ok {
		t.Fatal("the record did not decode")
	}
	if len(o.notStopped) < 100 {
		t.Fatalf("only %d changes reported not stopped without the complete-record entry; the mode would miss a coverage slip", len(o.notStopped))
	}
	// Some fields are covered by the complete-record entry alone: without
	// it, changing them is accepted even when no hash is recomputed.
	o, _ = tamperRun(readTestRecord(t, "testdata/round18/run-249-production.json"), withoutSecondEntry, false)
	if len(o.notStopped) == 0 {
		t.Fatal("expected fields only the complete-record entry covers")
	}
}

func TestRecomputeHashesOnTheHardwareRun(t *testing.T) {
	o, ok := tamperRun(readTestRecord(t, "testdata/round40/hardware-run-2026-10.json"), judgeForTamper, true)
	if !ok {
		t.Fatal("the record did not decode")
	}
	paths := map[string]bool{}
	for _, c := range o.notStopped {
		paths[tamperIndex.ReplaceAllString(tamperPathString(c.path), "[]")] = true
	}
	// No rewrite can change what AMD's report signs or what the
	// public-log entry binds.
	for _, p := range []string{"$.hardware_attestation.quote_b64", "$.envelope.envelope_id", "$.aer.seal.sealed_hash",
		"$.zksp_binding.seal.sealed_hash", "$.execution_record.input_hash", "$.execution_record.program_hash",
		"$.execution_record.transport_hash", "$.execution_record.execution_control_hash",
		"$.execution_record.kernel_output_ids[]", "$.rekor_anchor.leaf_hash"} {
		if paths[p] {
			t.Errorf("%s changed under a full rewrite", p)
		}
	}
	// The record predates the complete-record anchor, so a full rewrite
	// can change its decision; the evidence page says so.
	if !paths["$.aer.decision.result"] {
		t.Error("expected the decision to be rewritable on a record without a complete-record anchor")
	}
}

// The README states the tamper counts for run 249 and the hardware run;
// they must be the counts the tool produces (round 41: a stated count went
// stale when the method changed).
func TestReadmeStatesTheTamperCounts(t *testing.T) {
	readme := string(readTestRecord(t, "README.md"))
	plain, _ := tamperRun(readTestRecord(t, "testdata/round18/run-249-production.json"), judgeForTamper, false)
	forger, _ := tamperRun(readTestRecord(t, "testdata/round18/run-249-production.json"), judgeForTamper, true)
	hw := uncoveredFields(readTestRecord(t, "testdata/round40/hardware-run-2026-10.json"),
		verify(mustDecode(t, "testdata/round40/hardware-run-2026-10.json")))
	hwForger, _ := tamperRun(readTestRecord(t, "testdata/round40/hardware-run-2026-10.json"), judgeForTamper, true)
	rewritable := map[string]bool{}
	for _, c := range hwForger.notStopped {
		p := tamperIndex.ReplaceAllString(tamperPathString(c.path), "[]")
		switch c.kind {
		case "added":
			p += ".(added key)"
		case "appended":
			p += "[] (appended item)"
		}
		rewritable[p] = true
	}
	for _, want := range []string{
		fmt.Sprintf("takes\n%s changes and rejects all of them", commaInt(plain.tried)),
		fmt.Sprintf("%s changes and stops all of them", commaInt(forger.tried)),
		fmt.Sprintf("%d of its paths are uncovered", len(hw)),
		fmt.Sprintf("%d of its paths, among them the decision", len(rewritable)),
	} {
		if !strings.Contains(strings.Join(strings.Fields(readme), " "), strings.Join(strings.Fields(want), " ")) {
			t.Errorf("README does not state %q", want)
		}
	}
}

func mustDecode(t *testing.T, path string) *artifacts.AuditBundle {
	t.Helper()
	b, err := decodeBundle(readTestRecord(t, path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func commaInt(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	return s[:len(s)-3] + "," + s[len(s)-3:]
}
