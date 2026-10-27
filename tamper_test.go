package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// memoJudge verifies each distinct candidate record once across the
// whole test binary: several tests walk the same changes, and CI runs the
// suite under the race detector.
var (
	memoMu    sync.Mutex
	memoCache = map[[32]byte]tamperVerdict{}
)

func memoJudge(data []byte) tamperVerdict {
	key := sha256.Sum256(data)
	memoMu.Lock()
	v, found := memoCache[key]
	memoMu.Unlock()
	if found {
		return v
	}
	v = judgeForTamper(data)
	memoMu.Lock()
	memoCache[key] = v
	memoMu.Unlock()
	return v
}

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
	for _, want := range []string{"aivp_t4.decision", "aivp_t4.adapter_id", "status", "run_id"} {
		if !got[want] {
			t.Errorf("uncovered fields must include %s", want)
		}
	}
	// Since v0.17.10 the verification block is compared with the AMD
	// report and the record clock is a copy of the envelope's timestamp.
	for f := range got {
		if strings.HasPrefix(f, "aer.decision") || f == "hardware_attestation.quote_b64" || f == "hardware_attestation.enclave_measurement" ||
			strings.HasPrefix(f, "execution_record") || strings.HasPrefix(f, "hardware_attestation.verification.") || f == "generated_at" {
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
	if len(got) != 55 {
		t.Errorf("the hardware run has %d uncovered fields; the disclosure states 55", len(got))
	}
}

func TestTamperReportNamesWhichCheckCaughtEachChange(t *testing.T) {
	var out bytes.Buffer
	code := runTamperTestJudged(&out, readTestRecord(t, "testdata/round18/run-249-production.json"), memoJudge, false)
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
	code := runTamperTestJudged(&out, readTestRecord(t, "testdata/round18/run-249-production.json"), memoJudge, true)
	if code != 0 || !strings.Contains(out.String(), "not stopped 0") {
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
		v := memoJudge(data)
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
	if len(o.notStopped()) < 100 {
		t.Fatalf("only %d changes reported not stopped without the complete-record entry; the mode would miss a coverage slip", len(o.notStopped()))
	}
	// Some fields are covered by the complete-record entry alone: without
	// it, changing them is accepted even when no hash is recomputed.
	o, _ = tamperRun(readTestRecord(t, "testdata/round18/run-249-production.json"), withoutSecondEntry, false)
	if len(o.notStopped()) == 0 {
		t.Fatal("expected fields only the complete-record entry covers")
	}
}

func TestRecomputeHashesOnTheHardwareRun(t *testing.T) {
	o, ok := tamperRun(readTestRecord(t, "testdata/round40/hardware-run-2026-10.json"), memoJudge, true)
	if !ok {
		t.Fatal("the record did not decode")
	}
	paths := map[string]bool{}
	for _, p := range o.rewritable() {
		paths[p] = true
	}
	// No rewrite can change what AMD's report signs or what the
	// public-log entry binds, nor, since v0.17.9, any copy of those
	// values elsewhere in the record (round 43).
	for _, p := range []string{"hardware_attestation.quote_b64", "envelope.envelope_id", "aer.seal.sealed_hash",
		"zksp_binding.seal.sealed_hash", "execution_record.input_hash", "execution_record.program_hash",
		"execution_record.transport_hash", "execution_record.execution_control_hash",
		"execution_record.kernel_output_ids[]", "rekor_anchor.leaf_hash",
		"aer.envelope_id", "transport.envelope_id", "final_vfa.zksp_binding_hash", "final_vfa.aer_hash",
		"pote_proof.execution_trace_hash", "execution_record.aer_hash", "transport.seal.sealed_hash",
		"final_vfa.transport_hash", "envelope.registry_record_hash", "payload.content_hash", "envelope.payload_hash",
		"aer.execution_ids[]", "efa.steps[].execution_id"} {
		if paths[p] {
			t.Errorf("%s changed under a full rewrite", p)
		}
	}
	// The record predates the complete-record anchor, so a full rewrite
	// can change its decision; the evidence page says so.
	if !paths["aer.decision.result"] {
		t.Error("expected the decision to be rewritable on a record without a complete-record anchor")
	}
	// Every path the mode calls rewritable was shown: a change there
	// verified after the rewrite.
	for _, r := range o.results {
		if paths[tamperPathKey(r.change)] && r.Tier == tierNot && !r.Accepted {
			t.Errorf("%s %s is listed as rewritable but its rewrite was rejected", r.Kind, r.Path)
		}
	}
}

// The README states the tamper counts for run 249 and the hardware run;
// they must be the counts the tool produces (round 41: a stated count went
// stale when the method changed).
func TestReadmeStatesTheTamperCounts(t *testing.T) {
	readme := string(readTestRecord(t, "README.md"))
	plain, _ := tamperRun(readTestRecord(t, "testdata/round18/run-249-production.json"), memoJudge, false)
	forger, _ := tamperRun(readTestRecord(t, "testdata/round18/run-249-production.json"), memoJudge, true)
	hw := uncoveredFields(readTestRecord(t, "testdata/round40/hardware-run-2026-10.json"),
		verify(mustDecode(t, "testdata/round40/hardware-run-2026-10.json")))
	hwForger, _ := tamperRun(readTestRecord(t, "testdata/round40/hardware-run-2026-10.json"), memoJudge, true)
	rewritable := hwForger.rewritable()
	for _, want := range []string{
		fmt.Sprintf("takes\n%s changes and rejects all of them", commaInt(plain.tried)),
		fmt.Sprintf("takes %s changes; the public log stops %s of them, and strict reading refuses the other %d",
			commaInt(forger.tried), commaInt(forger.tierCount[tierLog]), forger.tierCount[tierStrict]),
		fmt.Sprintf("%d of its paths are uncovered", len(hw)),
		fmt.Sprintf("%d of its paths, among them the decision", len(rewritable)),
		fmt.Sprintf("Of its other changes, %d (mostly a whole section or seal deleted) are rejected only by checks a rewrite might satisfy, with no verifying rewrite found, and %d are stopped only by the actor signature",
			hwForger.tierCount[tierNoRewrite], hwForger.tierCount[tierActorOnly]),
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

// Round 42: a change counts as stopped by the public log only when a
// public-log entry or its timestamps catch it, never because the tool's
// own edit did not decode or because only the actor signature, whose keys
// Verdifax holds, caught it.
func TestRecomputeHashesTiersOnACompleteRecord(t *testing.T) {
	o, ok := tamperRun(readTestRecord(t, "testdata/round18/run-249-production.json"), memoJudge, true)
	if !ok {
		t.Fatal("the record did not decode")
	}
	if o.tierCount[tierActorOnly] != 0 || o.tierCount[tierNot] != 0 {
		t.Fatalf("tiers %v: a change relied on the actor signature alone or was not stopped", o.tierCount)
	}
	for _, r := range o.results {
		if r.Tier == tierStrict && r.Kind != "added" && r.Path != "$.kind" {
			t.Errorf("%s %s is refused only by strict reading; a well-formed retry should reach the public log", r.Kind, r.Path)
		}
	}
	if o.tierCount[tierLog] < 1000 {
		t.Fatalf("only %d changes stopped by the public log: %v", o.tierCount[tierLog], o.tierCount)
	}
}

func TestMalformedEditsAreRetriedWellFormed(t *testing.T) {
	o, _ := tamperRun(readTestRecord(t, "testdata/round18/run-249-production.json"), memoJudge, true)
	for _, r := range o.results {
		if r.Path == "$.rekor_anchor.input_nonce" && r.Kind == "changed" {
			if !r.Retried || r.Tier != tierLog {
				t.Fatalf("the nonce change was not retried as a well-formed number reaching the public log: %+v", r)
			}
			return
		}
	}
	t.Fatal("no nonce change found")
}

func TestActorOnlyCountsAgainstTheRecord(t *testing.T) {
	original := []byte(`{"kind":"verdifax.audit_bundle.v1","nrep":{"signature":"abc"}}`)
	root, _ := tamperDecode(original)
	same, _ := json.Marshal(root)
	actorOnly := func(data []byte) tamperVerdict {
		if bytes.Equal(data, same) || bytes.Equal(data, original) {
			return tamperVerdict{accepted: true}
		}
		return tamperVerdict{caughtBy: []string{catchActor}}
	}
	var out bytes.Buffer
	if code := runTamperTestJudged(&out, original, actorOnly, true); code != 1 {
		t.Fatalf("exit %d: changes stopped only by the actor signature must fail the test:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "stopped only by the actor signature") {
		t.Fatalf("the actor-only tier is not reported:\n%s", out.String())
	}
}

func TestWellFormedValues(t *testing.T) {
	for in, want := range map[string]string{
		"1792344015032211032":  "1792344015032211033",
		"2026-10-24T15:59:19Z": "2026-10-24T15:59:20Z",
		"ab12":                 "bb12",
		"QUJD":                 "RUJD",
		"run-x":                "run-y",
	} {
		if got, ok := tamperWellFormed(in); !ok || got != want {
			t.Errorf("tamperWellFormed(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestTamperJSONListsEveryChange(t *testing.T) {
	var out bytes.Buffer
	runTamperTestOutput(&out, readTestRecord(t, "testdata/round18/run-249-production.json"), memoJudge, true, true)
	var rep tamperReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Tried == 0 || len(rep.Changes) != rep.Tried || !rep.Passed {
		t.Fatalf("tried %d, %d changes listed, passed %v", rep.Tried, len(rep.Changes), rep.Passed)
	}
	for _, c := range rep.Changes {
		if c.Tier == "" || (!c.Accepted && len(c.CaughtBy) == 0) {
			t.Fatalf("change without its checks: %+v", c)
		}
	}
}
