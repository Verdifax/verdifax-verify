package main

import (
	"fmt"
	"strings"
	"testing"
)

// Round 43: a value the record stores more than once (the envelope id,
// each section's sealed hash, the AER and execution-record hashes, the
// six execution ids) must hold the same value in every copy, or the
// record fails. Before v0.17.9 a rewrite could change a copy the public
// log does not bind and keep the bound one.

var boundCopyRecords = []string{
	"testdata/round18/run-249-production.json",
	"testdata/round22/run-253-production.json",
	"testdata/round40/hardware-run-2026-10.json",
}

func TestPublishedRecordsHaveConsistentCopies(t *testing.T) {
	for _, path := range boundCopyRecords {
		if failures := verifyBoundCopies(mustDecode(t, path)); len(failures) > 0 {
			t.Errorf("%s: %v", path, failures)
		}
	}
}

func TestEveryCopyOfABoundValueMustAgree(t *testing.T) {
	for _, path := range boundCopyRecords {
		data := readTestRecord(t, path)
		root, readErr := tamperDecode(data)
		if readErr != nil {
			t.Fatal(readErr)
		}
		checked := 0
		b0 := mustDecode(t, path)
		for _, g := range boundCopyGroups {
			vals := g.value(b0)
			for i, p := range g.paths {
				steps := tamperKeySteps(p)
				old, carried := tamperValueAt(root, steps).(string)
				// A path the group reads no value from on this record is
				// behind a declared gate (TestEveryGateIsDeclared); a path
				// that is itself the gate switches the group off when it
				// changes, and the record fails elsewhere
				// (TestEveryGateIsBound).
				if !carried || vals[i] == nil || isGatePath(g, p) {
					continue
				}
				changed, set := tamperSetAt(data, steps, tamperAltered(old))
				if !set {
					t.Fatalf("%s: could not change %s", path, p)
				}
				b, decodeErr := decodeBundle(changed)
				if decodeErr != nil {
					t.Fatalf("%s: %s: %v", path, p, decodeErr)
				}
				failures := strings.Join(verifyBoundCopies(b), "\n")
				if !strings.Contains(failures, p) {
					t.Errorf("%s: changing only %s is not reported as a copy that disagrees: %q", path, p, failures)
				}
				if !exitShouldFail(verify(b), false, false) {
					t.Errorf("%s: changing only %s still verifies", path, p)
				}
				checked++
			}
		}
		if checked < 30 {
			t.Errorf("%s: only %d copies checked", path, checked)
		}
	}
}

func TestEveryCopyOfTheExecutionIdsMustAgree(t *testing.T) {
	data := readTestRecord(t, "testdata/round18/run-249-production.json")
	for _, path := range [][]tamperStep{
		{{key: "aer"}, {key: "execution_ids"}, {index: 2, list: true}},
		{{key: "efa"}, {key: "steps"}, {index: 2, list: true}, {key: "execution_id"}},
		{{key: "execution_record"}, {key: "kernel_output_ids"}, {index: 2, list: true}},
	} {
		root, _ := tamperDecode(data)
		changed, set := tamperSetAt(data, path, tamperAltered(tamperValueAt(root, path)))
		if !set {
			t.Fatalf("could not change %s", tamperPathString(path))
		}
		b, decodeErr := decodeBundle(changed)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if failures := verifyBoundCopies(b); len(failures) == 0 {
			t.Errorf("changing only %s is not reported as a list copy that disagrees", tamperPathString(path))
		}
	}
}

// The forger mode writes a change to one copy into every copy, so the
// copy check is never what stops it: on the hardware run, whose public-log
// entry binds the envelope id but not the envelope's own sealed hash, the
// envelope id copies are stopped by the log and the envelope hash copies
// stay rewritable.
func TestForgerRewritesEveryCopyTogether(t *testing.T) {
	data := readTestRecord(t, "testdata/round40/hardware-run-2026-10.json")
	root, _ := tamperDecode(data)
	c := tamperChange{"changed", tamperKeySteps("aer.envelope_id")}
	changed, built := tamperApply(data, c)
	if !built {
		t.Fatal("could not apply the change")
	}
	spread, _ := tamperDecode(tamperSpreadCopies(changed, root, c))
	want := tamperValueAt(spread, tamperKeySteps("aer.envelope_id"))
	for _, p := range []string{"envelope.envelope_id", "transport.envelope_id"} {
		if got := tamperValueAt(spread, tamperKeySteps(p)); got != want {
			t.Errorf("%s = %v after the forger's change, want %v", p, got, want)
		}
	}
	o, ok := tamperRun(data, memoJudge, true)
	if !ok {
		t.Fatal("the record did not decode")
	}
	tiers := map[string]string{}
	for _, r := range o.results {
		if r.Kind == "changed" {
			tiers[strings.TrimPrefix(r.Path, "$.")] = r.Tier
		}
	}
	for _, p := range []string{"aer.envelope_id", "transport.envelope_id", "final_vfa.zksp_binding_hash"} {
		if tiers[p] != tierLog {
			t.Errorf("%s: %q, want %q", p, tiers[p], tierLog)
		}
	}
	for _, p := range []string{"final_vfa.envelope_hash", "transport.envelope_hash", "envelope.seal.sealed_hash"} {
		if tiers[p] != tierNot {
			t.Errorf("%s: %q, want %q (the October 2026 entry does not bind the envelope's sealed hash)", p, tiers[p], tierNot)
		}
	}
}

// A change only internal hashes or consistency checks reject, whose
// rewrite the mode did not find, is neither shown stopped nor shown
// rewritable: it has its own tier, counts against the record, and is
// not listed among the rewritable paths.
func TestUnfoundRewritesHaveTheirOwnTier(t *testing.T) {
	o, ok := tamperRun(readTestRecord(t, "testdata/round40/hardware-run-2026-10.json"), memoJudge, true)
	if !ok {
		t.Fatal("the record did not decode")
	}
	rewritable := map[string]bool{}
	for _, p := range o.rewritable() {
		rewritable[p] = true
	}
	unfound := 0
	for _, r := range o.results {
		switch {
		case r.Tier == tierNot && !r.Accepted:
			t.Errorf("%s %s: rejected but placed in %q", r.Kind, r.Path, tierNot)
		case r.Tier == tierNoRewrite:
			unfound++
			if r.Accepted {
				t.Errorf("%s %s: accepted but placed in %q", r.Kind, r.Path, tierNoRewrite)
			}
		}
	}
	if unfound == 0 {
		t.Error("expected some changes on the hardware run without a verifying rewrite (deleted seals)")
	}
	counted := 0
	for _, r := range o.notStopped() {
		if r.Tier == tierNoRewrite {
			counted++
		}
	}
	if counted != unfound {
		t.Errorf("%d unfound rewrites, %d counted against the record", unfound, counted)
	}
}

// Round 44: the record's hardware_attestation.verification block and its
// measurement and report-data fields were read by nothing, so a rewrite
// could show any measurement while the raw AMD report said another. Each
// stated value must now equal the report's.
func TestHardwareVerificationBlockMustMatchTheReport(t *testing.T) {
	data := readTestRecord(t, "testdata/round40/hardware-run-2026-10.json")
	for _, p := range []string{
		"hardware_attestation.verification.measurement_hex",
		"hardware_attestation.enclave_measurement",
		"hardware_attestation.verification.report_id_hex",
		"hardware_attestation.verification.reported_tcb_hex",
		"hardware_attestation.verification.current_tcb_hex",
		"hardware_attestation.verification.report_data_hex",
		"hardware_attestation.report_data_hex",
		"hardware_attestation.verification.root_fingerprint_sha256",
		"hardware_attestation.verification.vlek_leaf_sha256",
	} {
		root, _ := tamperDecode(data)
		steps := tamperKeySteps(p)
		old, _ := tamperValueAt(root, steps).(string)
		changed, set := tamperSetAt(data, steps, tamperAltered(old))
		if !set {
			t.Fatalf("could not change %s", p)
		}
		b, decodeErr := decodeBundle(changed)
		if decodeErr != nil {
			t.Fatalf("%s: %v", p, decodeErr)
		}
		r := verify(b)
		if !exitShouldFail(r, false, false) {
			t.Errorf("changing %s still verifies", p)
		}
		found := false
		for _, c := range r.Categories {
			if c.Name == "hardware_attestation_sevsnp_quote" && !c.Match && strings.Contains(c.Computed, "do not match the AMD report") {
				found = true
			}
		}
		if !found {
			t.Errorf("changing %s is not reported as a mismatch with the AMD report", p)
		}
	}
	for _, p := range []string{"hardware_attestation.verification.report_version"} {
		root, _ := tamperDecode(data)
		steps := tamperKeySteps(p)
		old, _ := tamperValueAt(root, steps).(float64)
		changed, _ := tamperSetAt(data, steps, old+1)
		b, decodeErr := decodeBundle(changed)
		if decodeErr != nil {
			t.Fatalf("%s: %v", p, decodeErr)
		}
		if !exitShouldFail(verify(b), false, false) {
			t.Errorf("changing %s still verifies", p)
		}
	}
	if r := verify(mustDecode(t, "testdata/round40/hardware-run-2026-10.json")); r.VerdictTier != "ANCHORED_PARTIAL_COVERAGE" || !r.AllPassed {
		t.Fatalf("the genuine hardware run must still verify as anchored with partial coverage: tier=%s cross=%v", r.VerdictTier, r.CrossChecks)
	}
}

// The forger changes every copy of a value together, so a change to the
// PIA hash reaches the three execution-id lists, a change to the
// proof-of-execution entry number reaches the anchor, and a change to a
// list item at index 4 reaches the PIA hash.
func TestForgerSpreadsTheNewCopies(t *testing.T) {
	data := readTestRecord(t, "testdata/round40/hardware-run-2026-10.json")
	root, _ := tamperDecode(data)
	for _, tc := range []struct {
		from string
		to   []string
	}{
		{"aivp_t4.pia_hash", []string{"aer.execution_ids[4]", "efa.steps[4].execution_id", "execution_record.kernel_output_ids[4]"}},
		{"pote_proof.log_entry_id", []string{"rekor_anchor.log_entry_id"}},
		{"transcript.proof_hash_input", []string{"aer.seal.sealed_hash"}},
		{"aer.execution_ids[4]", []string{"aivp_t4.pia_hash", "efa.steps[4].execution_id"}},
	} {
		c := tamperChange{"changed", tamperKeySteps(tc.from)}
		changed, built := tamperApply(data, c)
		if !built {
			t.Fatalf("could not apply the change at %s", tc.from)
		}
		spread, _ := tamperDecode(tamperSpreadCopies(changed, root, c))
		want := tamperValueAt(spread, tamperKeySteps(tc.from))
		for _, p := range tc.to {
			if got := tamperValueAt(spread, tamperKeySteps(p)); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("%s = %v after the forger's change at %s, want %v", p, got, tc.from, want)
			}
		}
		if tc.from == "transcript.proof_hash_input" {
			if got := tamperValueAt(spread, tamperKeySteps("execution_record.proof_hash")); fmt.Sprint(got) == fmt.Sprint(want) {
				t.Errorf("the forger spread the transcript's input to execution_record.proof_hash, which was not its source on this record")
			}
		}
	}
}

// The README and the docs guide state how many copy groups the verifier
// checks; the number must be the list's length, not a remembered count.
func TestReadmeStatesTheCopyGroupCount(t *testing.T) {
	readme := strings.Join(strings.Fields(string(readTestRecord(t, "README.md"))), " ")
	if len(boundListGroups) != 1 {
		t.Fatalf("%d list groups; the README says one", len(boundListGroups))
	}
	want := fmt.Sprintf("the %d copy groups and one list group listed in `boundcopies.go`", len(boundCopyGroups))
	if !strings.Contains(readme, want) {
		t.Errorf("README does not state %q", want)
	}
}

func isGatePath(g boundCopyGroup, p string) bool {
	for _, gate := range g.gates {
		if gate.path == p {
			return true
		}
	}
	return false
}
