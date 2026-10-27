package main

import (
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
		for _, g := range boundCopyGroups {
			for _, p := range g.paths {
				steps := tamperKeySteps(p)
				old, carried := tamperValueAt(root, steps).(string)
				if !carried {
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
