package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Round 45 of the external review: two copy groups a declared field
// could switch off, a skipped deleted copy, receipt flags ignored, a
// seal-pair excuse with a false reason, and six table rows nothing
// compared. Each finding is a test here; the structural rule (R82) is
// TestEveryGateIsDeclared and TestEveryGateIsBound.

// F1: the proof-of-execution section's ledger name must equal the
// anchor's, and renaming it no longer switches the entry comparisons off.
func TestLedgerNameMustMatchTheAnchor(t *testing.T) {
	data := readTestRecord(t, "testdata/round18/run-249-production.json")
	for _, c := range []tamperChange{
		{"changed", tamperKeySteps("pote_proof.ledger_backend")},
		{"deleted", tamperKeySteps("pote_proof.ledger_backend")},
	} {
		changed, built := tamperApply(data, c)
		if !built {
			t.Fatal("could not apply the change")
		}
		b, decodeErr := decodeBundle(changed)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		failures := strings.Join(verifyBoundCopies(b), "\n")
		if !strings.Contains(failures, "pote_proof.ledger_backend") {
			t.Errorf("%s pote_proof.ledger_backend: not reported as a copy that disagrees: %q", c.kind, failures)
		}
		// The entry comparisons still run with the section renamed.
		renamed, set := tamperSetAt(changed, tamperKeySteps("pote_proof.log_entry_id"), "1")
		if !set {
			t.Fatal("could not change the entry number")
		}
		b2, decodeErr2 := decodeBundle(renamed)
		if decodeErr2 != nil {
			t.Fatal(decodeErr2)
		}
		if f := strings.Join(verifyBoundCopies(b2), "\n"); !strings.Contains(f, "pote_proof.log_entry_id") {
			t.Errorf("%s pote_proof.ledger_backend then entry number changed: the entry comparison was switched off: %q", c.kind, f)
		}
	}
}

// F2: a deleted or emptied PIA hash fails while the AI review ran, in
// plain verification, on every record generation that carries one.
func TestDeletedPiaHashFails(t *testing.T) {
	for _, path := range []string{"testdata/round40/hardware-run-2026-10.json", "testdata/round18/run-249-production.json", "testdata/round7/run-238-intact.json"} {
		data := readTestRecord(t, path)
		for _, c := range []tamperChange{
			{"deleted", tamperKeySteps("aivp_t4.pia_hash")},
			{"changed", tamperKeySteps("aivp_t4.pia_hash")},
		} {
			changed, built := tamperApply(data, c)
			if !built {
				t.Fatal("could not apply the change")
			}
			b, decodeErr := decodeBundle(changed)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if !exitShouldFail(verify(b), false, false) {
				t.Errorf("%s: %s aivp_t4.pia_hash still verifies", path, c.kind)
			}
			if f := strings.Join(verifyBoundCopies(b), "\n"); !strings.Contains(f, "aivp_t4.pia_hash") {
				t.Errorf("%s: %s aivp_t4.pia_hash is not reported as a copy that disagrees: %q", path, c.kind, f)
			}
		}
	}
}

// F2, the forger's tiers: a change is placed by the variant most
// favourable to the forger. A change in one copy that verifies alone is
// not stopped, even when the same change in every copy is caught.
func TestForgerReportsTheWeakestVariant(t *testing.T) {
	record := []byte(`{"transport":{"sequence_id":"seq-1"},"aer":{"sequence_id":"seq-1"}}`)
	// A judge that binds the transport copy only, so the change spread to
	// both copies is caught and the change to the AER copy alone is not.
	judge := func(data []byte) tamperVerdict {
		var doc struct {
			Transport struct {
				SequenceID string `json:"sequence_id"`
			} `json:"transport"`
		}
		if json.Unmarshal(data, &doc) != nil {
			return tamperVerdict{caughtBy: []string{catchDecode}}
		}
		if doc.Transport.SequenceID == "seq-1" {
			return tamperVerdict{accepted: true}
		}
		return tamperVerdict{caughtBy: []string{catchFirstEntry}}
	}
	o, ok := tamperRun(record, judge, true)
	if !ok {
		t.Fatal("the record did not run")
	}
	tiers := map[string]string{}
	for _, r := range o.results {
		if r.Kind == "changed" {
			tiers[strings.TrimPrefix(r.Path, "$.")] = r.Tier
		}
	}
	if tiers["aer.sequence_id"] != tierNot {
		t.Errorf("aer.sequence_id: %q, want %q (the change in that copy alone verifies)", tiers["aer.sequence_id"], tierNot)
	}
	if tiers["transport.sequence_id"] != tierLog {
		t.Errorf("transport.sequence_id: %q, want %q", tiers["transport.sequence_id"], tierLog)
	}
}

// F3: --tamper-test runs on a receipt document, plain and as a forger,
// and every change to an anchored receipt is stopped.
func TestReceiptTamperTest(t *testing.T) {
	data := readTestRecord(t, "testdata/round10/deny-receipt-run242-production-v2.json")
	for _, recompute := range []bool{false, true} {
		var out bytes.Buffer
		code := runTamperTestOutput(&out, data, judgeReceiptForTamper, recompute, true)
		var rep tamperReport
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatalf("recompute=%v: %v\n%s", recompute, err, out.String())
		}
		if code != 0 || !rep.Passed {
			var open []string
			for _, r := range rep.Changes {
				if r.Tier == tierNot || r.Tier == tierNoRewrite || r.Tier == tierActorOnly {
					open = append(open, r.Kind+" "+r.Path+": "+r.Tier)
				}
			}
			t.Errorf("recompute=%v: exit %d, passed=%v; not stopped: %v", recompute, code, rep.Passed, open)
		}
		if rep.Tried < 20 {
			t.Errorf("recompute=%v: only %d changes tried", recompute, rep.Tried)
		}
		if recompute {
			if rep.Tiers[tierLog] == 0 {
				t.Errorf("no change stopped by the receipt's public-log entry: %v", rep.Tiers)
			}
			for _, r := range rep.Changes {
				if r.Path == "$.deny_receipt.fired_rule_id" && r.Kind == "changed" && r.Tier != tierLog {
					t.Errorf("a rewritten rule id with the receipt hash recomputed: %q, want %q (%v)", r.Tier, tierLog, r.CaughtBy)
				}
			}
		}
	}
}

// Every flag the binary defines names the inputs it applies to, and the
// table names only flags that exist.
func TestEveryFlagNamesItsInputKinds(t *testing.T) {
	fs := flag.NewFlagSet("verdifax-verify", flag.ContinueOnError)
	defineFlags(fs)
	defined := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		defined[f.Name] = true
		if _, known := flagInputKinds[f.Name]; !known {
			t.Errorf("--%s is defined but flagInputKinds does not say which input it applies to", f.Name)
		}
	})
	for name := range flagInputKinds {
		if !defined[name] {
			t.Errorf("flagInputKinds names --%s, which the binary does not define", name)
		}
	}
}

// F3: a flag that does not apply to the input is refused with exit 2,
// and the flags that apply to both work on a receipt.
func TestFlagsAreRefusedOnTheWrongInput(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "verdifax-verify")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build: %v\n%s", buildErr, out)
	}
	receipt := filepath.Join("testdata", "round10", "deny-receipt-run242-production-v2.json")
	bundle := filepath.Join("testdata", "round18", "run-249-production.json")
	policy := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policy, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args   []string
		want   int
		stderr string
		stdout string
	}{
		{[]string{"--policy", policy, receipt}, 2, "--policy applies only to an audit bundle; this input is a receipt document", ""},
		{[]string{"--strict", receipt}, 2, "--strict applies only to an audit bundle", ""},
		{[]string{"--allow-partial", receipt}, 2, "--allow-partial applies only to an audit bundle", ""},
		{[]string{"--show-evidence-summary", receipt}, 2, "--show-evidence-summary applies only to an audit bundle", ""},
		{[]string{"--strict", "--show-evidence-summary", receipt}, 2, "--show-evidence-summary and --strict apply only to an audit bundle", ""},
		{[]string{"--self-hosted-receipt", bundle}, 2, "--self-hosted-receipt applies only to a receipt document; this input is an audit bundle", ""},
		{[]string{"--recompute-hashes", receipt}, 2, "--recompute-hashes only applies with --tamper-test", ""},
		{[]string{"--tamper-test", receipt}, 0, "", "TAMPER TEST"},
		{[]string{"--tamper-test", "--recompute-hashes", receipt}, 0, "", "TAMPER TEST WITH HASHES RECOMPUTED"},
		{[]string{"--json", receipt}, 0, "", "\"verdict_tier\": \"VERIFIED_ANCHORED\""},
		{[]string{receipt}, 0, "", "RECEIPT VERIFIED AND ANCHORED"},
	}
	for _, c := range cases {
		cmd := exec.Command(bin, c.args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		runErr := cmd.Run()
		got := 0
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			got = exitErr.ExitCode()
		} else if runErr != nil {
			t.Fatalf("%v: %v", c.args, runErr)
		}
		if got != c.want {
			t.Errorf("%v: exit %d, want %d\n%s%s", c.args, got, c.want, stdout.String(), stderr.String())
		}
		if c.stderr != "" && !strings.Contains(stderr.String(), c.stderr) {
			t.Errorf("%v: stderr %q does not say %q", c.args, stderr.String(), c.stderr)
		}
		if c.stdout != "" && !strings.Contains(stdout.String(), c.stdout) {
			t.Errorf("%v: stdout does not contain %q:\n%s", c.args, c.stdout, stdout.String())
		}
	}
}

var gateRecords = []string{
	"testdata/round18/run-249-production.json",
	"testdata/round45/run-248-production.json",
	"testdata/round22/run-253-production.json",
	"testdata/round8/run-239-intact.json",
	"testdata/round40/hardware-run-2026-10.json",
}

// The mock record is unanchored, so the forger's judge rejects it as
// it stands; it takes part only in the declaration test.
var gateDeclarationRecords = append(append([]string{}, gateRecords...), "testdata/policy-gate/orchestrator-mock-allowed-run.json")

// R82: a group returns no value for a path the record carries only
// through a declared gate.
func TestEveryGateIsDeclared(t *testing.T) {
	for _, path := range withGenuineFixtures(gateDeclarationRecords) {
		b := mustDecode(t, path)
		root, _ := tamperDecode(readTestRecord(t, path))
		for _, g := range boundCopyGroups {
			for i, v := range g.value(b) {
				carried := tamperValueAt(root, tamperKeySteps(g.paths[i])) != nil
				if v == nil && carried && len(g.gates) == 0 {
					t.Errorf("%s: the group %v returns no value for %s, which the record carries, and declares no gate", path, g.paths, g.paths[i])
				}
			}
		}
	}
}

// R82: switching any gate off (the forger's rewrite included) is caught
// by the public log, AMD's report or strict reading on every record
// generation, unless that record already discloses every path of the
// group as uncovered.
func TestEveryGateIsBound(t *testing.T) {
	for _, path := range withGenuineFixtures(gateRecords) {
		data := readTestRecord(t, path)
		b := mustDecode(t, path)
		root, _ := tamperDecode(data)
		uncovered := map[string]bool{}
		for _, f := range uncoveredFields(data, verify(b)) {
			uncovered[f] = true
		}
		// The record's rewritable list is needed only when a gate lands
		// outside the stopping tiers, so it is computed on first use.
		var rewritable map[string]bool
		isRewritable := func(p string) bool {
			if rewritable == nil {
				rewritable = map[string]bool{}
				forger, ran := tamperRun(data, memoJudge, true)
				if !ran {
					t.Fatalf("%s: the forger run did not run", path)
				}
				for _, r := range forger.rewritable() {
					rewritable[r] = true
				}
			}
			return rewritable[p]
		}
		for _, g := range boundCopyGroups {
			for _, gate := range g.gates {
				if !gate.active(b) {
					continue
				}
				steps := tamperKeySteps(gate.path)
				var c tamperChange
				var changed []byte
				var built bool
				if gate.deleted {
					c = tamperChange{"deleted", steps}
					changed, built = tamperApply(data, c)
				} else {
					c = tamperChange{"changed", steps}
					changed, built = tamperSetAt(data, steps, gateOffValue(root, steps, gate.off))
				}
				if !built {
					t.Fatalf("%s: could not switch %s off", path, gate.path)
				}
				variants := [][]byte{tamperRecompute(tamperSpreadCopies(changed, root, c)), tamperRecompute(changed)}
				weakest := ""
				rank := -1
				for _, variant := range variants {
					tier := tamperTier(memoJudge(variant), true)
					if r := tamperForgerRank(tier); r > rank {
						weakest, rank = tier, r
					}
				}
				// A gate switched off must never leave the record verifying
				// or stopped only by the actor signature. A verdict of "no
				// verifying rewrite found" is a gate bound through a value
				// the entry binds (the attestation mode contradicts the
				// execution record's hardware row, whose preimage the AER
				// hash commits to).
				if weakest == tierLog || weakest == tierAMD || weakest == tierStrict || weakest == tierNoRewrite {
					continue
				}
				// Otherwise the gate's weakness must already be published:
				// the gate field itself is in the record's rewritable list,
				// or every path of the group is disclosed as uncovered.
				if isRewritable(gate.path) {
					continue
				}
				for _, p := range g.paths {
					norm := tamperIndex.ReplaceAllString(p, "[]")
					if tamperValueAt(root, tamperKeySteps(p)) != nil && !uncovered[norm] {
						t.Errorf("%s: switching %s to %q (gate of %v) lands in %q; %s is not in the rewritable list and %s is not disclosed as uncovered",
							path, gate.path, gate.off, g.paths, weakest, gate.path, p)
					}
				}
			}
		}
	}
}

// F6: the transcript's input hash is the execution record's proof hash
// from run 248 on and the AER hash before it; neither source can stand
// in for the other.
func TestTranscriptSourceIsFixedByGeneration(t *testing.T) {
	for _, tc := range []struct {
		path   string
		after  bool
		source string
	}{
		{"testdata/round45/run-248-production.json", true, "execution_record.proof_hash"},
		{"testdata/round18/run-249-production.json", true, "execution_record.proof_hash"},
		{"testdata/round8/run-239-intact.json", false, "aer.seal.sealed_hash"},
		{"testdata/round40/hardware-run-2026-10.json", false, "aer.seal.sealed_hash"},
	} {
		data := readTestRecord(t, tc.path)
		b := mustDecode(t, tc.path)
		if transcriptFromProof(b) != tc.after {
			t.Errorf("%s: transcriptFromProof = %v, want %v (clock %s)", tc.path, !tc.after, tc.after, recordClock(b))
		}
		if f := verifyBoundCopies(b); len(f) != 0 {
			t.Errorf("%s: %v", tc.path, f)
		}
		// Switch the copy to the other source.
		other := "aer.seal.sealed_hash"
		if !tc.after {
			other = "execution_record.proof_hash"
		}
		root, _ := tamperDecode(data)
		switched, set := tamperSetAt(data, tamperKeySteps("transcript.proof_hash_input"), tamperValueAt(root, tamperKeySteps(other)))
		if !set {
			t.Fatal("could not switch the source")
		}
		sb, decodeErr := decodeBundle(switched)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if f := strings.Join(verifyBoundCopies(sb), "\n"); !strings.Contains(f, "transcript.proof_hash_input") {
			t.Errorf("%s: transcript.proof_hash_input switched from %s to %s still passes: %q", tc.path, tc.source, other, f)
		}
	}
}

// F5: each category section's hash and the copy in its seal are a group,
// so a seal copy changed alone fails.
func TestCategorySealCopiesMustAgree(t *testing.T) {
	data := readTestRecord(t, "testdata/round18/run-249-production.json")
	for _, section := range []string{"request_substance", "authorization_chain", "regulatory_scaffolding", "causal_graph", "system_provenance"} {
		p := section + ".seal.sealed_hash"
		if _, grouped := boundCopyGroupOf(p); !grouped {
			t.Errorf("%s is in no copy group", p)
		}
		changed, built := tamperApply(data, tamperChange{"changed", tamperKeySteps(p)})
		if !built {
			t.Fatal("could not apply the change")
		}
		b, decodeErr := decodeBundle(changed)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if f := strings.Join(verifyBoundCopies(b), "\n"); !strings.Contains(f, p) {
			t.Errorf("changing %s alone is not reported as a copy that disagrees: %q", p, f)
		}
	}
}

// F5: every row of the frozen pre-anchor table is compared with a
// displayed value, checked for its one defined value, or named as
// table-only with the reason; and the rows round 45 added fail when
// the record's value differs.
func TestEveryPreAnchorRowIsAccountedFor(t *testing.T) {
	b := mustDecode(t, "testdata/round22/run-253-production.json")
	table := map[string]string{}
	for _, row := range b.PreAnchor {
		table[row.Name] = row.Value
	}
	compared := map[string]bool{}
	for _, row := range preAnchorDisplayedRows(b, table) {
		compared[row.name] = true
	}
	for _, name := range artifacts.PreAnchorNamesV3 {
		if _, kind := preAnchorRowKinds[name]; !compared[name] && !kind {
			t.Errorf("table row %s is neither compared with the record nor named in preAnchorRowKinds", name)
		}
	}
	for name := range preAnchorRowKinds {
		if !strings.Contains(strings.Join(artifacts.PreAnchorNamesV3, ","), name) {
			t.Errorf("preAnchorRowKinds names %s, which is not a row of the table", name)
		}
	}
	if r := verifyPreAnchor(b); !r.Match {
		t.Fatalf("the genuine record fails: %v", r.Failures)
	}
	data := readTestRecord(t, "testdata/round22/run-253-production.json")
	for _, tc := range []struct{ path, row string }{
		{"epa.policy_gate.outcome", "pepg_outcome"},
		{"nrep.signed_at", "clock_epoch"},
	} {
		changed, set := tamperSetAt(data, tamperKeySteps(tc.path), "other")
		if !set {
			t.Fatal("could not change " + tc.path)
		}
		cb, decodeErr := decodeBundle(changed)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		r := verifyPreAnchor(cb)
		if r.Match || !strings.Contains(strings.Join(r.Failures, "\n"), tc.row+":") {
			t.Errorf("%s changed: the %s row does not fail: %v", tc.path, tc.row, r.Failures)
		}
	}
	// A bundle whose table names a deny receipt contradicts itself.
	root, _ := tamperDecode(data)
	rows := root.(map[string]any)["pre_anchor"].([]any)
	for _, r := range rows {
		if row := r.(map[string]any); row["name"] == "deny_receipt_hash" {
			row["value"] = strings.Repeat("ab", 32)
		}
	}
	withDeny, _ := json.Marshal(root)
	db, decodeErr := decodeBundle(withDeny)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if r := verifyPreAnchor(db); r.Match || !strings.Contains(strings.Join(r.Failures, "\n"), "deny_receipt_hash:") {
		t.Errorf("a table naming a deny receipt in a sealed run does not fail: %v", r.Failures)
	}
	_ = fmt.Sprint
}

// Round 45: each category section's hash and its seal copy are a group,
// so the reviewer's round-6 and round-7 rewrites, which recomputed a
// section's hash and left the seal's copy stale, now fail on that copy.
// A fuller forgery that also rewrites the seal copy keeps the verdict
// those files earned before, which the older tests still assert on it.
var staleSealRewrites = map[string]string{
	"V2_request_substance_rewritten.json":       "request_substance",
	"V3_authorization_chain_rewritten.json":     "authorization_chain",
	"V4_causal_graph_effect_added.json":         "causal_graph",
	"V5_system_provenance_upgraded.json":        "system_provenance",
	"run-238-STRIP_V2_request_substance.json":   "request_substance",
	"run-238-STRIP_V3_authorization_chain.json": "authorization_chain",
	"run-238-STRIP_V4_causal_graph_effect.json": "causal_graph",
	"run-238-STRIP_V5_system_provenance.json":   "system_provenance",
}

// requireStaleSealCopyFails asserts a rewrite that left a seal copy
// stale fails on that copy, then returns the fuller forgery with the
// five seal copies rewritten and the bundle hash recomputed.
func requireStaleSealCopyFails(t *testing.T, name string, b *artifacts.AuditBundle) *artifacts.AuditBundle {
	t.Helper()
	section, stale := staleSealRewrites[name]
	if !stale {
		return b
	}
	r := verify(b)
	want := section + ".seal.sealed_hash does not equal " + section + ".hash"
	if r.VerdictTier != "FAILED" || !strings.Contains(strings.Join(r.CrossChecks, "\n"), want) {
		t.Fatalf("%s: a rewrite that left the seal copy stale must fail on it: tier=%s cross=%v", name, r.VerdictTier, r.CrossChecks)
	}
	b.RequestSubstance.Seal.SealedHash = b.RequestSubstance.Hash
	b.AuthorizationChain.Seal.SealedHash = b.AuthorizationChain.Hash
	b.RegulatoryScaffolding.Seal.SealedHash = b.RegulatoryScaffolding.Hash
	b.CausalGraph.Seal.SealedHash = b.CausalGraph.Hash
	b.SystemProvenance.Seal.SealedHash = b.SystemProvenance.Hash
	b.BundleHash = artifacts.RecomputeBundleHash(b)
	return b
}

// Round 46: the forger test on each anchored receipt in testdata/round10.
// Run 241's receipt carries a v1 anchor, which binds the receipt's kind,
// envelope id and hash but not the document's run number, so run_id is
// its one rewritable path (the README and the docs guide say so); the
// four receipts with a v2 anchor have none.
func TestReceiptForgerResults(t *testing.T) {
	cases := map[string][]string{
		"testdata/round10/deny-receipt-run241-production.json":       {"run_id"},
		"testdata/round10/deny-receipt-run242-production-v2.json":    {},
		"testdata/round10/deny-receipt-run243-production-batch.json": {},
		"testdata/round10/deny-receipt-run245-production-batch.json": {},
		"testdata/round10/deny-receipt-run247-production-batch.json": {},
	}
	for path, want := range cases {
		o, ok := tamperRun(readTestRecord(t, path), judgeReceiptForTamper, true)
		if !ok {
			t.Fatalf("%s: the receipt did not run", path)
		}
		if got := o.rewritable(); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: rewritable paths %v, want %v", path, got, want)
		}
	}
	readme := strings.Join(strings.Fields(string(readTestRecord(t, "README.md"))), " ")
	if !strings.Contains(readme, "run 241's receipt, whose v1 anchor does not bind the run number, has one rewritable path, `run_id`") {
		t.Error("README does not state run 241's receipt's rewritable path")
	}
}
