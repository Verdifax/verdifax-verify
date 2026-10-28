package main

// Round-27 regression suite: a record the public log covers only in part
// must not read as verified or exit 0 by default.
//
// Until v0.15.3, a record sealed before leaf v5 (the October 2026
// hardware run is one) or a v5 record without a complete-record anchor
// printed "VERIFIED AND ANCHORED, PARTIAL COVERAGE" and exited 0. Its
// descriptive sections are sealed only by hashes inside the bundle, so a
// party able to rewrite the whole bundle could flip the decision, change
// the approver and add an effect, recompute those hashes, keep the real
// public-log entry, and a script gating on exit status accepted it. From
// v0.16.0 such a record is reported as ANCHORED, PARTIAL COVERAGE (tier
// ANCHORED_PARTIAL_COVERAGE) and exits 3 unless --allow-partial is given.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// forgeHardwareStory applies the round-27 reviewer's rewrite to the
// published hardware run: the decision flipped to deny, with the AER
// hash and the bundle hash recomputed and the public-log anchor kept.
// Since v0.17.10 the decision is also a copy of the EPA's attested
// context, so the rewrite reaches both, as a forger's would.
func forgeHardwareStory(t *testing.T) *artifacts.AuditBundle {
	t.Helper()
	b := loadRound8(t, "hardware-run-2026-10.json")
	b.AER.Decision.Result = "deny"
	b.AER.Decision.Note = "rewritten by a forger who holds only the published bundle"
	b.EPA.AttestedContext.DecisionResult = b.AER.Decision.Result
	b.EPA.AttestedContext.DecisionNote = b.AER.Decision.Note
	b.EPA.Hash = artifacts.RecomputeEPAHash(b.EPA)
	b.AER.Hash = artifacts.RecomputeAERHash(b.AER)
	b.BundleHash = artifacts.RecomputeBundleHash(b)
	return b
}

// The reviewer's own round-27 rewrite changed the AER's decision alone;
// since v0.17.10 the copy in the EPA's attested context disagrees and
// the record fails outright.
func TestR27DecisionFlippedInOneSectionOnlyNowFails(t *testing.T) {
	b := loadRound8(t, "hardware-run-2026-10.json")
	b.AER.Decision.Result = "deny"
	b.AER.Hash = artifacts.RecomputeAERHash(b.AER)
	b.BundleHash = artifacts.RecomputeBundleHash(b)
	r := verify(b)
	if r.VerdictTier != "FAILED" || !exitShouldFail(r, true, false) {
		t.Fatalf("a decision flipped in the AER alone must fail: tier=%s", r.VerdictTier)
	}
	if !strings.Contains(strings.Join(r.CrossChecks, "\n"), "epa.attested_context.decision_result does not equal aer.decision.result") {
		t.Fatalf("the failure must name the copy that disagrees: %v", r.CrossChecks)
	}
}

func assertPartialNotVerified(t *testing.T, b *artifacts.AuditBundle, r *Report) {
	t.Helper()
	if !r.AllPassed || !r.Anchored {
		t.Fatalf("expected every check to pass on an anchored record: tier=%s", r.VerdictTier)
	}
	if completeRecordAnchored(r) {
		t.Fatal("record unexpectedly reads as complete-record anchored")
	}
	if r.VerdictTier != "ANCHORED_PARTIAL_COVERAGE" {
		t.Fatalf("tier = %s, want ANCHORED_PARTIAL_COVERAGE", r.VerdictTier)
	}
	if exitShouldFail(r, false, false) {
		t.Fatal("a partial record is not a failed check and must not exit 1")
	}
	if !partialCoverageExit(r, false) {
		t.Fatal("a partial record must exit 3 without --allow-partial")
	}
	if partialCoverageExit(r, true) {
		t.Fatal("--allow-partial must restore exit 0")
	}
	out := captureHumanReport(t, b, r)
	if strings.Contains(out, "VERIFIED") {
		t.Fatalf("a partial record's report must not say VERIFIED:\n%s", out)
	}
	if !strings.Contains(out, "VERDICT: ⚠ ANCHORED, PARTIAL COVERAGE") || !strings.Contains(out, "Exit code 3 without --allow-partial") {
		t.Fatalf("verdict must name partial coverage and exit 3:\n%s", out)
	}
}

func TestR27PublishedHardwareRunIsPartialAndExits3(t *testing.T) {
	b := loadRound8(t, "hardware-run-2026-10.json")
	assertPartialNotVerified(t, b, verify(b))
}

func TestR27HardwareStoryRewriteIsNeverReportedAsVerified(t *testing.T) {
	b := forgeHardwareStory(t)
	r := verify(b)
	// The rewrite is outside the pre-v5 leaf, so no check can catch it;
	// what must hold is that the verdict and exit code do not vouch for it.
	assertPartialNotVerified(t, b, r)
}

// The round-6 reviewer's files that flipped the AER decision alone (V1
// and V6) fail since v0.17.10, because the EPA's attested context still
// carries the original; the other rewrites, which changed sections the
// pre-v5 leaf does not bind and left every copy consistent, stay
// anchored with partial coverage and exit 3.
func TestR27Round6StoryRewritesExit3(t *testing.T) {
	flipped := map[string]bool{"V1_aer_decision_flipped_to_deny.json": true, "V6_story_rewrite_all.json": true}
	for _, name := range round6Forgeries {
		t.Run(name, func(t *testing.T) {
			b := loadRound6(t, name)
			if !flipped[name] {
				b = requireStaleSealCopyFails(t, name, b)
			}
			r := verify(b)
			if flipped[name] {
				if r.VerdictTier != "FAILED" || !exitShouldFail(r, true, false) {
					t.Fatalf("a decision flipped in one copy must fail: tier=%s", r.VerdictTier)
				}
				return
			}
			assertPartialNotVerified(t, b, r)
		})
	}
}

func TestR27CompleteRecordStillExits0(t *testing.T) {
	r := verify(loadRound7(t, "run-238-intact.json"))
	if !completeRecordAnchored(r) || r.VerdictTier != "VERIFIED_ANCHORED" {
		t.Fatalf("complete record: tier=%s coverage=%s", r.VerdictTier, r.RecordCoverage)
	}
	if exitShouldFail(r, false, false) || partialCoverageExit(r, false) {
		t.Fatal("a complete-record anchored record must exit 0")
	}
}

// TestR27BinaryExitCodes runs the built binary, as a script would.
func TestR27BinaryExitCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "verdifax-verify")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build: %v\n%s", buildErr, out)
	}
	hardware := filepath.Join("testdata", "round8", "hardware-run-2026-10.json")
	complete := filepath.Join("testdata", "round7", "run-238-intact.json")
	cases := []struct {
		args []string
		want int
	}{
		{[]string{hardware}, 3},
		{[]string{"--allow-partial", hardware}, 0},
		{[]string{"--json", hardware}, 3},
		{[]string{"--show-evidence-summary", hardware}, 3},
		{[]string{complete}, 0},
	}
	for _, c := range cases {
		cmd := exec.Command(bin, c.args...)
		runErr := cmd.Run()
		got := 0
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			got = exitErr.ExitCode()
		} else if runErr != nil {
			t.Fatalf("%v: %v", c.args, runErr)
		}
		if got != c.want {
			t.Errorf("%v: exit %d, want %d", c.args, got, c.want)
		}
	}
}
