package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Round 46: a gate assumed a server invariant that held for the records
// the tests named and not for an older generation, so the genuine run
// 208 in internal/artifacts/testdata failed as a rewrite. Every record
// and receipt JSON in the repository is listed here with its class and
// the verdict and exit code it must earn; a file missing from the list
// fails the test, so a new fixture cannot be left out, and the copy,
// duplicate and gate tests read their genuine records from this list.
type fixtureVerdict struct {
	path, class, tier string
	exit              int
}

var fixtureVerdicts = []fixtureVerdict{
	{"internal/artifacts/testdata/A7_aivp_output_hash_swapped.json", "forgery", "FAILED", 1},
	{"internal/artifacts/testdata/R5_payload_hash_replaced.json", "forgery", "FAILED", 1},
	{"internal/artifacts/testdata/R7_story_rewrite.json", "forgery", "FAILED", 1},
	{"internal/artifacts/testdata/bundle-anchor-vector.json", "synthetic", "ANCHORED_PARTIAL_COVERAGE", 3},
	{"internal/artifacts/testdata/golden-bundle-run-208.json", "genuine", "ANCHORED_PARTIAL_COVERAGE", 3},
	{"internal/artifacts/testdata/run-235-v3-bundle.json", "synthetic", "FAILED", 1},
	{"testdata/policy-gate/orchestrator-mock-allowed-run.json", "synthetic", "SELF_CONSISTENT_NOT_ANCHORED", 1},
	{"testdata/round10/deny-receipt-orchestrator-mock.json", "synthetic", "SELF_CONSISTENT_NOT_ANCHORED", 1},
	{"testdata/round10/deny-receipt-run241-production.json", "genuine", "VERIFIED_ANCHORED", 0},
	{"testdata/round10/deny-receipt-run242-production-v2.json", "genuine", "VERIFIED_ANCHORED", 0},
	{"testdata/round10/deny-receipt-run243-production-batch.json", "genuine", "VERIFIED_ANCHORED", 0},
	{"testdata/round10/deny-receipt-run245-production-batch.json", "genuine", "VERIFIED_ANCHORED", 0},
	{"testdata/round10/deny-receipt-run247-production-batch.json", "genuine", "VERIFIED_ANCHORED", 0},
	{"testdata/round18/run-249-production.json", "genuine", "VERIFIED_ANCHORED", 0},
	{"testdata/round22/run-253-production.json", "genuine", "VERIFIED_ANCHORED", 0},
	{"testdata/round40/hardware-run-2026-10.json", "genuine", "ANCHORED_PARTIAL_COVERAGE", 3},
	{"testdata/round45/run-248-production.json", "genuine", "VERIFIED_ANCHORED", 0},
	{"testdata/round6/L1_leaf_hash_swapped_genuine_entry_body.json", "forgery", "FAILED", 1},
	{"testdata/round6/V1_aer_decision_flipped_to_deny.json", "forgery", "FAILED", 1},
	{"testdata/round6/V2_request_substance_rewritten.json", "forgery", "FAILED", 1},
	{"testdata/round6/V3_authorization_chain_rewritten.json", "forgery", "FAILED", 1},
	{"testdata/round6/V4_causal_graph_effect_added.json", "forgery", "FAILED", 1},
	{"testdata/round6/V5_system_provenance_upgraded.json", "forgery", "FAILED", 1},
	{"testdata/round6/V6_story_rewrite_all.json", "forgery", "FAILED", 1},
	{"testdata/round6/run-237-intact.json", "genuine", "ANCHORED_PARTIAL_COVERAGE", 3},
	{"testdata/round7/orchestrator-e2e-v6-mock.json", "synthetic", "SELF_CONSISTENT_NOT_ANCHORED", 1},
	{"testdata/round7/run-238-STRIP_V1_aer_decision.json", "forgery", "FAILED", 1},
	{"testdata/round7/run-238-STRIP_V2_request_substance.json", "forgery", "FAILED", 1},
	{"testdata/round7/run-238-STRIP_V3_authorization_chain.json", "forgery", "FAILED", 1},
	{"testdata/round7/run-238-STRIP_V4_causal_graph_effect.json", "forgery", "FAILED", 1},
	{"testdata/round7/run-238-STRIP_V5_system_provenance.json", "forgery", "FAILED", 1},
	{"testdata/round7/run-238-STRIP_V6_all.json", "forgery", "FAILED", 1},
	{"testdata/round7/run-238-intact.json", "genuine", "VERIFIED_ANCHORED", 0},
	{"testdata/round7/v6-intact-test-log.json", "synthetic", "FAILED", 1},
	{"testdata/round7/v6-strip-test-log.json", "synthetic", "FAILED", 1},
	{"testdata/round8/hardware-run-2026-10.json", "genuine", "ANCHORED_PARTIAL_COVERAGE", 3},
	{"testdata/round8/orchestrator-e2e-v7-mock.json", "synthetic", "SELF_CONSISTENT_NOT_ANCHORED", 1},
	{"testdata/round8/run-239-intact.json", "genuine", "VERIFIED_ANCHORED", 0},
	{"testdata/round9/run-239-case-variant-keys.json", "forgery", "FAILED", 1},
}

// genuineRecordFixtures returns every genuine production bundle in the
// list, the records the copy, duplicate and gate tests must accept.
func genuineRecordFixtures() []string {
	var out []string
	for _, f := range fixtureVerdicts {
		if f.class == "genuine" && !strings.Contains(f.path, "receipt") {
			out = append(out, f.path)
		}
	}
	return out
}

func recordFixtureFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, root := range []string{"testdata", "internal/artifacts/testdata"} {
		walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
				return err
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			var doc map[string]any
			if json.Unmarshal(raw, &doc) != nil {
				return nil
			}
			_, envelope := doc["envelope"]
			_, aer := doc["aer"]
			receipt := false
			for _, k := range []string{"deny_receipt", "ccv_halt_receipt", "macc_halt_receipt", "aivp_t4_halt_receipt", "attestation_gap_receipt"} {
				_, has := doc[k]
				receipt = receipt || has
			}
			if (envelope && aer) || receipt {
				out = append(out, filepath.ToSlash(path))
			}
			return nil
		})
		if walkErr != nil {
			t.Fatal(walkErr)
		}
	}
	sort.Strings(out)
	return out
}

func TestEveryRecordFixtureIsListed(t *testing.T) {
	listed := map[string]bool{}
	for _, f := range fixtureVerdicts {
		listed[f.path] = true
	}
	found := recordFixtureFiles(t)
	for _, p := range found {
		if !listed[p] {
			t.Errorf("%s is a record or receipt fixture missing from fixtureVerdicts: give it a class and the verdict it must earn", p)
		}
	}
	present := map[string]bool{}
	for _, p := range found {
		present[p] = true
	}
	for _, f := range fixtureVerdicts {
		if !present[f.path] {
			t.Errorf("fixtureVerdicts lists %s, which is not a record fixture in the repository", f.path)
		}
	}
}

func TestEveryRecordFixtureKeepsItsVerdict(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "verdifax-verify")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build: %v\n%s", buildErr, out)
	}
	for _, f := range fixtureVerdicts {
		out, runErr := exec.Command(bin, "--json", f.path).Output()
		code := 0
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			code = exitErr.ExitCode()
		} else if runErr != nil {
			t.Fatalf("%s: %v", f.path, runErr)
		}
		var rep map[string]any
		_ = json.Unmarshal(out, &rep)
		tier, _ := rep["verdict_tier"].(string)
		if tier != f.tier || code != f.exit {
			t.Errorf("%s (%s): %s, exit %d; want %s, exit %d", f.path, f.class, tier, code, f.tier, f.exit)
		}
	}
}

// withGenuineFixtures adds every genuine record in fixtureVerdicts to a
// test's own list, so no genuine generation is left untested.
func withGenuineFixtures(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range append(append([]string{}, list...), genuineRecordFixtures()...) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
