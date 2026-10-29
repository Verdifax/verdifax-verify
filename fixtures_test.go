package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// Round 47: a copy group switched off by an anchoring window must never
// be off on a genuine record that wrote its copies equal; the windows
// hold only records that wrote them differently.
func TestNoWindowSwitchesOffCopiesThatAgree(t *testing.T) {
	for _, path := range genuineRecordFixtures() {
		b := mustDecode(t, path)
		root, _ := tamperDecode(readTestRecord(t, path))
		for _, g := range boundCopyGroups {
			for _, gate := range g.gates {
				if gate.path != "rekor_anchor.integrated_time" || !rekorAnchored(b) || gate.active(b) {
					continue
				}
				var carried []string
				for _, p := range g.paths {
					if v := tamperValueAt(root, tamperKeySteps(p)); v != nil {
						carried = append(carried, fmt.Sprint(v))
					}
				}
				same := len(carried) >= 2
				for _, v := range carried {
					same = same && v == carried[0]
				}
				if same {
					t.Errorf("%s: the group %v is switched off by an anchoring window, yet the record wrote its copies equal", path, g.paths)
				}
			}
		}
	}
}

// Round 47: the forger's result on every genuine record fixture is
// pinned, so a change that frees or binds a path on any record generation
// (run 208's checkpoint copy, freed by a boundary in v0.17.13 before this
// test existed) fails here. Round 48: the pin is the count and the
// SHA-256 of the sorted path list, one path per line, so a change that
// frees one path and binds another on the same record fails too. Run 238
// predates the requirement for a complete-record anchor, so deleting its
// anchor or renaming its backend earns partial coverage, as the security
// page says; runs 208 and 237 and the hardware run predate leaf v5.
type forgerPin struct {
	count int
	paths string // SHA-256 of the sorted rewritable paths joined by newlines
}

const noPaths = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

var genuineForgerRewritable = map[string]forgerPin{
	"internal/artifacts/testdata/golden-bundle-run-208.json": {287, "32559da3bac751db6722947ff1d8fd1e762da1f2c38e728a412515ffd04a1048"},
	"testdata/round18/run-249-production.json":               {0, noPaths},
	"testdata/round22/run-253-production.json":               {0, noPaths},
	"testdata/round40/hardware-run-2026-10.json":             {291, "dce55fc168ad92eea3886fd0d161b5a3f5efdb7851085d30d33c57939487f54b"},
	"testdata/round45/run-248-production.json":               {0, noPaths},
	"testdata/round6/run-237-intact.json":                    {245, "2da206e050c1915a8b6ed616aa97945c438853a39a5d9a3d21500a3cdfe00a20"},
	"testdata/round7/run-238-intact.json":                    {2, "182fec3ff095b6c2e27f7aa941adccd1ca7882f7437cf3d8a585d93578d37cd6"},
	"testdata/round8/hardware-run-2026-10.json":              {291, "dce55fc168ad92eea3886fd0d161b5a3f5efdb7851085d30d33c57939487f54b"},
	"testdata/round8/run-239-intact.json":                    {0, noPaths},
}

func TestEveryGenuineFixtureKeepsItsForgerResult(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the forger mode on every genuine record")
	}
	genuine := genuineRecordFixtures()
	for _, path := range genuine {
		if _, pinned := genuineForgerRewritable[path]; !pinned {
			t.Errorf("%s is a genuine record fixture without a pinned forger result", path)
		}
	}
	for path, want := range genuineForgerRewritable {
		o, ok := tamperRun(readTestRecord(t, path), memoJudge, true)
		if !ok {
			t.Fatalf("%s: the record did not run", path)
		}
		paths := append([]string(nil), o.rewritable()...)
		sort.Strings(paths)
		sum := sha256.Sum256([]byte(strings.Join(paths, "\n")))
		if got := hex.EncodeToString(sum[:]); len(paths) != want.count || got != want.paths {
			t.Errorf("%s: %d rewritable paths with list hash %s, pinned %d with %s", path, len(paths), got, want.count, want.paths)
		}
	}
}

// forgerHeavy marks a test that runs the forger mode over a whole record
// (thousands of verifications). CI runs the suite twice (round 47): once
// under the race detector with -short, which skips these, and once
// without the race detector, which runs everything. The forger mode
// starts no goroutines, so the race detector finds nothing in these
// tests; under it they took most of the 30-minute budget and the
// v0.17.14 release test timed out.
func forgerHeavy(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("runs the forger mode over a whole record; CI runs it in the suite without the race detector")
	}
}
