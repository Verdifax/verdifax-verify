package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// The four SDKs' rule_in_force helper mirrors this file's rule for a refusal
// for missing fields (round 64, rule in force). Every refusal case of the
// shared vector, testdata/sdk-rule-in-force-vector.json (a copy of
// scripts/sdk-rule-in-force-vector.json), is run here through the verifier's
// own functions: a change the receipt seals that its context does not name is
// refused (gapActivationProblem); the change a refusal names is the one
// gapActivationOf reads; with a history, of every change it holds exactly the
// one the SDKs answer passes checkRuleInForce, and none when the SDKs refuse.
func TestTheSDKRuleInForceVectorAgreesWithTheVerifier(t *testing.T) {
	raw, readErr := os.ReadFile(filepath.Join("testdata", "sdk-rule-in-force-vector.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	var vector struct {
		Cases []struct {
			Name     string `json:"name"`
			Document struct {
				Gap     *artifacts.AttestationGapReceipt `json:"attestation_gap_receipt"`
				Context *artifacts.ReceiptContext        `json:"receipt_context"`
			} `json:"document"`
			PolicyHistory []json.RawMessage `json:"policy_history"`
			Expected      []struct {
				Outcome        string `json:"outcome"`
				ActivationHash string `json:"activation_hash"`
				FoundBy        string `json:"found_by"`
			} `json:"expected"`
			ExpectedError bool `json:"expected_error"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, tc := range vector.Cases {
		gap := tc.Document.Gap
		if gap == nil {
			continue
		}
		checked++
		want := ""
		for _, d := range tc.Expected {
			if d.Outcome == "attestation_gap" {
				want = d.ActivationHash
			}
		}
		if tc.ExpectedError == (want != "") {
			t.Fatalf("%s: the vector states both an answer and a refusal, or neither", tc.Name)
		}
		problem := gapActivationProblem(gap, tc.Document.Context)
		named := gapActivationOf(gap, tc.Document.Context)
		var entries []PolicyHistoryEntry
		for _, item := range tc.PolicyHistory {
			var e struct {
				Format string `json:"format"`
				PolicyHistoryEntry
			}
			if err := json.Unmarshal(item, &e); err != nil {
				t.Fatal(err)
			}
			if e.Format == artifacts.PolicyActivationFormat {
				entries = append(entries, e.PolicyHistoryEntry)
			}
		}
		// passes is each change of the history the verifier accepts as the
		// one the refusal was made under.
		var passes []string
		for _, e := range entries {
			c := &PolicyHistoryCheck{Checked: true, OK: true, Entries: entries}
			checkRuleInForce(c, gap, e.ActivationHash)
			if c.OK && (named == "" || named == e.ActivationHash) {
				passes = append(passes, e.ActivationHash)
			}
		}
		switch {
		case problem != nil:
			if !tc.ExpectedError {
				t.Errorf("%s: the verifier refuses the receipt (%v), and the SDKs answer %s", tc.Name, problem, want)
			}
		case len(entries) == 0:
			// With no history, only a change the refusal names can be stated.
			if named != want {
				t.Errorf("%s: the verifier reads change %q, and the SDKs answer %q", tc.Name, named, want)
			}
		case tc.ExpectedError:
			if len(passes) != 0 {
				t.Errorf("%s: the SDKs refuse, and the verifier accepts change %v as the one in force", tc.Name, passes)
			}
		default:
			if len(passes) != 1 || passes[0] != want {
				t.Errorf("%s: the verifier accepts %v as the change in force, and the SDKs answer %s", tc.Name, passes, want)
			}
		}
	}
	if checked < 10 {
		t.Fatalf("only %d refusal cases were checked; the vector holds more", checked)
	}
}
