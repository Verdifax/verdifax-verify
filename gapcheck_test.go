package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/policyhash"
)

// gapPolicy is an account policy requiring the fields listed, as the round 62
// demo's policy requires actor_id.
func gapPolicy(id, fields string) string {
	required := ""
	if fields != "" {
		required = `"required_attested_fields":[` + fields + `],`
	}
	return `{"schema":"psl.v1","policy_id":"` + id + `","policy_name":"Demo rules","policy_version":"4","effective_at":"2026-11-13T00:00:00Z",` + required +
		`"default_effect":"deny","rules":[{"rule_id":"steps","effect":"allow","subject":{"type":"any","id_match":{"operator":"any"}},"verb":{"match":{"operator":"any"}},"object":{"type":"any","id_match":{"operator":"any"}}}]}`
}

// gapOf is the refusal a server seals under doc for the fields missing.
func gapOf(t *testing.T, doc string, missing ...string) *artifacts.AttestationGapReceipt {
	t.Helper()
	got, err := policyhash.FromDocument([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	required, err := policyhash.RequiredAttestedFields([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return &artifacts.AttestationGapReceipt{Version: "vfa.attestation_gap_receipt.v1", DecisionReasonCode: "ATTESTATION_GAP",
		PolicyHash: got.PolicyHash, PolicyID: got.PolicyID, PolicyName: got.PolicyName,
		RequiredFields: required, MissingFields: missing}
}

// Round 62: a policy document given with a refusal for missing fields is
// checked against the refusal, with --policy or --account-policy alike.
func TestARefusalForMissingFieldsIsCheckedAgainstThePolicyGiven(t *testing.T) {
	demo := gapPolicy("claims-review-demo-rules", `"actor_id"`)
	refusal := gapOf(t, demo, "actor_id")
	for _, flag := range []string{"--policy", "--account-policy"} {
		if c := checkGapPolicyDocument(refusal, []byte(demo), flag); !c.DocumentMatch || c.Reason != "" || !c.Present || c.Outcome != "refused" {
			t.Errorf("%s: the policy the refusal names must match it: %+v", flag, c)
		}
	}
	twoFields := gapOf(t, gapPolicy("claims-review-demo-rules", `"actor_id","model_provider"`), "model_provider")
	noFields := gapOf(t, gapPolicy("claims-review-demo-rules", ""), "actor_id")
	notRequired := gapOf(t, demo, "model_provider")
	noneMissing := gapOf(t, demo)
	wrongList := gapOf(t, demo, "actor_id")
	wrongList.RequiredFields = []string{"actor_id", "model_name"}
	for name, c := range map[string]struct {
		refusal *artifacts.AttestationGapReceipt
		doc     string
		want    string
	}{
		"another policy":                    {refusal, gapPolicy("another", `"actor_id"`), "is not"},
		"the policy requiring another set":  {twoFields, demo, "is not"},
		"a policy requiring none":           {noFields, gapPolicy("claims-review-demo-rules", ""), "requires no attested fields"},
		"a field the policy never required": {notRequired, demo, "does not require"},
		"no field missing":                  {noneMissing, demo, "names no missing field"},
		"a different required list":         {wrongList, demo, "were required"},
		"not a policy":                      {refusal, `{"schema":"psl.v1"`, "could not be read"},
	} {
		got := checkGapPolicyDocument(c.refusal, []byte(c.doc), "--account-policy")
		if got.DocumentMatch || !strings.Contains(got.Reason, c.want) || !policyFailed(got) {
			t.Errorf("%s must fail naming %q: %+v", name, c.want, got)
		}
	}
}

// The report's verdict follows the check: the policy the refusal names leaves
// it as it was, any other fails it, under either option.
func TestThePolicyOptionsFailARefusalOfAnotherPolicy(t *testing.T) {
	demo := gapPolicy("claims-review-demo-rules", `"actor_id"`)
	dir := t.TempDir()
	right, wrong := filepath.Join(dir, "right.json"), filepath.Join(dir, "wrong.json")
	if err := os.WriteFile(right, []byte(demo), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrong, []byte(gapPolicy("another", `"actor_id"`)), 0o600); err != nil {
		t.Fatal(err)
	}
	report := func() *ReceiptReport {
		return &ReceiptReport{gap: gapOf(t, demo, "actor_id"), AllPassed: true, VerdictTier: "ANCHORED"}
	}
	r := report()
	applyReceiptAccountFlags(r, right, "")
	if !r.AllPassed || r.AccountPolicyGate == nil || !r.AccountPolicyGate.DocumentMatch {
		t.Fatalf("--account-policy with the policy named: %+v %+v", r, r.AccountPolicyGate)
	}
	r = report()
	applyReceiptAccountFlags(r, wrong, "")
	if r.AllPassed || r.VerdictTier != "FAILED" {
		t.Fatalf("--account-policy with another policy must fail: %+v", r)
	}
	r = report()
	applyReceiptPolicyDocument(r, []byte(demo))
	if !r.AllPassed || !r.PolicyGate.DocumentMatch {
		t.Fatalf("--policy with the policy named: %+v", r.PolicyGate)
	}
	r = report()
	applyReceiptPolicyDocument(r, []byte(gapPolicy("another", `"actor_id"`)))
	if r.AllPassed || r.VerdictTier != "FAILED" {
		t.Fatalf("--policy with another policy must fail: %+v", r)
	}
}
