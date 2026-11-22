package artifacts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The records these tests read were sealed by production before round 64.
// The server keeps copies in its testdata/saved-records; this verifier reads
// its own, byte for byte the same, in testdata/round59 and
// testdata/policy-gate, where every other test holds them to their verdicts.
var savedRecordDirs = map[string]string{
	"builtin-allowed.json": "policy-gate", "builtin-refused.json": "policy-gate",
	"run-3223-key-policy.json": "round59", "run-3235-signoff-required.json": "round59",
	"run-3236-account-refusal-receipt.json": "round59",
}

func readSaved(t *testing.T, name string) map[string]json.RawMessage {
	t.Helper()
	raw, readErr := os.ReadFile(filepath.Join("..", "..", "testdata", savedRecordDirs[name], name))
	if readErr != nil {
		t.Fatal(readErr)
	}
	var doc map[string]json.RawMessage
	if decodeErr := json.Unmarshal(raw, &doc); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	return doc
}

// sameInputs decodes a sealed inputs object as PolicyInputs and requires its
// encoding to be the sealed bytes exactly, so no field was lost, added or
// reordered by the type.
func sameInputs(t *testing.T, where string, sealed json.RawMessage) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(sealed))
	dec.DisallowUnknownFields()
	var in PolicyInputs
	if decodeErr := dec.Decode(&in); decodeErr != nil {
		t.Fatalf("%s: %v", where, decodeErr)
	}
	again, encodeErr := json.Marshal(in)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	var compact bytes.Buffer
	if compactErr := json.Compact(&compact, sealed); compactErr != nil {
		t.Fatal(compactErr)
	}
	if !bytes.Equal(again, compact.Bytes()) {
		t.Fatalf("%s: inputs encode as\n%s\nsealed as\n%s", where, again, compact.Bytes())
	}
}

// Round 64, R304: every saved record's EPA, whose policy gates seal the
// decision's inputs, recomputes to its sealed hash with the round 64 inputs
// type, and every sealed inputs object encodes to its exact bytes.
func TestSavedRecordsHashAsSealedWithRound64Inputs(t *testing.T) {
	for _, name := range []string{"run-3223-key-policy.json", "run-3235-signoff-required.json", "builtin-allowed.json"} {
		var epa EPA
		if decodeErr := json.Unmarshal(readSaved(t, name)["epa"], &epa); decodeErr != nil {
			t.Fatalf("%s: %v", name, decodeErr)
		}
		if got := RecomputeEPAHash(epa); got != epa.Hash {
			t.Errorf("%s: EPA hash %s, sealed %s", name, got, epa.Hash)
		}
		var gates struct {
			PolicyGate        *struct{ Inputs json.RawMessage } `json:"policy_gate"`
			AccountPolicyGate *struct{ Inputs json.RawMessage } `json:"account_policy_gate"`
		}
		if decodeErr := json.Unmarshal(readSaved(t, name)["epa"], &gates); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		found := 0
		for label, g := range map[string]*struct{ Inputs json.RawMessage }{"policy_gate": gates.PolicyGate, "account_policy_gate": gates.AccountPolicyGate} {
			if g != nil && len(g.Inputs) > 0 {
				sameInputs(t, name+" "+label, g.Inputs)
				found++
			}
		}
		if found == 0 {
			t.Errorf("%s seals no inputs; the test reads nothing", name)
		}
	}
}

// Round 64, R304: every saved refusal's receipt context, which seals the
// decision's inputs through their digest, gives the public-log leaf its
// anchor names, with the round 64 inputs type.
func TestSavedReceiptsLeafAsAnchoredWithRound64Inputs(t *testing.T) {
	for _, name := range []string{"run-3236-account-refusal-receipt.json", "builtin-refused.json"} {
		doc := readSaved(t, name)
		var context ReceiptContext
		var receipt DenyReceipt
		var anchor ReceiptAnchor
		var runID int64
		for field, into := range map[string]any{"receipt_context": &context, "deny_receipt": &receipt, "receipt_anchor": &anchor, "run_id": &runID} {
			if decodeErr := json.Unmarshal(doc[field], into); decodeErr != nil {
				t.Fatalf("%s %s: %v", name, field, decodeErr)
			}
		}
		leaf := ComputeReceiptLeafHashV3("deny_receipt", receipt.EnvelopeID, receipt.Hash, runID, context.Hash())
		if leaf != anchor.LeafHashHex {
			t.Errorf("%s: leaf %s, anchored %s", name, leaf, anchor.LeafHashHex)
		}
		var sealed struct {
			Policy        *struct{ Inputs json.RawMessage } `json:"policy"`
			AccountPolicy *struct{ Inputs json.RawMessage } `json:"account_policy"`
		}
		if decodeErr := json.Unmarshal(doc["receipt_context"], &sealed); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		found := 0
		for label, b := range map[string]*struct{ Inputs json.RawMessage }{"policy": sealed.Policy, "account_policy": sealed.AccountPolicy} {
			if b != nil && len(b.Inputs) > 0 {
				sameInputs(t, name+" "+label, b.Inputs)
				found++
			}
		}
		if found == 0 {
			t.Errorf("%s seals no inputs; the test reads nothing", name)
		}
	}
}

// Round 64: setup facts and a data-use declaration, when sealed, join the
// inputs digest a receipt context binds, so a changed declaration changes the
// receipt's leaf.
func TestSetupAndDataUseJoinTheReceiptDigest(t *testing.T) {
	base := PolicyBinding{Source: PolicySourceCustomer, PolicyHash: "p", Outcome: "deny", FiredRuleID: "r",
		Inputs: &PolicyInputs{SubjectID: "a", SubjectType: "agent", Verb: "v", ObjectType: "data", ObjectID: "o",
			Classification: "INTERNAL", EvaluatedAt: "2026-11-17T00:00:00Z"}}
	digest := func(b PolicyBinding) string { return b.fields()[len(b.fields())-1] }
	withSetup, withUse := base, base
	setupInputs, useInputs := *base.Inputs, *base.Inputs
	setupInputs.Setup = &SetupFacts{DeclaredByCaller: &DeclaredSetup{ModelName: "m"}}
	useInputs.DataUse = &DataUse{Purpose: "claims.review"}
	withSetup.Inputs, withUse.Inputs = &setupInputs, &useInputs
	if digest(withSetup) == digest(base) || digest(withUse) == digest(base) || digest(withSetup) == digest(withUse) {
		t.Fatal("setup facts and a data use must each change the inputs digest")
	}
}
