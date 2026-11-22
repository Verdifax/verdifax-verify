package artifacts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// The vectors below were computed apart from this package, from the recipes
// the records' documentation states (length-prefixed SHA-256 over the listed
// parts, and the v3 receipt leaf), so a change to either recipe fails here.
const (
	setupVectorHash   = "6ca3ae1b4c08b6bad237030bc2e7bf184d0f33e7ad368bb148e2f320c8bdf8c9"
	setupChangeVector = "673f8e8b82706cac281beffc1cccd63ab3c3c1611b5bc721cd25befd6452fde7"
	setupChangeLeaf   = "c81f8d20bda3536ac6514604caade18eea98410288d485f437137fbde17f9c24"
	reviewDueVector   = "3ad67985e4d241043cc73bff88e5d405328b75f30501a010e25c1531cac0bc3a"
	reviewDueLeaf     = "00de49eb629eafd746dcd6a5189a765696331cef0daf7c56305e4f92b2b1fae5"
)

func setupChangeVectorRecord() *SetupChange {
	c := &SetupChange{Format: SetupChangeFormat, RunID: 42, RecordKind: SetupRecordKindRecord, RecordHash: strings.Repeat("a", 64),
		Scope: "account", ActivationHash: strings.Repeat("b", 64), Fields: []string{"model_name", "review_prompt_id"},
		PreviousSetupHash: strings.Repeat("c", 64),
		Setup: SetupFacts{DeclaredByCaller: &DeclaredSetup{ModelName: "claude-opus-5-5"},
			AttestedByVerdifax: &AttestedSetup{ReviewPromptID: "statements-v1"}},
		ChangedAt: "2026-11-17T12:00:00Z", Signal: SignalLink{Account: "account-7", Sequence: 5, PreviousSignalHash: strings.Repeat("d", 64)}}
	c.SetupHash = SetupHash(c.Fields, &c.Setup)
	c.SetupChangeHash = c.ComputeHash()
	return c
}

func reviewDueVectorRecord() *ReviewDue {
	r := &ReviewDue{Format: ReviewDueFormat, ChainID: "account-7", ActivationSequence: 3, ActivationHash: strings.Repeat("a", 64),
		DocumentHash: strings.Repeat("b", 64), ActivatedAt: "2026-08-01T00:00:00.5Z", IntervalDays: 90,
		DueAt: "2026-10-30T00:00:00.5Z", Statement: ReviewDueStatement(3), StatedAt: "2026-10-30T00:01:00Z",
		Signal: SignalLink{Account: "account-7", Sequence: 6, PreviousSignalHash: strings.Repeat("c", 64)}}
	r.ReviewDueHash = r.ComputeHash()
	return r
}

// Round 64, R307: the setup fingerprint, the setup-change record's hash and
// its leaf follow the stated recipe, and the record is valid.
func TestSetupChangeVector(t *testing.T) {
	c := setupChangeVectorRecord()
	if c.SetupHash != setupVectorHash || c.SetupChangeHash != setupChangeVector || c.LeafHash() != setupChangeLeaf {
		t.Fatalf("setup %s change %s leaf %s", c.SetupHash, c.SetupChangeHash, c.LeafHash())
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("the vector must be valid: %v", err)
	}
	if err := ValidateReceiptLeafFieldsV3(SetupChangeKind, c.Signal.Account, c.SetupChangeHash, c.Signal.Sequence, c.Signal.PreviousSignalHash); err != nil {
		t.Fatalf("a setup change must be loggable: %v", err)
	}
}

func TestSetupChangeHashCoversEveryValue(t *testing.T) {
	for name, mutate := range map[string]func(c *SetupChange){
		"run":         func(c *SetupChange) { c.RunID = 43 },
		"record kind": func(c *SetupChange) { c.RecordKind = "deny_receipt" },
		"record":      func(c *SetupChange) { c.RecordHash = strings.Repeat("e", 64) },
		"scope":       func(c *SetupChange) { c.Scope = "key-9" },
		"activation":  func(c *SetupChange) { c.ActivationHash = strings.Repeat("e", 64) },
		"previous":    func(c *SetupChange) { c.PreviousSetupHash = "" },
		"value":       func(c *SetupChange) { c.Setup.DeclaredByCaller.ModelName = "claude-sonnet-5" },
		"stated by": func(c *SetupChange) {
			c.Setup.AttestedByVerdifax.ReviewPromptID = ""
		},
		"time":   func(c *SetupChange) { c.ChangedAt = "2026-11-17T12:00:01Z" },
		"signal": func(c *SetupChange) { c.Signal.Sequence = 6 },
		"fields": func(c *SetupChange) { c.Fields = []string{"model_name"} },
	} {
		c := setupChangeVectorRecord()
		mutate(c)
		if c.ComputeHash() == setupChangeVector {
			t.Errorf("%s does not change the record's hash", name)
		}
	}
}

func TestSetupChangeValidateRefusesABadShape(t *testing.T) {
	for name, mutate := range map[string]func(c *SetupChange){
		"unknown format":      func(c *SetupChange) { c.Format = "verdifax.setup-change.v2" },
		"unknown fact":        func(c *SetupChange) { c.Fields = []string{"model_name", "actor_id"} },
		"fields out of order": func(c *SetupChange) { c.Fields = []string{"review_prompt_id", "model_name"} },
		"fingerprint":         func(c *SetupChange) { c.SetupHash = strings.Repeat("e", 64) },
		"unchanged":           func(c *SetupChange) { c.PreviousSetupHash = c.SetupHash },
		"unwatched value": func(c *SetupChange) {
			c.Setup.DeclaredByCaller.ModelVersion = "1"
		},
		"empty group": func(c *SetupChange) {
			c.Fields = []string{"model_name"}
			c.Setup.AttestedByVerdifax = &AttestedSetup{}
			c.SetupHash = SetupHash(c.Fields, &c.Setup)
		},
		"bad scope":       func(c *SetupChange) { c.Scope = "team-a" },
		"bad record kind": func(c *SetupChange) { c.RecordKind = "bundle" },
	} {
		c := setupChangeVectorRecord()
		mutate(c)
		c.SetupChangeHash = c.ComputeHash()
		if c.Validate() == nil {
			t.Errorf("%s: a bad record was accepted", name)
		}
	}
}

// The fingerprint and the record list facts in one order, the decision's
// (psleval.SetupFacts, which this package cannot import; R163 keeps the
// verifier's copies in step).
func TestSetupFactOrderIsTheDecisionsOrder(t *testing.T) {
	want := "model_provider,model_name,model_version,model_temperature,prompt_hash,client_name,client_version,review_model,review_prompt_id,review_checker_id"
	if strings.Join(SetupFactOrder, ",") != want {
		t.Fatalf("fact order %v", SetupFactOrder)
	}
	if ordered, err := OrderSetupFields([]string{"review_model", "model_name"}); err != nil || strings.Join(ordered, ",") != "model_name,review_model" {
		t.Fatalf("ordered %v %v", ordered, err)
	}
}

// Round 64, R309: the review-due record's hash, leaf and due time follow the
// stated recipe, and it says only that the declared date passed.
func TestReviewDueVector(t *testing.T) {
	r := reviewDueVectorRecord()
	if r.ReviewDueHash != reviewDueVector || r.LeafHash() != reviewDueLeaf {
		t.Fatalf("hash %s leaf %s", r.ReviewDueHash, r.LeafHash())
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("the vector must be valid: %v", err)
	}
	if r.Statement != "the date this policy declared has passed while activation 3 was in force" {
		t.Fatalf("statement %q", r.Statement)
	}
	if due, err := ReviewDueAt("2027-01-01T09:00:00+05:30", 0, ""); err != nil || due != "2027-01-01T03:30:00Z" {
		t.Fatalf("review_by due %s %v", due, err)
	}
}

func TestReviewDueValidateRefusesABadShape(t *testing.T) {
	for name, mutate := range map[string]func(r *ReviewDue){
		"both forms":       func(r *ReviewDue) { r.ReviewBy = "2026-10-30T00:00:00Z" },
		"due moved":        func(r *ReviewDue) { r.DueAt = "2026-10-31T00:00:00.5Z" },
		"stated too early": func(r *ReviewDue) { r.StatedAt = "2026-10-29T23:59:59Z" },
		"other wording":    func(r *ReviewDue) { r.Statement = "the policy was reviewed" },
		"bad chain":        func(r *ReviewDue) { r.ChainID = "key-7" },
	} {
		r := reviewDueVectorRecord()
		mutate(r)
		r.ReviewDueHash = r.ComputeHash()
		if r.Validate() == nil {
			t.Errorf("%s: a bad record was accepted", name)
		}
	}
}

// Round 64, R308: a receipt context with no data use and no setup
// fingerprint encodes and hashes exactly as before; each, when present,
// joins the hash under its own label.
func TestSavedReceiptContextsEncodeAsSealed(t *testing.T) {
	for _, name := range []string{"run-3236-account-refusal-receipt.json", "builtin-refused.json"} {
		sealed := readSaved(t, name)["receipt_context"]
		dec := json.NewDecoder(bytes.NewReader(sealed))
		dec.DisallowUnknownFields()
		var c ReceiptContext
		if err := dec.Decode(&c); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		again, _ := json.Marshal(c)
		var compact bytes.Buffer
		if err := json.Compact(&compact, sealed); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, compact.Bytes()) {
			t.Fatalf("%s: context encodes as\n%s\nsealed as\n%s", name, again, compact.Bytes())
		}
		before := c.Hash()
		withUse, withSetup := c, c
		withUse.DataUse = &DataUse{Purpose: "claims.review", Basis: "contract"}
		withSetup.SetupHash = strings.Repeat("a", 64)
		if withUse.Hash() == before || withSetup.Hash() == before || withUse.Hash() == withSetup.Hash() {
			t.Fatalf("%s: data use and the setup fingerprint must each change the context's hash", name)
		}
	}
}

// Round 64, R308: the data-use copies of a record or receipt are one value.
func TestDataUseCopiesMustAgree(t *testing.T) {
	use := &DataUse{Purpose: "claims.review", Basis: "contract", Categories: []string{"claims"}}
	same := *use
	other := DataUse{Purpose: "claims.review", Basis: "consent"}
	epa := EPA{DataUse: use, PolicyGate: &PolicyGate{Inputs: &PolicyInputs{DataUse: &same}}, AccountPolicyGate: &PolicyGate{Inputs: &PolicyInputs{DataUse: &same}}}
	if err := epa.DataUseCopiesAgree(); err != nil {
		t.Fatalf("equal copies: %v", err)
	}
	epa.AccountPolicyGate.Inputs.DataUse = &other
	if epa.DataUseCopiesAgree() == nil {
		t.Fatal("differing copies must be refused")
	}
	epa.AccountPolicyGate.Inputs.DataUse = nil
	if epa.DataUseCopiesAgree() == nil {
		t.Fatal("a decision's inputs without the declaration the record carries must be refused")
	}
	gap := ReceiptContext{DataUse: use, Policy: &PolicyBinding{}}
	if err := gap.DataUseCopiesAgree(); err != nil {
		t.Fatalf("a receipt from before the rules ran carries the declaration alone: %v", err)
	}
}

// Round 64, R308: every saved record's EPA section, attested context
// included, decodes with the round 64 types and encodes to its exact bytes,
// so a record without a data use or a declared client is unchanged.
func TestSavedEPASectionsEncodeAsSealed(t *testing.T) {
	for _, name := range []string{"run-3223-key-policy.json", "run-3235-signoff-required.json", "builtin-allowed.json"} {
		sealed := readSaved(t, name)["epa"]
		dec := json.NewDecoder(bytes.NewReader(sealed))
		dec.DisallowUnknownFields()
		var epa EPA
		if err := dec.Decode(&epa); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		again, _ := json.Marshal(epa)
		var compact bytes.Buffer
		if err := json.Compact(&compact, sealed); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, compact.Bytes()) {
			t.Fatalf("%s: EPA encodes as\n%s\nsealed as\n%s", name, again, compact.Bytes())
		}
		var digest string
		if raw, ok := readSaved(t, name)["attested_digest"]; ok {
			if err := json.Unmarshal(raw, &digest); err != nil {
				t.Fatal(err)
			}
			if got := ComputeAttestedContextDigest(epa.AttestedContext); got != digest {
				t.Fatalf("%s: attested digest %s, sealed %s", name, got, digest)
			}
		}
		withUse := epa
		withUse.DataUse = &DataUse{Purpose: "claims.review", Basis: "contract"}
		if RecomputeEPAHash(withUse) == epa.Hash {
			t.Fatalf("%s: a data use must change the EPA hash", name)
		}
	}
}

// Round 64, R310: a gap receipt without an activation hashes exactly as the
// preimage released before round 64 does, and one with an activation joins
// it to the hash.
func TestAGapReceiptHashCoversItsActivation(t *testing.T) {
	r := AttestationGapReceipt{AnchorRequired: true, DecisionReasonCode: "ATTESTATION_GAP", EnvelopeID: strings.Repeat("e", 64),
		EvaluatorVersion: "pepg-0.1.0", GapClock: "2026-11-17T12:00:00Z", MissingFields: []string{"actor_id"},
		PolicyHash: strings.Repeat("p", 64), PolicyID: "acme", PolicyName: "Acme", RequiredFields: []string{"actor_id"},
		Version: "vfa.attestation_gap_receipt.v1"}
	before, beforeErr := CanonicalHash(struct {
		AnchorRequired     bool     `json:"anchor_required,omitempty"`
		DecisionReasonCode string   `json:"decision_reason_code"`
		EnvelopeID         string   `json:"envelope_id"`
		EvaluatorVersion   string   `json:"evaluator_version"`
		GapClock           string   `json:"gap_clock"`
		MissingFields      []string `json:"missing_fields"`
		PolicyHash         string   `json:"policy_hash"`
		PolicyID           string   `json:"policy_id"`
		PolicyName         string   `json:"policy_name"`
		ProfileTag         string   `json:"profile_tag,omitempty"`
		RequiredFields     []string `json:"required_fields"`
		Version            string   `json:"version"`
	}{true, r.DecisionReasonCode, r.EnvelopeID, r.EvaluatorVersion, r.GapClock, r.MissingFields, r.PolicyHash, r.PolicyID,
		r.PolicyName, "", r.RequiredFields, r.Version})
	if beforeErr != nil {
		t.Fatal(beforeErr)
	}
	plain := r
	if got, _ := BuildAttestationGapReceiptHash(&plain); got != before {
		t.Fatalf("a receipt without an activation hashes %s, before round 64 %s", got, before)
	}
	sealed := r
	sealed.ActivationHash = strings.Repeat("a", 64)
	got, _ := BuildAttestationGapReceiptHash(&sealed)
	if got == before || VerifyAttestationGapReceiptHash(&sealed) != nil {
		t.Fatal("the activation must join the receipt's hash")
	}
	sealed.ActivationHash = strings.Repeat("b", 64)
	if VerifyAttestationGapReceiptHash(&sealed) == nil {
		t.Fatal("a changed activation must fail the receipt")
	}
}

// Round 64, R307: a run-sealed record without a setup fingerprint hashes as
// before; with one, the fingerprint joins its hash, labelled. Both hashes
// were computed apart from the code.
func TestARunSealedRecordCarriesTheSetupFingerprint(t *testing.T) {
	r := RunSealed{Format: RunSealedFormat, RunID: 42, RecordHash: strings.Repeat("a", 64), SealedAt: "2026-11-17T12:00:00Z",
		Signal: SignalLink{Account: "account-7", Sequence: 5, PreviousSignalHash: strings.Repeat("d", 64)}}
	if got := r.ComputeHash(); got != "af33bc3d74ae9a316c2521f3d9c68277cbb44223d853e961c109616f174856cf" {
		t.Fatalf("without a fingerprint %s", got)
	}
	r.SetupHash = strings.Repeat("e", 64)
	if got := r.ComputeHash(); got != "5d80bbd3ae6d64e9a5dbc8e7c7beaa48076ec94f1eac657844a6efae6d2bdf36" {
		t.Fatalf("with a fingerprint %s", got)
	}
	raw, _ := json.Marshal(RunSealed{})
	if strings.Contains(string(raw), "setup_hash") {
		t.Fatalf("an unwatched record carries no setup_hash: %s", raw)
	}
	r.SetupHash, r.RunSealedHash = "E", strings.Repeat("f", 64)
	if r.Validate() == nil {
		t.Fatal("a malformed fingerprint is refused")
	}
}
