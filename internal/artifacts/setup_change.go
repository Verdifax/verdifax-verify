package artifacts

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Setup changes (round 64, design 02). When the policy in force watches a
// run's setup (watch_setup), every run it counts carries a setup fingerprint,
// setup_hash, in its feed entry, and a run whose fingerprint differs from the
// last one the watch saw in its scope is preceded in the feed by a sealed
// setup-change record: the run, its record or receipt, the two fingerprints,
// and the watched values, each under who stated it. The record states what
// was declared and what Verdifax's AI review stated; it never says which
// model ran.
const (
	// SetupChangeFormat is the format field of a setup-change record.
	SetupChangeFormat = "verdifax.setup-change.v1"
	// SetupHashForm opens the setup fingerprint's preimage.
	SetupHashForm = "verdifax.setup-hash.v1"
	// SetupRecordKindRecord names an allowed run's record as the one a
	// setup change names; a stopped run's names its receipt kind.
	SetupRecordKindRecord = "record"

	// The two parties that state setup facts.
	SetupStatedByCaller   = "declared_by_caller"
	SetupStatedByVerdifax = "attested_by_verdifax"
)

// SetupFactOrder is every setup fact by its sealed name, in the one order a
// fingerprint and a record list them (psleval.SetupFacts; a test holds the
// two in step).
var SetupFactOrder = []string{"model_provider", "model_name", "model_version", "model_temperature", "prompt_hash",
	"client_name", "client_version", "review_model", "review_prompt_id", "review_checker_id"}

// SetupFactStatedBy is who states a setup fact, or "" for a name that is not
// one.
func SetupFactStatedBy(fact string) string {
	switch fact {
	case "model_provider", "model_name", "model_version", "model_temperature", "prompt_hash", "client_name", "client_version":
		return SetupStatedByCaller
	case "review_model", "review_prompt_id", "review_checker_id":
		return SetupStatedByVerdifax
	}
	return ""
}

// Fact returns a setup fact's stated value, or "" when it was not stated.
func (s *SetupFacts) Fact(fact string) string {
	if s == nil {
		return ""
	}
	if d := s.DeclaredByCaller; d != nil {
		switch fact {
		case "model_provider":
			return d.ModelProvider
		case "model_name":
			return d.ModelName
		case "model_version":
			return d.ModelVersion
		case "model_temperature":
			return d.ModelTemperature
		case "prompt_hash":
			return d.PromptHash
		case "client_name":
			return d.ClientName
		case "client_version":
			return d.ClientVersion
		}
	}
	if a := s.AttestedByVerdifax; a != nil {
		switch fact {
		case "review_model":
			return a.ReviewModel
		case "review_prompt_id":
			return a.ReviewPromptID
		case "review_checker_id":
			return a.ReviewCheckerID
		}
	}
	return ""
}

// WatchedSetup keeps only the named facts of a setup, each under who stated
// it; a group with no stated fact is left out.
func WatchedSetup(all *SetupFacts, fields []string) SetupFacts {
	var d DeclaredSetup
	var a AttestedSetup
	for _, f := range fields {
		v := all.Fact(f)
		switch f {
		case "model_provider":
			d.ModelProvider = v
		case "model_name":
			d.ModelName = v
		case "model_version":
			d.ModelVersion = v
		case "model_temperature":
			d.ModelTemperature = v
		case "prompt_hash":
			d.PromptHash = v
		case "client_name":
			d.ClientName = v
		case "client_version":
			d.ClientVersion = v
		case "review_model":
			a.ReviewModel = v
		case "review_prompt_id":
			a.ReviewPromptID = v
		case "review_checker_id":
			a.ReviewCheckerID = v
		}
	}
	var out SetupFacts
	if d != (DeclaredSetup{}) {
		out.DeclaredByCaller = &d
	}
	if a != (AttestedSetup{}) {
		out.AttestedByVerdifax = &a
	}
	return out
}

// OrderSetupFields returns the named facts in SetupFactOrder, or an error
// for a name that is not a setup fact or is named twice.
func OrderSetupFields(fields []string) ([]string, error) {
	named := map[string]bool{}
	for _, f := range fields {
		if SetupFactStatedBy(f) == "" || named[f] {
			return nil, errors.New("setup watch: fields must be distinct setup facts")
		}
		named[f] = true
	}
	if len(named) == 0 {
		return nil, errors.New("setup watch: no fields")
	}
	out := make([]string, 0, len(named))
	for _, f := range SetupFactOrder {
		if named[f] {
			out = append(out, f)
		}
	}
	return out, nil
}

// SetupHash is the setup fingerprint of the watched facts: each fact in
// SetupFactOrder, who states it and its value (empty when not stated),
// length-prefixed after the form. fields must already be in that order.
func SetupHash(fields []string, setup *SetupFacts) string {
	parts := []string{SetupHashForm}
	for _, f := range fields {
		parts = append(parts, f, SetupFactStatedBy(f), setup.Fact(f))
	}
	return lengthPrefixedHash(parts)
}

// SetupChange is one setup change seen by a policy's setup watch.
type SetupChange struct {
	Format string `json:"format"`
	RunID  int64  `json:"run_id"`
	// RecordKind is "record" for an allowed run, or the kind of a stopped
	// run's receipt; RecordHash is that record's or receipt's hash.
	RecordKind string `json:"record_kind"`
	RecordHash string `json:"record_hash"`
	// Scope is the watch's scope: "account", or "key-N" for one key.
	Scope string `json:"scope"`
	// ActivationHash is the change record of the watching policy in force.
	ActivationHash string `json:"activation_hash"`
	// Fields are the watched facts, in SetupFactOrder.
	Fields []string `json:"fields"`
	// PreviousSetupHash is the fingerprint the watch saw last in this scope,
	// empty for the first setup it saw.
	PreviousSetupHash string `json:"previous_setup_hash"`
	SetupHash         string `json:"setup_hash"`
	// Setup holds the watched values as stated: declared_by_caller, the
	// caller's own declaration, and attested_by_verdifax, what Verdifax's AI
	// review stated about itself. Neither is confirmed by the other.
	Setup           SetupFacts     `json:"setup"`
	ChangedAt       string         `json:"changed_at"`
	Signal          SignalLink     `json:"signal"`
	SetupChangeHash string         `json:"setup_change_hash"`
	Anchor          *ReceiptAnchor `json:"anchor,omitempty"`
}

// ComputeHash returns the record's hash: every field but the hash and the
// anchor, each length-prefixed, the watched values in field order.
func (c *SetupChange) ComputeHash() string {
	fields := []string{c.Format, strconv.FormatInt(c.RunID, 10), c.RecordKind, c.RecordHash, c.Scope, c.ActivationHash,
		"fields", strings.Join(c.Fields, ","), c.PreviousSetupHash, c.SetupHash}
	for _, f := range c.Fields {
		fields = append(fields, f, SetupFactStatedBy(f), c.Setup.Fact(f))
	}
	fields = append(append(fields, c.ChangedAt), c.Signal.fields()...)
	return lengthPrefixedHash(fields)
}

var setupScopePattern = regexp.MustCompile(`^(account|key-[1-9][0-9]{0,18})$`)

// Validate checks the record's shape: every value its hash and leaf are built
// from, a fingerprint that recomputes from the stated values, and no stated
// value outside the watched fields.
func (c *SetupChange) Validate() error {
	ordered, orderErr := OrderSetupFields(c.Fields)
	switch {
	case c.Format != SetupChangeFormat:
		return errors.New("setup change: unknown format")
	case c.RunID <= 0:
		return errors.New("setup change: run_id must be positive")
	case c.RecordKind != SetupRecordKindRecord && !oneOf(c.RecordKind, ReceiptKinds):
		return errors.New("setup change: record_kind must be record or a receipt kind")
	case !jobHashPattern.MatchString(c.RecordHash):
		return errors.New("setup change: record_hash must be 64 lowercase hex characters")
	case !setupScopePattern.MatchString(c.Scope):
		return errors.New("setup change: scope must be account or key-N")
	case !jobHashPattern.MatchString(c.ActivationHash):
		return errors.New("setup change: activation_hash must be 64 lowercase hex characters")
	case orderErr != nil || strings.Join(ordered, ",") != strings.Join(c.Fields, ","):
		return errors.New("setup change: fields must be distinct setup facts in their fixed order")
	case c.PreviousSetupHash != "" && !jobHashPattern.MatchString(c.PreviousSetupHash):
		return errors.New("setup change: previous_setup_hash must be empty or 64 lowercase hex characters")
	case c.PreviousSetupHash == c.SetupHash:
		return errors.New("setup change: the setup did not change")
	case c.SetupHash != SetupHash(c.Fields, &c.Setup):
		return errors.New("setup change: setup_hash does not recompute from the stated values")
	case !sameSetup(WatchedSetup(&c.Setup, c.Fields), c.Setup):
		return errors.New("setup change: a stated value is outside the watched fields, or a group is empty")
	case c.ChangedAt == "":
		return errors.New("setup change: changed_at is required")
	case !jobHashPattern.MatchString(c.SetupChangeHash):
		return errors.New("setup change: setup_change_hash must be 64 lowercase hex characters")
	}
	return c.Signal.Validate()
}

// sameSetup reports whether two setups hold the same groups with the same
// values; an empty group is never the same as an absent one, so a record
// cannot carry one.
func sameSetup(a, b SetupFacts) bool {
	sameDeclared := (a.DeclaredByCaller == nil) == (b.DeclaredByCaller == nil) &&
		(a.DeclaredByCaller == nil || *a.DeclaredByCaller == *b.DeclaredByCaller)
	sameAttested := (a.AttestedByVerdifax == nil) == (b.AttestedByVerdifax == nil) &&
		(a.AttestedByVerdifax == nil || *a.AttestedByVerdifax == *b.AttestedByVerdifax)
	return sameDeclared && sameAttested
}

// LeafHash is the public-log leaf that binds this record: its hash and its
// place in the account's feed.
func (c *SetupChange) LeafHash() string {
	return ComputeReceiptLeafHashV3(SetupChangeKind, c.Signal.Account, c.SetupChangeHash, c.Signal.Sequence, c.Signal.PreviousSignalHash)
}
