package artifacts

import (
	"errors"
	"strconv"
)

// Round 56, E5. Every successful run in an account is one numbered event in
// the account's feed, so the feed is a complete account ledger: an owner or
// auditor holding it can tell that a successful run is missing from an
// export. Refusals, halts and failures were already events; a successful
// run now is too. The event's entry is a small sealed record naming the run
// and the exact record it sealed, with its own place in the feed, anchored
// on the public log as its own entry. The run's record itself does not
// change, and an account's runs still run side by side.

const (
	// RunSealedFormat is the format field of a run-sealed record.
	RunSealedFormat = "verdifax.run-sealed.v1"
	// RunSealedKind is the leaf kind of its public-log entry.
	RunSealedKind = "run_sealed"
	// SignalRunSealed is its event kind in the account's feed.
	SignalRunSealed = "run.sealed"
)

// RunSealed is one successful run of an account: the run, the hash of the
// record it sealed, its place in a job when it has one, and when it sealed.
type RunSealed struct {
	Format     string     `json:"format"`
	RunID      int64      `json:"run_id"`
	RecordHash string     `json:"record_hash"`
	JobID      string     `json:"job_id,omitempty"`
	StepID     string     `json:"step_id,omitempty"`
	SealedAt   string     `json:"sealed_at"`
	Signal     SignalLink `json:"signal"`
	// SignOffRequired says the policy rule that allowed the run requires a
	// person's sign-off on its result (round 58, B7), so the account's feed
	// shows each such result waiting for one. Present only when true.
	SignOffRequired bool `json:"signoff_required,omitempty"`
	// SetupHash is the run's setup fingerprint (round 64, SetupHash),
	// present only when the policy in force watches the setup, so a reader
	// of the feed sees each counted run's fingerprint and every record
	// sealed without a watch hashes as it did.
	SetupHash string `json:"setup_hash,omitempty"`
	// SignOffTarget is the response target of the rule that allowed the run
	// (round 64, response times), present only when the rule's
	// signoff.within sets seal_in_result, so the feed alone shows the
	// target in force for this result; every record sealed without one
	// hashes as it did.
	SignOffTarget *SealedTarget  `json:"signoff_target,omitempty"`
	RunSealedHash string         `json:"run_sealed_hash"`
	Anchor        *ReceiptAnchor `json:"anchor,omitempty"`
}

// ComputeHash returns the record's hash: every field but the hash and the
// anchor, each length-prefixed. The sign-off requirement joins the fields
// only when true, labelled, so every record sealed before it hashes as it did.
func (r *RunSealed) ComputeHash() string {
	fields := append([]string{r.Format, strconv.FormatInt(r.RunID, 10), r.RecordHash, r.JobID, r.StepID, r.SealedAt},
		r.Signal.fields()...)
	if r.SignOffRequired {
		fields = append(fields, "signoff_required=true")
	}
	if r.SetupHash != "" {
		fields = append(fields, "setup_hash="+r.SetupHash)
	}
	if r.SignOffTarget != nil {
		fields = append(fields, r.SignOffTarget.fields("signoff_target")...)
	}
	return lengthPrefixedHash(fields)
}

// Validate checks the record's shape: every value its hash and leaf are
// built from.
func (r *RunSealed) Validate() error {
	switch {
	case r.Format != RunSealedFormat:
		return errors.New("run sealed: unknown format")
	case r.RunID <= 0:
		return errors.New("run sealed: run_id must be positive")
	case !jobHashPattern.MatchString(r.RecordHash):
		return errors.New("run sealed: record_hash must be 64 lowercase hex characters")
	case len(r.JobID) > 200 || len(r.StepID) > 200:
		return errors.New("run sealed: job_id and step_id are at most 200 bytes")
	case (r.JobID == "") != (r.StepID == ""):
		return errors.New("run sealed: a record in a job names both its job and its step")
	case r.SealedAt == "":
		return errors.New("run sealed: sealed_at is required")
	case r.SetupHash != "" && !jobHashPattern.MatchString(r.SetupHash):
		return errors.New("run sealed: setup_hash must be 64 lowercase hex characters")
	case r.SignOffTarget != nil && !r.SignOffRequired:
		return errors.New("run sealed: a sign-off target is sealed only on a result that requires a sign-off")
	case r.SignOffTarget != nil && r.SignOffTarget.Validate() != nil:
		return r.SignOffTarget.Validate()
	case !jobHashPattern.MatchString(r.RunSealedHash):
		return errors.New("run sealed: run_sealed_hash must be 64 lowercase hex characters")
	}
	return r.Signal.Validate()
}

// LeafHash is the public-log leaf that binds this record: its hash and its
// place in the account's feed.
func (r *RunSealed) LeafHash() string {
	return ComputeReceiptLeafHashV3(RunSealedKind, r.Signal.Account, r.RunSealedHash, r.Signal.Sequence, r.Signal.PreviousSignalHash)
}
