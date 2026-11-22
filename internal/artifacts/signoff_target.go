package artifacts

import (
	"errors"
	"strconv"
	"time"
)

// Response targets (round 64, design 04). A customer's policy may declare a
// target for how long a result waits for a sign-off: signoff.within on the
// rule that allows a run (its run.sealed result), or response_targets.refusals
// and response_targets.stops for refused and halted runs (their receipts).
// The target names which sign-off is compared with it (compare) and how a
// passed target is shown (notice). With seal_in_result the target is also
// sealed into each result's own feed entry, so the figure is provable from
// the feed alone, against the target in force for that result.
//
// When the notice is event or both, a target that passes with no sign-off of
// the kind it compares is stated once in the feed, signoff.target_passed, as a
// verdifax.signoff-target-passed.v1 record under leaf kind signoff_target.
// The record states a time and the customer's own target, judges neither,
// and says nothing about the result or the decision.
const (
	// SignOffTargetPassedFormat is the format field of a target-passed
	// record.
	SignOffTargetPassedFormat = "verdifax.signoff-target-passed.v1"
	// SignOffTargetStatement is the record's one sentence.
	SignOffTargetStatement = "no sign-off of the kind this target compares was on the public log by the deadline"

	// The results a target applies to: an allowed run's record (its
	// run.sealed entry), or a refused or halted run's receipt.
	TargetResultRecord  = "record"
	TargetResultReceipt = "receipt"

	// Where the target came from: a rule's signoff.within, or the policy's
	// response_targets for refusals or for stops (halted runs).
	TargetSourceSignOff  = "signoff.within"
	TargetSourceRefusals = "response_targets.refusals"
	TargetSourceStops    = "response_targets.stops"

	// The start a deadline is counted from: the result entry's public-log
	// time, or, for a result whose entry has none, its sealed record time.
	TargetStartPublicLog  = "public_log"
	TargetStartRecordTime = "record_time"

	// The sign-off a target compares, and how a passed target is shown
	// (the same values as the policy's).
	TargetCompareFirstSignOff    = "first_signoff"
	TargetCompareFirstApproval   = "first_approval"
	TargetCompareDecisionInForce = "decision_in_force"
	TargetNoticeEvent            = "event"
	TargetNoticeHead             = "head"
	TargetNoticeBoth             = "both"

	// MaxTargetSeconds is the longest target a policy may declare.
	MaxTargetSeconds = 366 * 24 * 3600
)

// SealedTarget is a response target as sealed into a result's entry: the
// run.sealed record's signoff_target, or a receipt context's
// response_target. It joins its record's hash under its own label only when
// present, so every result sealed without one hashes as before.
type SealedTarget struct {
	Within  int64  `json:"within"`
	Compare string `json:"compare"`
	Notice  string `json:"notice"`
}

// fields are the target's values as they join a hash, after a label.
func (t *SealedTarget) fields(label string) []string {
	return []string{label, strconv.FormatInt(t.Within, 10), t.Compare, t.Notice}
}

// Validate checks the target's shape.
func (t *SealedTarget) Validate() error {
	switch {
	case t.Within < 1 || t.Within > MaxTargetSeconds:
		return errors.New("response target: within must be from 1 second to 366 days")
	case !targetCompare(t.Compare):
		return errors.New("response target: compare must be first_signoff, first_approval or decision_in_force")
	case !targetNotice(t.Notice):
		return errors.New("response target: notice must be event, head or both")
	}
	return nil
}

func targetCompare(v string) bool {
	return v == TargetCompareFirstSignOff || v == TargetCompareFirstApproval || v == TargetCompareDecisionInForce
}

func targetNotice(v string) bool {
	return v == TargetNoticeEvent || v == TargetNoticeHead || v == TargetNoticeBoth
}

// SignOffTargetPassed is the record of one result's response target passing
// with no sign-off of the kind it compares on the public log by its deadline.
type SignOffTargetPassed struct {
	Format string `json:"format"`
	// ResultKind is record or receipt; RunID the run; ResultSequence the
	// feed place of the result's own event and ResultHash that event's
	// entry hash (the run.sealed record's hash, or the receipt's hash).
	ResultKind     string `json:"result_kind"`
	RunID          int64  `json:"run_id"`
	ResultSequence int64  `json:"result_sequence"`
	ResultHash     string `json:"result_hash"`
	// Source names the policy field the target came from; Within, Compare
	// and Notice are the target.
	Source  string `json:"source"`
	Within  int64  `json:"within"`
	Compare string `json:"compare"`
	Notice  string `json:"notice"`
	// StartBasis is public_log when Start is the result entry's public-log
	// time (whole seconds, UTC), or record_time when the entry has none and
	// Start is its sealed record time. Deadline is Start plus Within.
	StartBasis string `json:"start_basis"`
	Start      string `json:"start"`
	Deadline   string `json:"deadline"`
	// Statement is SignOffTargetStatement.
	Statement        string         `json:"statement"`
	StatedAt         string         `json:"stated_at"`
	Signal           SignalLink     `json:"signal"`
	TargetPassedHash string         `json:"target_passed_hash"`
	Anchor           *ReceiptAnchor `json:"anchor,omitempty"`
}

// TargetDeadline is a start plus a target, in UTC with RFC 3339 and
// nanoseconds.
func TargetDeadline(start string, within int64) (string, error) {
	at, parseErr := time.Parse(time.RFC3339Nano, start)
	if parseErr != nil {
		return "", errors.New("response target: start is not an RFC 3339 time")
	}
	return at.UTC().Add(time.Duration(within) * time.Second).Format(time.RFC3339Nano), nil
}

// ComputeHash returns the record's hash: every field but the hash and the
// anchor, each length-prefixed.
func (r *SignOffTargetPassed) ComputeHash() string {
	fields := []string{r.Format, r.ResultKind, strconv.FormatInt(r.RunID, 10), strconv.FormatInt(r.ResultSequence, 10), r.ResultHash,
		r.Source, strconv.FormatInt(r.Within, 10), r.Compare, r.Notice, r.StartBasis, r.Start, r.Deadline, r.Statement, r.StatedAt}
	return lengthPrefixedHash(append(fields, r.Signal.fields()...))
}

// Validate checks the record's shape: every value its hash and leaf are built
// from, a deadline that recomputes from its start and target, the fixed
// sentence, a statement made no earlier than the deadline, and a result
// placed before the record in the same feed.
func (r *SignOffTargetPassed) Validate() error {
	deadline, deadlineErr := TargetDeadline(r.Start, r.Within)
	at, _ := time.Parse(time.RFC3339Nano, r.Deadline)
	stated, statedErr := time.Parse(time.RFC3339Nano, r.StatedAt)
	target := SealedTarget{Within: r.Within, Compare: r.Compare, Notice: r.Notice}
	switch {
	case r.Format != SignOffTargetPassedFormat:
		return errors.New("target passed: unknown format")
	case r.ResultKind != TargetResultRecord && r.ResultKind != TargetResultReceipt:
		return errors.New("target passed: result_kind must be record or receipt")
	case r.RunID <= 0:
		return errors.New("target passed: run_id must be positive")
	case r.ResultSequence <= 0 || r.ResultSequence >= r.Signal.Sequence:
		return errors.New("target passed: result_sequence must name an earlier place in the feed")
	case !jobHashPattern.MatchString(r.ResultHash):
		return errors.New("target passed: result_hash must be 64 lowercase hex characters")
	case r.Source != TargetSourceSignOff && r.Source != TargetSourceRefusals && r.Source != TargetSourceStops:
		return errors.New("target passed: source must be signoff.within, response_targets.refusals or response_targets.stops")
	case (r.Source == TargetSourceSignOff) != (r.ResultKind == TargetResultRecord):
		return errors.New("target passed: a record's target is its rule's signoff.within, and only a record's is")
	case target.Validate() != nil:
		return target.Validate()
	case r.Notice == TargetNoticeHead:
		return errors.New("target passed: a target whose notice is head is shown by the feed head only, never by a record")
	case r.StartBasis != TargetStartPublicLog && r.StartBasis != TargetStartRecordTime:
		return errors.New("target passed: start_basis must be public_log or record_time")
	case deadlineErr != nil:
		return deadlineErr
	case r.Deadline != deadline:
		return errors.New("target passed: deadline does not recompute from start and within")
	case r.Statement != SignOffTargetStatement:
		return errors.New("target passed: the statement is not the fixed sentence")
	case statedErr != nil || stated.Before(at):
		return errors.New("target passed: stated_at must be a time no earlier than the deadline")
	case !jobHashPattern.MatchString(r.TargetPassedHash):
		return errors.New("target passed: target_passed_hash must be 64 lowercase hex characters")
	}
	return r.Signal.Validate()
}

// LeafHash is the public-log leaf that binds this record: its hash and its
// place in the account's feed.
func (r *SignOffTargetPassed) LeafHash() string {
	return ComputeReceiptLeafHashV3(SignOffTargetKind, r.Signal.Account, r.TargetPassedHash, r.Signal.Sequence, r.Signal.PreviousSignalHash)
}
