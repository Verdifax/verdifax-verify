package artifacts

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// Policy review dates (round 64, design 02). A customer's policy may declare
// a review date: a fixed time (review_by) or a number of days from each
// activation (interval_days). When that date passes while the activation is
// still the one in force, Verdifax seals one review-due record for it in the
// account's feed. The record states only that the date the policy declared
// has passed; it says nothing about whether anyone reviewed the policy.
const (
	// ReviewDueFormat is the format field of a review-due record.
	ReviewDueFormat = "verdifax.policy-review-due.v1"
	// ReviewDueStatementForm is the record's one sentence, with the
	// activation's sequence on its chain.
	ReviewDueStatementForm = "the date this policy declared has passed while activation %d was in force"
)

// ReviewDueStatement is the sentence a review-due record seals.
func ReviewDueStatement(activationSequence int64) string {
	return fmt.Sprintf(ReviewDueStatementForm, activationSequence)
}

// ReviewDueAt is the due time an activation's review declaration gives, in
// UTC with RFC 3339 and nanoseconds: review_by itself, or activated_at plus
// interval_days whole days. Exactly one of reviewBy and intervalDays is set.
func ReviewDueAt(reviewBy string, intervalDays int, activatedAt string) (string, error) {
	switch {
	case reviewBy != "" && intervalDays == 0:
		by, parseErr := time.Parse(time.RFC3339, reviewBy)
		if parseErr != nil {
			return "", fmt.Errorf("review due: review_by %q is not an RFC 3339 time", reviewBy)
		}
		return by.UTC().Format(time.RFC3339Nano), nil
	case reviewBy == "" && intervalDays > 0:
		at, parseErr := time.Parse(time.RFC3339Nano, activatedAt)
		if parseErr != nil {
			return "", fmt.Errorf("review due: activated_at %q is not an RFC 3339 time", activatedAt)
		}
		return at.UTC().Add(time.Duration(intervalDays) * 24 * time.Hour).Format(time.RFC3339Nano), nil
	}
	return "", errors.New("review due: set exactly one of review_by and interval_days")
}

// ReviewDue is the record of one activation's declared review date passing.
type ReviewDue struct {
	Format string `json:"format"`
	// ChainID, ActivationSequence, ActivationHash, DocumentHash and
	// ActivatedAt name the activation, as its policy.changed record does.
	ChainID            string `json:"chain_id"`
	ActivationSequence int64  `json:"activation_sequence"`
	ActivationHash     string `json:"activation_hash"`
	DocumentHash       string `json:"document_hash"`
	ActivatedAt        string `json:"activated_at"`
	// ReviewBy or IntervalDays is the declaration, exactly as the policy
	// states it; DueAt is the time it gives (ReviewDueAt).
	ReviewBy     string `json:"review_by,omitempty"`
	IntervalDays int    `json:"interval_days,omitempty"`
	DueAt        string `json:"due_at"`
	// Statement is ReviewDueStatement for the activation's sequence.
	Statement     string         `json:"statement"`
	StatedAt      string         `json:"stated_at"`
	Signal        SignalLink     `json:"signal"`
	ReviewDueHash string         `json:"review_due_hash"`
	Anchor        *ReceiptAnchor `json:"anchor,omitempty"`
}

// ComputeHash returns the record's hash: every field but the hash and the
// anchor, each length-prefixed.
func (r *ReviewDue) ComputeHash() string {
	fields := []string{r.Format, r.ChainID, strconv.FormatInt(r.ActivationSequence, 10), r.ActivationHash, r.DocumentHash,
		r.ActivatedAt, r.ReviewBy, strconv.Itoa(r.IntervalDays), r.DueAt, r.Statement, r.StatedAt}
	return lengthPrefixedHash(append(fields, r.Signal.fields()...))
}

var reviewChainPattern = regexp.MustCompile(`^(api-key|account)-[1-9][0-9]{0,18}$`)

// Validate checks the record's shape: every value its hash and leaf are built
// from, a due time that recomputes from the declaration, the fixed sentence,
// and a statement made no earlier than the due time.
func (r *ReviewDue) Validate() error {
	due, dueErr := ReviewDueAt(r.ReviewBy, r.IntervalDays, r.ActivatedAt)
	dueAt, _ := time.Parse(time.RFC3339Nano, r.DueAt)
	stated, statedErr := time.Parse(time.RFC3339Nano, r.StatedAt)
	switch {
	case r.Format != ReviewDueFormat:
		return errors.New("review due: unknown format")
	case !reviewChainPattern.MatchString(r.ChainID):
		return errors.New("review due: chain_id must be api-key-N or account-N")
	case r.ActivationSequence <= 0:
		return errors.New("review due: activation_sequence must be positive")
	case !jobHashPattern.MatchString(r.ActivationHash) || !jobHashPattern.MatchString(r.DocumentHash):
		return errors.New("review due: activation_hash and document_hash must be 64 lowercase hex characters")
	case dueErr != nil:
		return dueErr
	case r.DueAt != due:
		return errors.New("review due: due_at does not recompute from the declaration")
	case r.Statement != ReviewDueStatement(r.ActivationSequence):
		return errors.New("review due: the statement is not the fixed sentence")
	case statedErr != nil || stated.Before(dueAt):
		return errors.New("review due: stated_at must be a time no earlier than due_at")
	case !jobHashPattern.MatchString(r.ReviewDueHash):
		return errors.New("review due: review_due_hash must be 64 lowercase hex characters")
	}
	return r.Signal.Validate()
}

// LeafHash is the public-log leaf that binds this record: its hash and its
// place in the account's feed.
func (r *ReviewDue) LeafHash() string {
	return ComputeReceiptLeafHashV3(ReviewDueKind, r.Signal.Account, r.ReviewDueHash, r.Signal.Sequence, r.Signal.PreviousSignalHash)
}
