package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The signal feed. Every control signal in an account (a refused, halted or
// failed run, a policy change, a sign-off, an approver or key change) is one
// event, numbered 1, 2, 3 within the account, each naming the previous event's
// hash. The number and the link are sealed inside the event's own entry before
// that entry is anchored on the public log, so the one entry fixes both what
// happened and its place in the feed: a removed, reordered or rewritten event
// breaks the links.
//
// The feed shows every signal Verdifax recorded for the account, in the order
// it recorded them. It cannot show a signal Verdifax never recorded.
const (
	// SignalFormat is the form of the Verdifax event inside each CloudEvent.
	SignalFormat = "verdifax.signal.v1"
	// NoPreviousSignal is the previous hash of an account's first event.
	NoPreviousSignal = "0000000000000000000000000000000000000000000000000000000000000000"

	// The event kinds. Each is also a CloudEvents type, prefixed
	// SignalTypePrefix.
	SignalRunRefused         = "run.refused"
	SignalRunHalted          = "run.halted"
	SignalRunFailed          = "run.failed"
	SignalPolicyChanged      = "policy.changed"
	SignalSignOffRecorded    = "signoff.recorded"
	SignalApproverRegistered = "approver.registered"
	SignalApproverRevoked    = "approver.revoked"
	SignalKeyCreated         = "key.created"
	SignalKeyRevoked         = "key.revoked"
	// SignalRunPublished and SignalRunUnpublished: the account's owner made
	// one of the account's records public, or withdrew it.
	SignalRunPublished   = "run.published"
	SignalRunUnpublished = "run.unpublished"

	// SignalTypePrefix opens every CloudEvents type the feed emits.
	SignalTypePrefix = "com.verdifax."
)

// SignalKinds lists every event kind, in a fixed order.
var SignalKinds = []string{SignalRunRefused, SignalRunHalted, SignalRunFailed, SignalPolicyChanged,
	SignalSignOffRecorded, SignalApproverRegistered, SignalApproverRevoked, SignalKeyCreated, SignalKeyRevoked,
	SignalRunPublished, SignalRunUnpublished, SignalChainGap, SignalRunSealed}

// IsSignalKind reports a kind the feed emits.
func IsSignalKind(kind string) bool {
	for _, k := range SignalKinds {
		if k == kind {
			return true
		}
	}
	return false
}

var signalAccount = regexp.MustCompile(`^account-[1-9][0-9]{0,18}$`)

// SignalLink is an event's place in its account's feed, sealed inside the
// event's own entry.
type SignalLink struct {
	Account            string `json:"signal_account"`
	Sequence           int64  `json:"signal_sequence"`
	PreviousSignalHash string `json:"signal_previous_hash"`
}

// Validate checks the link's shape.
func (l *SignalLink) Validate() error {
	switch {
	case l == nil:
		return errors.New("signal: no link")
	case !signalAccount.MatchString(l.Account):
		return errors.New("signal: signal_account must be an account, account-N")
	case l.Sequence <= 0:
		return errors.New("signal: signal_sequence must be positive")
	case !jobHashPattern.MatchString(l.PreviousSignalHash):
		return errors.New("signal: signal_previous_hash must be 64 lowercase hex characters")
	case (l.Sequence == 1) != (l.PreviousSignalHash == NoPreviousSignal):
		return errors.New("signal: only the first event follows no event, and the first event follows none")
	}
	return nil
}

// fields are the link's values as they join a record's hash, after a label.
func (l *SignalLink) fields() []string {
	return []string{"signal", l.Account, strconv.FormatInt(l.Sequence, 10), l.PreviousSignalHash}
}

// SignalEventHash is the hash the next event in the feed names: the kind, the
// hash of the event's own entry, and its place.
func SignalEventHash(kind, entryHash string, link SignalLink) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{SignalFormat, kind, entryHash, link.Account,
		strconv.FormatInt(link.Sequence, 10), link.PreviousSignalHash}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// Key changes. An approver key registered or revoked, or a member or feed key
// created or revoked, is one record, anchored on the public log as its own
// entry and carrying its place in the account's feed.
const (
	// KeyChangeFormat is the format field of a key-change record.
	KeyChangeFormat = "verdifax.key-change.v1"
	// KeyChangeKind is the leaf kind of its public-log entry.
	KeyChangeKind = "key_change"

	// KeyScopeRun, KeyScopeSignals and KeyScopeApprover name what the key is.
	KeyScopeRun      = "run"
	KeyScopeSignals  = "signals"
	KeyScopeApprover = "approver"
)

// KeyChange is one key added to or removed from an account.
type KeyChange struct {
	Format        string         `json:"format"`
	Action        string         `json:"action"`
	KeyID         int64          `json:"key_id"`
	KeyScope      string         `json:"key_scope"`
	PublicKey     string         `json:"public_key,omitempty"`
	Name          string         `json:"name"`
	ChangedAt     string         `json:"changed_at"`
	Signal        SignalLink     `json:"signal"`
	KeyChangeHash string         `json:"key_change_hash"`
	Anchor        *ReceiptAnchor `json:"anchor,omitempty"`
}

// ComputeHash returns the record's hash: every field but the hash and the
// anchor, each length-prefixed.
func (k *KeyChange) ComputeHash() string {
	fields := append([]string{k.Format, k.Action, strconv.FormatInt(k.KeyID, 10), k.KeyScope, k.PublicKey,
		k.Name, k.ChangedAt}, k.Signal.fields()...)
	return lengthPrefixedHash(fields)
}

// Validate checks the record's shape: every value its hash and leaf are built
// from.
func (k *KeyChange) Validate() error {
	switch {
	case k.Format != KeyChangeFormat:
		return errors.New("key change: unknown format")
	case k.Action != SignalApproverRegistered && k.Action != SignalApproverRevoked &&
		k.Action != SignalKeyCreated && k.Action != SignalKeyRevoked:
		return errors.New("key change: action must be approver.registered, approver.revoked, key.created or key.revoked")
	case k.KeyID <= 0:
		return errors.New("key change: key_id must be positive")
	case (k.KeyScope == KeyScopeApprover) != (k.Action == SignalApproverRegistered || k.Action == SignalApproverRevoked):
		return errors.New("key change: an approver action names an approver key, and only an approver action does")
	case k.KeyScope != KeyScopeRun && k.KeyScope != KeyScopeSignals && k.KeyScope != KeyScopeApprover:
		return errors.New("key change: key_scope must be run, signals or approver")
	case (k.KeyScope == KeyScopeApprover) != (k.PublicKey != ""):
		return errors.New("key change: an approver key names its public key, and only an approver key does")
	case k.PublicKey != "" && !validBase64Len(k.PublicKey, 32):
		return errors.New("key change: public_key must be a base64 Ed25519 key")
	case len(k.Name) > 200:
		return errors.New("key change: name is longer than 200 bytes")
	case !jobHashPattern.MatchString(k.KeyChangeHash):
		return errors.New("key change: key_change_hash must be 64 lowercase hex characters")
	}
	return k.Signal.Validate()
}

// LeafHash is the public-log leaf that binds this record: its hash and its
// place in the account's feed.
func (k *KeyChange) LeafHash() string {
	return ComputeReceiptLeafHashV3(KeyChangeKind, k.Signal.Account, k.KeyChangeHash, k.Signal.Sequence, k.Signal.PreviousSignalHash)
}

// A run publication is the account owner's decision to make one of the
// account's sealed records public on its random link, or to withdraw it.
// Each is one record, anchored on the public log as its own entry and
// carrying its place in the account's feed, so an auditor sees who made what
// public and when. Only the account's owner key can make the decision; the
// service's admin key publishes only records it made itself.
const (
	// RunPublicationFormat is the format field of a run-publication record:
	// v2 seals who decided, the account's owner or a Verdifax admin key.
	RunPublicationFormat = "verdifax.run-publication.v2"
	// RunPublicationFormatV1 is the first format, sealed before v2: every v1
	// publication was the owner's decision, and v1 seals no decided_by.
	RunPublicationFormatV1 = "verdifax.run-publication.v1"
	// PublicationByOwner and PublicationByVerdifax name who decided: the
	// account's owner key, or a Verdifax admin key, which withdraws any
	// public record and publishes only records it made itself (R160).
	PublicationByOwner    = "owner"
	PublicationByVerdifax = "verdifax_admin"
	// RunPublicationKind is the leaf kind of its public-log entry.
	RunPublicationKind = "run_publication"
)

// RunPublication is one record made public or withdrawn: by the account's
// owner, or withdrawn by a Verdifax admin key.
type RunPublication struct {
	Format string `json:"format"`
	// Action is run.published or run.unpublished.
	Action string `json:"action"`
	// DecidedBy is who decided, owner or verdifax_admin; sealed in v2 and
	// absent from v1, whose every record was the owner's.
	DecidedBy string `json:"decided_by,omitempty"`
	RunID     int64  `json:"run_id"`
	// RecordHash is the record's own hash (its manifest hash), so the
	// publication binds the exact record, not only its number.
	RecordHash string `json:"record_hash"`
	// JobID and StepID name the record's place in a job, when it has one.
	JobID           string         `json:"job_id,omitempty"`
	StepID          string         `json:"step_id,omitempty"`
	ChangedAt       string         `json:"changed_at"`
	Signal          SignalLink     `json:"signal"`
	PublicationHash string         `json:"publication_hash"`
	Anchor          *ReceiptAnchor `json:"anchor,omitempty"`
}

// ComputeHash returns the record's hash: every field but the hash and the
// anchor, each length-prefixed.
func (p *RunPublication) ComputeHash() string {
	head := []string{p.Format, p.Action}
	if p.Format != RunPublicationFormatV1 {
		head = append(head, p.DecidedBy)
	}
	fields := append(append(head, strconv.FormatInt(p.RunID, 10), p.RecordHash, p.JobID, p.StepID,
		p.ChangedAt), p.Signal.fields()...)
	return lengthPrefixedHash(fields)
}

// Decider is who made the decision: the sealed decided_by, or the owner for a
// v1 record, which could only be the owner's.
func (p *RunPublication) Decider() string {
	if p.Format == RunPublicationFormatV1 {
		return PublicationByOwner
	}
	return p.DecidedBy
}

// Validate checks the record's shape: every value its hash and leaf are built
// from.
func (p *RunPublication) Validate() error {
	switch {
	case p.Format != RunPublicationFormat && p.Format != RunPublicationFormatV1:
		return errors.New("run publication: unknown format")
	case p.Format == RunPublicationFormatV1 && p.DecidedBy != "":
		return errors.New("run publication: a v1 publication seals no decided_by")
	case p.Format == RunPublicationFormat && p.DecidedBy != PublicationByOwner && p.DecidedBy != PublicationByVerdifax:
		return errors.New("run publication: decided_by must be owner or verdifax_admin")
	case p.Action != SignalRunPublished && p.Action != SignalRunUnpublished:
		return errors.New("run publication: action must be run.published or run.unpublished")
	case p.RunID <= 0:
		return errors.New("run publication: run_id must be positive")
	case !jobHashPattern.MatchString(p.RecordHash):
		return errors.New("run publication: record_hash must be 64 lowercase hex characters")
	case len(p.JobID) > 200 || len(p.StepID) > 200:
		return errors.New("run publication: job_id and step_id are at most 200 bytes")
	case (p.JobID == "") != (p.StepID == ""):
		return errors.New("run publication: a record in a job names both its job and its step")
	case p.ChangedAt == "":
		return errors.New("run publication: changed_at is required")
	case !jobHashPattern.MatchString(p.PublicationHash):
		return errors.New("run publication: publication_hash must be 64 lowercase hex characters")
	}
	return p.Signal.Validate()
}

// LeafHash is the public-log leaf that binds this record: its hash and its
// place in the account's feed.
func (p *RunPublication) LeafHash() string {
	return ComputeReceiptLeafHashV3(RunPublicationKind, p.Signal.Account, p.PublicationHash, p.Signal.Sequence, p.Signal.PreviousSignalHash)
}

// lengthPrefixedHash digests fields so that none can run into the next.
func lengthPrefixedHash(fields []string) string {
	digest := sha256.New()
	for _, f := range fields {
		digest.Write([]byte(strconv.Itoa(len(f)) + ":" + f))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// Failure receipts. A run that fails with a server error seals a failure
// receipt naming the request and the stage that failed, anchored like every
// other receipt, so every request Verdifax accepts leaves a sealed outcome.
const (
	// FailureReceiptVersion is the version field of a failure receipt.
	FailureReceiptVersion = "vfa.failure_receipt.v1"

	// The error classes. The raw error text never enters the receipt: it can
	// carry internal detail, and the class is what a reader acts on.
	FailureInternal   = "internal_error"
	FailureTimeout    = "timeout"
	FailureDependency = "dependency_unavailable"
)

// FailureReceipt is the sealed outcome of a run that failed with a server
// error. Field order is lexicographic, as in every receipt.
type FailureReceipt struct {
	AnchorRequired   bool   `json:"anchor_required,omitempty"`
	EnvelopeID       string `json:"envelope_id"`
	ErrorClass       string `json:"error_class"`
	EvaluatorVersion string `json:"evaluator_version"`
	FailClock        string `json:"fail_clock"`
	FailedStage      string `json:"failed_stage"`
	Version          string `json:"version"`
	Hash             string `json:"hash,omitempty"`
}

var failureStage = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)

// BuildFailureReceiptHash computes the receipt's canonical hash and fills
// its Hash field.
func BuildFailureReceiptHash(r *FailureReceipt) (string, error) {
	if r == nil {
		return "", errors.New("artifacts: nil FailureReceipt")
	}
	switch {
	case r.Version != FailureReceiptVersion:
		return "", errors.New("artifacts: failure receipt has an unknown version")
	case r.ErrorClass != FailureInternal && r.ErrorClass != FailureTimeout && r.ErrorClass != FailureDependency:
		return "", errors.New("artifacts: failure receipt error_class must be internal_error, timeout or dependency_unavailable")
	case !failureStage.MatchString(r.FailedStage):
		return "", errors.New("artifacts: failure receipt failed_stage must be 1 to 40 lowercase letters, digits or underscores")
	}
	preimage := struct {
		AnchorRequired   bool   `json:"anchor_required,omitempty"`
		EnvelopeID       string `json:"envelope_id"`
		ErrorClass       string `json:"error_class"`
		EvaluatorVersion string `json:"evaluator_version"`
		FailClock        string `json:"fail_clock"`
		FailedStage      string `json:"failed_stage"`
		Version          string `json:"version"`
	}{r.AnchorRequired, r.EnvelopeID, r.ErrorClass, r.EvaluatorVersion, r.FailClock, r.FailedStage, r.Version}
	hash, hashErr := CanonicalHash(preimage)
	if hashErr != nil {
		return "", fmt.Errorf("artifacts: failure receipt hash: %w", hashErr)
	}
	r.Hash = hash
	return hash, nil
}

// ErrFailureReceiptHashMismatch is returned when a failure receipt's stored
// hash does not recompute from its fields.
var ErrFailureReceiptHashMismatch = errors.New("artifacts: failure receipt hash mismatch")

// VerifyFailureReceiptHash recomputes the receipt's hash and compares it to
// the stored one.
func VerifyFailureReceiptHash(r *FailureReceipt) error {
	if r == nil {
		return errors.New("artifacts: nil FailureReceipt")
	}
	expected := r.Hash
	r.Hash = ""
	defer func() { r.Hash = expected }()
	actual, buildErr := BuildFailureReceiptHash(r)
	if buildErr != nil {
		return fmt.Errorf("artifacts: recompute failure receipt: %w", buildErr)
	}
	if actual != expected {
		return ErrFailureReceiptHashMismatch
	}
	return nil
}
