// Package feedcount counts an account's signal feed: the figures of a period
// summary (verdifax.period-summary.v1) and the response-time report
// (verdifax.response-times.v1). It reads only the feed's served events, the
// same JSON a verifier holds, and uses the standard library only, so
// verdifax-verify copies this package byte for byte (as it copies psleval,
// R163) and recounts every figure and every event list the server states.
//
// Verdifax counts sealed facts and judges none of them: no figure says a
// result was right, a sign-off careful, or a time too long. A time is stated
// as measured, with the customer's own target beside it when one applies.
package feedcount

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// The forms this package states.
const (
	// CountingRules names these counting rules. A change to what any figure
	// counts is a new name. v2 (round 64, N32, R376) adds, for the owner's
	// stops, the signed and unsigned figures: account.stops.by:owner.signed
	// and .unsigned, and the same for account.stopped_seconds. An unsigned
	// owner stop is the server's word that the owner's key asked for it.
	CountingRules = "verdifax.period-summary-counting.v2"
	// CountingRulesV1 are the rules every summary stated before v2 was
	// counted by; a verifier recounts such a summary by them.
	CountingRulesV1 = "verdifax.period-summary-counting.v1"
	// ResponseTimesForm is the form of the response-time report.
	ResponseTimesForm = "verdifax.response-times.v1"
)

// The feed kinds this package reads.
const (
	kindRunRefused         = "run.refused"
	kindRunHalted          = "run.halted"
	kindRunFailed          = "run.failed"
	kindRunSealed          = "run.sealed"
	kindPolicyChanged      = "policy.changed"
	kindSignOffRecorded    = "signoff.recorded"
	kindApproverRegistered = "approver.registered"
	kindApproverRevoked    = "approver.revoked"
	kindKeyCreated         = "key.created"
	kindKeyRevoked         = "key.revoked"
	kindRunPublished       = "run.published"
	kindRunUnpublished     = "run.unpublished"
	kindChainGap           = "chain.gap"
	kindChainInterrupted   = "chain.interrupted"
	kindAccountChanged     = "account.changed"
	kindRunDeleted         = "run.deleted"
	kindAccountStopped     = "account.stopped"
	kindAccountResumed     = "account.resumed"
	kindSetupChanged       = "setup.changed"
	kindReviewDue          = "review.due"
	kindTargetPassed       = "signoff.target_passed"
	kindSignOffRefused     = "signoff.refused"
)

// Event is one served feed event: its place, kind and hash, the run it
// names, and its entry exactly as served. Deleted is set on an event whose
// record was deleted: its tombstone stands in its place and its entry is
// null, so its own sealed time cannot be read.
type Event struct {
	Sequence  int64
	Kind      string
	EventHash string
	RunID     int64
	Entry     json.RawMessage
	Deleted   bool
}

// EventRef is one event a figure counts: its place and its hash.
type EventRef struct {
	Sequence  int64
	EventHash string
}

func (e *Event) ref() EventRef { return EventRef{Sequence: e.Sequence, EventHash: e.EventHash} }

// target is a response target as sealed into a result's entry.
type target struct {
	Within  int64  `json:"within"`
	Compare string `json:"compare"`
	Notice  string `json:"notice"`
}

// anchor is the part of a public-log anchor this package reads: the log's
// own time for the entry, in whole seconds, or 0 when it states none.
type anchor struct {
	IntegratedTime int64 `json:"integrated_time"`
}

func loggedOf(a *anchor) int64 {
	if a == nil || a.IntegratedTime <= 0 {
		return 0
	}
	return a.IntegratedTime
}

// signOffTarget names the result a sign-off is on.
type signOffTarget struct {
	Kind  string `json:"kind"`
	RunID int64  `json:"run_id"`
}

// receiptDoc is the part of a refused, halted or failed run's receipt
// document this package reads.
type receiptDoc struct {
	Deny *struct {
		Clock string `json:"deny_clock"`
		Code  string `json:"decision_reason_code"`
		Hash  string `json:"hash"`
	} `json:"deny_receipt"`
	Gap *struct {
		Clock string `json:"gap_clock"`
		Code  string `json:"decision_reason_code"`
		Hash  string `json:"hash"`
	} `json:"attestation_gap_receipt"`
	CCV *struct {
		Clock string `json:"halt_clock"`
		Code  string `json:"halt_reason_code"`
		Hash  string `json:"hash"`
	} `json:"ccv_halt_receipt"`
	MACC *struct {
		Clock string `json:"halt_clock"`
		Code  string `json:"halt_reason_code"`
		Hash  string `json:"hash"`
	} `json:"macc_halt_receipt"`
	AivpT4 *struct {
		Clock string `json:"halt_clock"`
		Code  string `json:"halt_reason_code"`
		Hash  string `json:"hash"`
	} `json:"aivp_t4_halt_receipt"`
	Failure *struct {
		Clock string `json:"fail_clock"`
		Stage string `json:"failed_stage"`
		Class string `json:"error_class"`
		Hash  string `json:"hash"`
	} `json:"failure_receipt"`
	Anchor  *anchor `json:"receipt_anchor"`
	Context *struct {
		DataUse        json.RawMessage `json:"data_use"`
		ResponseTarget *target         `json:"response_target"`
	} `json:"receipt_context"`
}

// entry is the part of every other entry this package reads; each kind
// fills the fields it carries.
type entry struct {
	Format    string `json:"format"`
	DecidedBy string `json:"decided_by"`
	// The sealed clocks, one per kind.
	SealedAt    string `json:"sealed_at"`
	ActivatedAt string `json:"activated_at"`
	RecordedAt  string `json:"recorded_at"`
	ChangedAt   string `json:"changed_at"`
	StatedAt    string `json:"stated_at"`
	RefusedAt   string `json:"refused_at"`
	// run.sealed
	RunID           int64   `json:"run_id"`
	JobID           string  `json:"job_id"`
	SignOffRequired bool    `json:"signoff_required"`
	SignOffTarget   *target `json:"signoff_target"`
	RunSealedHash   string  `json:"run_sealed_hash"`
	// policy.changed
	ChainID   string          `json:"chain_id"`
	Signature json.RawMessage `json:"signature"`
	// signoff.recorded
	Decision string        `json:"decision"`
	Target   signOffTarget `json:"target"`
	// account.stopped, account.resumed
	Action         string          `json:"action"`
	LiftsSequence  int64           `json:"lifts_sequence"`
	OwnerSignature json.RawMessage `json:"owner_signature"`
	Unsigned       string          `json:"unsigned"`
	// signoff.target_passed
	ResultKind string  `json:"result_kind"`
	Anchor     *anchor `json:"anchor"`
}

// facts are what one event's entry states, read once.
type facts struct {
	ev *Event
	// clock is the entry's own sealed time and clockText as sealed.
	clock     time.Time
	clockText string
	// logged is the entry's public-log time, or 0.
	logged    int64
	decidedBy string
	// ownerSigned is set on an owner's stop that carries the owner's
	// request-key signature and no unsigned statement.
	ownerSigned bool
	// Receipts: the receipt kind and its code; a failure's class and stage.
	receiptKind string
	code        string
	class       string
	stage       string
	dataUse     bool
	// The result's hash: the run.sealed record's or the receipt's.
	resultHash string
	target     *target
	e          entry
}

// errFeed is a feed this package cannot count.
var errFeed = errors.New("feedcount: the feed cannot be counted")

func feedErr(ev *Event, format string, args ...any) error {
	return fmt.Errorf("%w: event %d (%s): %s", errFeed, ev.Sequence, ev.Kind, fmt.Sprintf(format, args...))
}

// parseClock reads a sealed time: RFC 3339, any offset, fraction optional.
func parseClock(text string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, text)
	return t, err == nil
}

// readFacts reads one event's entry. A deleted event has no facts; every
// other event must carry its kind's sealed clock.
func readFacts(ev *Event) (*facts, error) {
	if ev.Deleted {
		return nil, nil
	}
	f := &facts{ev: ev}
	switch ev.Kind {
	case kindRunRefused, kindRunHalted, kindRunFailed:
		var d receiptDoc
		if err := json.Unmarshal(ev.Entry, &d); err != nil {
			return nil, feedErr(ev, "its receipt document does not decode: %v", err)
		}
		switch {
		case d.Deny != nil:
			f.receiptKind, f.clockText, f.code, f.resultHash = "deny_receipt", d.Deny.Clock, d.Deny.Code, d.Deny.Hash
		case d.Gap != nil:
			f.receiptKind, f.clockText, f.code, f.resultHash = "attestation_gap_receipt", d.Gap.Clock, d.Gap.Code, d.Gap.Hash
		case d.CCV != nil:
			f.receiptKind, f.clockText, f.code, f.resultHash = "ccv_halt_receipt", d.CCV.Clock, d.CCV.Code, d.CCV.Hash
		case d.MACC != nil:
			f.receiptKind, f.clockText, f.code, f.resultHash = "macc_halt_receipt", d.MACC.Clock, d.MACC.Code, d.MACC.Hash
		case d.AivpT4 != nil:
			f.receiptKind, f.clockText, f.code, f.resultHash = "aivp_t4_halt_receipt", d.AivpT4.Clock, d.AivpT4.Code, d.AivpT4.Hash
		case d.Failure != nil:
			f.receiptKind, f.clockText, f.class, f.stage, f.resultHash = "failure_receipt", d.Failure.Clock, d.Failure.Class, d.Failure.Stage, d.Failure.Hash
		default:
			return nil, feedErr(ev, "its receipt document carries no receipt")
		}
		f.logged = loggedOf(d.Anchor)
		if d.Context != nil {
			f.dataUse = len(d.Context.DataUse) > 0 && string(d.Context.DataUse) != "null"
			f.target = d.Context.ResponseTarget
		}
	default:
		if err := json.Unmarshal(ev.Entry, &f.e); err != nil {
			return nil, feedErr(ev, "its entry does not decode: %v", err)
		}
		e := &f.e
		f.logged, f.decidedBy = loggedOf(e.Anchor), e.DecidedBy
		switch ev.Kind {
		case kindRunSealed:
			f.clockText, f.target, f.resultHash = e.SealedAt, e.SignOffTarget, e.RunSealedHash
		case kindPolicyChanged:
			f.clockText = e.ActivatedAt
		case kindSignOffRecorded, kindChainGap, kindChainInterrupted:
			f.clockText = e.RecordedAt
		case kindApproverRegistered, kindApproverRevoked, kindKeyCreated, kindKeyRevoked:
			f.clockText = e.ChangedAt
			if e.Format == "verdifax.key-change.v1" {
				f.decidedBy = "owner"
			}
		case kindRunPublished, kindRunUnpublished:
			f.clockText = e.ChangedAt
			if e.Format == "verdifax.run-publication.v1" {
				f.decidedBy = "owner"
			}
		case kindAccountChanged, kindRunDeleted, kindSetupChanged, kindAccountStopped, kindAccountResumed:
			f.clockText = e.ChangedAt
			f.ownerSigned = len(e.OwnerSignature) > 0 && string(e.OwnerSignature) != "null" && e.Unsigned == ""
		case kindReviewDue, kindTargetPassed:
			f.clockText = e.StatedAt
		case kindSignOffRefused:
			f.clockText = e.RefusedAt
		default:
			return nil, feedErr(ev, "its kind is not one these counting rules read")
		}
	}
	clock, ok := parseClock(f.clockText)
	if !ok {
		return nil, feedErr(ev, "its sealed time %q is not an RFC 3339 time", f.clockText)
	}
	f.clock = clock
	return f, nil
}

// resultOf is the result an event is, for sign-offs and targets: a
// run.sealed record, or a refused or halted run's receipt.
func (f *facts) resultKind() string {
	switch f.ev.Kind {
	case kindRunSealed:
		return "record"
	case kindRunRefused, kindRunHalted:
		return "receipt"
	}
	return ""
}

// names reports whether a sign-off names the result of this run and kind:
// a receipt only by a receipt sign-off; a record by a record or a job
// sign-off on the same run (the job's governs).
func names(t signOffTarget, runID int64, resultKind string) bool {
	if t.RunID != runID {
		return false
	}
	switch resultKind {
	case "receipt":
		return t.Kind == "receipt"
	case "record":
		return t.Kind == "record" || t.Kind == "job"
	}
	return false
}

// KnownCountingRules reports rules this package counts by.
func KnownCountingRules(rules string) bool {
	return rules == CountingRules || rules == CountingRulesV1
}
