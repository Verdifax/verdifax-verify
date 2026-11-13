package main

// The signal feed (v0.23.0). GET /signals returns an account's control
// signals as CloudEvents, oldest first. Each event's number and the previous
// event's hash are sealed inside the event's own entry (a receipt, a policy
// change, a sign-off or a key change) before that entry is anchored on the
// public log. --signals checks each entry as its own kind, that the place it
// seals is the event's place, that every event belongs to one account, and
// that the numbers and links run without a gap. --signals-after N:hash checks
// continuity from the last event a system already read.
//
// A feed shows the signals Verdifax recorded for the account, in order. It
// cannot show a signal Verdifax never recorded.
//
// Since v0.34.0 (round 61) a page that reaches the feed's end carries the
// feed's head statement, so a feed cut short before a later event fails, and
// each key's request-key chain is followed through the feed (keychains.go).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// signalSource opens the CloudEvents source of every feed event.
const signalSource = "https://api.verdifax.com/accounts/"

// signalCloudEvent is one feed event as the API serves it.
type signalCloudEvent struct {
	SpecVersion     string      `json:"specversion"`
	ID              string      `json:"id"`
	Source          string      `json:"source"`
	Type            string      `json:"type"`
	Time            string      `json:"time"`
	DataContentType string      `json:"datacontenttype"`
	Data            signalEvent `json:"data"`
}

// signalEvent is the Verdifax event inside the envelope.
type signalEvent struct {
	Form               string          `json:"form"`
	Kind               string          `json:"kind"`
	Account            string          `json:"account"`
	Sequence           int64           `json:"sequence"`
	PreviousSignalHash string          `json:"previous_signal_hash"`
	EventHash          string          `json:"event_hash"`
	RunID              int64           `json:"run_id,omitempty"`
	APIKeyID           int64           `json:"api_key_id,omitempty"`
	Reason             string          `json:"reason,omitempty"`
	Entry              json.RawMessage `json:"entry"`
	// Deleted (round 60, v0.33.0) is the tombstone served in place of a
	// deleted record's entry: the event then carries no entry, and its hash
	// is checked against the record hash the tombstone seals.
	Deleted *artifacts.RunDeletion `json:"deleted,omitempty"`
}

// signalFeedPage is the body of GET /signals. Head (round 61, N23) is
// Verdifax's head statement, served on a page that reaches the feed's end.
type signalFeedPage struct {
	Events    []signalCloudEvent  `json:"events"`
	NextAfter int64               `json:"next_after"`
	Newest    int64               `json:"newest"`
	Head      *artifacts.FeedHead `json:"head,omitempty"`
}

// SignalFeedEntry is one checked event in the report.
type SignalFeedEntry struct {
	Sequence int64  `json:"sequence"`
	Kind     string `json:"kind"`
	RunID    int64  `json:"run_id,omitempty"`
	// DecidedBy, on a publication, key change, account change or deletion,
	// is who decided: owner, or verdifax_admin for a Verdifax admin key
	// (R160; round 60 for key and account changes and deletions).
	DecidedBy string `json:"decided_by,omitempty"`
	// Change and Value, on an account.changed event, are the change and its
	// new value; KeyScope, on a key change, is the key's scope.
	Change   string `json:"change,omitempty"`
	Value    string `json:"value,omitempty"`
	KeyScope string `json:"key_scope,omitempty"`
	// OwnerSignedBy, on a change the owner decided, is the request key that
	// signed it: compare it with the owner's own request key.
	OwnerSignedBy string `json:"owner_signed_by,omitempty"`
	// RecordDeletedBy, on an event whose record was deleted, is who deleted
	// it, from the tombstone served in its place; TombstoneSequence (round
	// 61, N25) is the tombstone's own event.
	RecordDeletedBy   string `json:"record_deleted_by,omitempty"`
	TombstoneSequence int64  `json:"tombstone_sequence,omitempty"`
	// KeyID, on a key or account change that names a key, is that key.
	KeyID int64 `json:"key_id,omitempty"`
	// At is the time the entry seals; for an event whose record was deleted
	// it is the event's served time, since the record is gone.
	At       string `json:"at"`
	LogEntry string `json:"log_entry_id"`
	// CommittedBy, when set, is the later event whose public-log entry
	// commits this one: this event carries no entry of its own, so its time
	// is proven only by that later entry, not by its own clock.
	CommittedBy int64 `json:"committed_by,omitempty"`
	// GapChain, GapFrom and GapTo, on a chain.gap event, are the chain and
	// the places a restore from backup made it skip (round 56, E4).
	GapChain string `json:"gap_chain,omitempty"`
	GapFrom  int64  `json:"gap_from,omitempty"`
	GapTo    int64  `json:"gap_to,omitempty"`
}

// SignalFeedCheck is the --signals result.
type SignalFeedCheck struct {
	Checked bool              `json:"checked"`
	OK      bool              `json:"ok"`
	Account string            `json:"account,omitempty"`
	First   int64             `json:"first_sequence,omitempty"`
	Last    int64             `json:"last_sequence,omitempty"`
	Entries []SignalFeedEntry `json:"entries,omitempty"`
	// ContinuityFrom says what the first event was checked against: "start"
	// (it is event 1), "given point" (--signals-after), or "not checked"
	// (a later page read with no point given).
	ContinuityFrom string `json:"continuity_from,omitempty"`
	LastEventHash  string `json:"last_event_hash,omitempty"`
	// CommittedLater counts the events with no public-log entry of their own
	// that a later event's entry commits. The feed is then sound but partly
	// timed: --signals exits 3 unless --allow-partial is given.
	CommittedLater int `json:"committed_by_a_later_event,omitempty"`
	// DeclaredGaps counts the chain.gap events: places a restore made one of
	// the account's chains skip, each sealed and named by its own entry.
	DeclaredGaps int `json:"declared_gaps,omitempty"`
	// OwnerSigningKeys are the request keys that signed the owner's changes
	// in the feed, in the order first seen; OwnerKeysPinned says every one
	// was a key given with --owner-request-key (round 60).
	OwnerSigningKeys []string `json:"owner_signing_keys,omitempty"`
	OwnerKeysPinned  bool     `json:"owner_keys_pinned,omitempty"`
	// RequestKeyChains (round 61, N22) is each key's request-key chain as
	// the feed shows it, by key.
	RequestKeyChains []RequestKeyChain `json:"request_key_chains,omitempty"`
	// Head (round 61, N23) is the head statement the feed ends with, when
	// it carries one: CompleteAsOf is its time on the public log and
	// CompleteAge how long before this check that was (N24).
	HeadSequence int64  `json:"head_sequence,omitempty"`
	CompleteAsOf string `json:"complete_as_of,omitempty"`
	CompleteAge  string `json:"complete_as_of_age,omitempty"`
	// OwnerBlocks are the owner's blocks as the feed leaves them, and
	// BlocksHeldAsOf the time they are shown to hold until: the head's time,
	// or empty when the feed has no head and a later event may exist.
	OwnerBlocks    map[string]string `json:"owner_blocks,omitempty"`
	BlocksHeldAsOf string            `json:"owner_blocks_held_as_of,omitempty"`
	// UnconfirmedOwnerChanges (round 62, N28) are the owner's changes signed
	// by a request key registered after the owner's chain started afresh and
	// not named by --owner-request-key. None is counted as the owner's: an
	// unconfirmed allow lifts no block, while an unconfirmed block still
	// holds, since a block only restricts Verdifax.
	UnconfirmedOwnerChanges []UnconfirmedOwnerChange `json:"unconfirmed_owner_changes,omitempty"`
	// WebhookChanges counts the webhook subscriptions added and removed in
	// the feed (round 62: from verifier v0.35.0's server release on, each is
	// an account.changed event signed by the owner's request key). Webhooks,
	// for a feed read from its start, are the subscriptions in place at its
	// end, each as its sealed value: the SHA-256 of the address and the kinds
	// it takes, so a reader sees every place the account's events are sent.
	WebhookChanges int      `json:"webhook_changes,omitempty"`
	Webhooks       []string `json:"webhooks,omitempty"`
	// Notes are what the check could not confirm without more evidence, and
	// how to give it.
	Notes  []string `json:"notes,omitempty"`
	Reason string   `json:"reason,omitempty"`
}

// UnconfirmedOwnerChange is one owner change the feed cannot tie to the owner
// (round 62, N28): the event, what it set, the request key that signed it,
// and the fresh start of the owner's chain that left that key unconfirmed.
type UnconfirmedOwnerChange struct {
	Sequence     int64  `json:"sequence"`
	Kind         string `json:"kind"`
	Action       string `json:"action,omitempty"`
	Value        string `json:"value,omitempty"`
	SignedBy     string `json:"signed_by"`
	FreshStart   string `json:"fresh_start"`
	FreshStartAt int64  `json:"fresh_start_at"`
}

// RequestKeyChain is one key's request keys as the feed shows them: each
// registration, rotation and clear, in order.
type RequestKeyChain struct {
	KeyID int64 `json:"key_id"`
	// OwnerKey says the key is the account's owner key, by its creation in
	// the feed.
	OwnerKey bool `json:"owner_key,omitempty"`
	// Current is the key's request key after the feed's last event, empty
	// when it holds none.
	Current string              `json:"current,omitempty"`
	Events  []RequestKeyEventAt `json:"events"`
	// ClearedByVerdifax is the event at which Verdifax last cleared the
	// key's request key: the chain is broken there, and a key registered
	// after it is proven only by --owner-request-key.
	ClearedByVerdifax int64 `json:"cleared_by_verdifax_at,omitempty"`
	// Unrooted says the chain's first event in the feed is not a
	// registration: the key was registered before the feed shows (before
	// the server sealed registrations, or before the point checked).
	Unrooted bool `json:"unrooted,omitempty"`
}

// RequestKeyEventAt is one change in a key's request-key chain.
type RequestKeyEventAt struct {
	Sequence  int64  `json:"sequence"`
	Action    string `json:"action"`
	Key       string `json:"key,omitempty"`
	DecidedBy string `json:"decided_by"`
}

var signalAfterPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,18}):([0-9a-f]{64})$`)

// signalPoint is the last event a system already read.
type signalPoint struct {
	sequence int64
	hash     string
}

// parseSignalPoint reads --signals-after N:hash.
func parseSignalPoint(v string) (*signalPoint, error) {
	if v == "" {
		return nil, nil
	}
	m := signalAfterPattern.FindStringSubmatch(v)
	if m == nil {
		return nil, errors.New("--signals-after must be N:hash, the last event's sequence and its 64-character event hash")
	}
	n, parseErr := strconv.ParseInt(m[1], 10, 64)
	if parseErr != nil {
		return nil, fmt.Errorf("--signals-after: %w", parseErr)
	}
	if (n == 0) != (m[2] == artifacts.NoPreviousSignal) {
		return nil, errors.New("--signals-after: point 0 has the all-zero hash, and only point 0 does")
	}
	return &signalPoint{n, m[2]}, nil
}

// decodeSignalEvents reads a feed page, or a bare list of events, refusing
// unknown fields. A page that reaches the feed's end carries its head.
func decodeSignalEvents(data []byte) ([]signalCloudEvent, *artifacts.FeedHead, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var events []signalCloudEvent
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if decodeErr := dec.Decode(&events); decodeErr != nil {
			return nil, nil, fmt.Errorf("the feed is not a list of signal events: %w", decodeErr)
		}
		return events, nil, nil
	}
	var page signalFeedPage
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if decodeErr := dec.Decode(&page); decodeErr != nil {
		return nil, nil, fmt.Errorf("the feed is not a GET /signals body: %w", decodeErr)
	}
	return page.Events, page.Head, nil
}

// strictDecode decodes an entry, refusing unknown fields.
func strictDecode(raw json.RawMessage, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(into)
}

// receiptSignalKind is the feed kind of a receipt kind.
func receiptSignalKind(receiptKind string) string {
	switch receiptKind {
	case "deny_receipt", "attestation_gap_receipt":
		return artifacts.SignalRunRefused
	case "failure_receipt":
		return artifacts.SignalRunFailed
	}
	return artifacts.SignalRunHalted
}

// checkedEntry is what one event's entry showed.
type checkedEntry struct {
	hash, at, logEntry string
	link               *artifacts.SignalLink
	runID              int64
	decidedBy          string
	// unlogged is an entry sound in every way but one: it carries no
	// public-log entry of its own.
	unlogged bool
	// gap is the restore gap a chain.gap event's entry records.
	gap *artifacts.RestoreGap
	// change is an account.changed event's record; keyScope a key change's
	// scope.
	change    *artifacts.AccountChange
	keyScope  string
	keyID     int64
	ownerKey  string
	deletedBy string
	// tombstoneAt is, on an event whose record was deleted, the
	// tombstone's own event (round 61, N25).
	tombstoneAt int64
}

// unloggedOr passes a check that failed only for want of a public-log entry,
// and returns every other failure.
func unloggedOr(err error) (bool, error) {
	if err == nil {
		return false, nil
	}
	if errors.Is(err, errNoLogEntry) {
		return true, nil
	}
	return false, err
}

// logEntryOf is an anchor's entry id, or empty for none.
func logEntryOf(a *artifacts.ReceiptAnchor) string {
	if a == nil {
		return ""
	}
	return a.LogEntryID
}

// checkSignalEntry checks one event's entry as its own kind and returns its
// hash and the feed place it seals.
func checkSignalEntry(ce *signalCloudEvent) (checkedEntry, error) {
	e := &ce.Data
	if e.Deleted != nil {
		return checkDeletedRecordEvent(ce)
	}
	switch e.Kind {
	case artifacts.SignalRunRefused, artifacts.SignalRunHalted, artifacts.SignalRunFailed:
		var doc artifacts.ReceiptDocument
		if decodeErr := strictDecode(e.Entry, &doc); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not a receipt document: %w", decodeErr)
		}
		rep := verifyReceiptDocument(&doc)
		// A receipt sound in every way but carrying no log entry, and not
		// sealed as requiring one, is unlogged; one sealed with
		// anchor_required that lost its entry fails, as it does alone.
		unlogged := rep.AllPassed && rep.VerdictTier == "SELF_CONSISTENT_NOT_ANCHORED" && doc.ReceiptAnchor == nil
		if !unlogged && (!rep.AllPassed || rep.VerdictTier != "VERIFIED_ANCHORED") {
			return checkedEntry{}, fmt.Errorf("its receipt does not verify as anchored: %s", rep.Reason)
		}
		if got := receiptSignalKind(rep.ReceiptKind); got != e.Kind {
			return checkedEntry{}, fmt.Errorf("it is a %s event, and its entry is a %s, which is a %s", e.Kind, rep.ReceiptKind, got)
		}
		if e.RunID != doc.RunID {
			return checkedEntry{}, fmt.Errorf("it names run %d, and its receipt is run %d's", e.RunID, doc.RunID)
		}
		ctx := doc.ReceiptContext
		if ctx == nil || ctx.Signal == nil {
			return checkedEntry{}, errors.New("its receipt seals no place in the feed")
		}
		if ctx.AccountID != e.Account {
			return checkedEntry{}, fmt.Errorf("its receipt seals account %q, not %s", ctx.AccountID, e.Account)
		}
		return checkedEntry{hash: rep.ReceiptHash, at: rep.ReceiptClock, logEntry: rep.AnchorLogEntry, link: ctx.Signal, runID: doc.RunID, unlogged: unlogged}, nil
	case artifacts.SignalPolicyChanged:
		var a artifacts.PolicyActivation
		if decodeErr := strictDecode(e.Entry, &a); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not a policy change: %w", decodeErr)
		}
		if a.Signal == nil {
			return checkedEntry{}, errors.New("its policy change seals no place in the feed")
		}
		unlogged, checkErr := unloggedOr(checkPolicyChangeAlone(&a))
		if checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its policy change: %w", checkErr)
		}
		return checkedEntry{hash: a.ActivationHash, at: a.ActivatedAt, logEntry: logEntryOf(a.Anchor), link: a.Signal, unlogged: unlogged}, nil
	case artifacts.SignalSignOffRecorded:
		var s artifacts.SignOff
		if decodeErr := strictDecode(e.Entry, &s); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not a sign-off: %w", decodeErr)
		}
		if s.Signal == nil {
			return checkedEntry{}, errors.New("its sign-off seals no place in the feed")
		}
		unlogged, checkErr := unloggedOr(checkOneSignOff(&s))
		if checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its sign-off: %w", checkErr)
		}
		return checkedEntry{hash: s.SignOffHash, at: s.RecordedAt, logEntry: logEntryOf(s.Anchor), link: s.Signal, runID: s.Target.RunID, unlogged: unlogged}, nil
	case artifacts.SignalApproverRegistered, artifacts.SignalApproverRevoked, artifacts.SignalKeyCreated, artifacts.SignalKeyRevoked:
		var k artifacts.KeyChange
		if decodeErr := strictDecode(e.Entry, &k); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not a key change: %w", decodeErr)
		}
		unlogged, checkErr := unloggedOr(checkKeyChange(&k))
		if checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its key change: %w", checkErr)
		}
		if k.Action != e.Kind {
			return checkedEntry{}, fmt.Errorf("it is a %s event, and its key change is a %s", e.Kind, k.Action)
		}
		link := k.Signal
		return checkedEntry{hash: k.KeyChangeHash, at: k.ChangedAt, logEntry: logEntryOf(k.Anchor), link: &link,
			decidedBy: k.Decider(), keyScope: k.KeyScope, keyID: k.KeyID, unlogged: unlogged}, nil
	case artifacts.SignalAccountChanged:
		var c artifacts.AccountChange
		if decodeErr := strictDecode(e.Entry, &c); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not an account change: %w", decodeErr)
		}
		unlogged, checkErr := unloggedOr(checkSealedEntry(c.Validate(), c.ComputeHash(), c.AccountChangeHash, c.ChangedAt, "changed_at",
			c.Anchor, artifacts.AccountChangeKind, c.LeafHash()))
		if checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its account change: %w", checkErr)
		}
		link := c.Signal
		return checkedEntry{hash: c.AccountChangeHash, at: c.ChangedAt, logEntry: logEntryOf(c.Anchor), link: &link,
			decidedBy: c.DecidedBy, change: &c, keyID: c.KeyID, ownerKey: ownerKeyOf(c.OwnerSignature), unlogged: unlogged}, nil
	case artifacts.SignalRunDeleted:
		var d artifacts.RunDeletion
		if decodeErr := strictDecode(e.Entry, &d); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not a run deletion: %w", decodeErr)
		}
		unlogged, checkErr := unloggedOr(checkSealedEntry(d.Validate(), d.ComputeHash(), d.DeletionHash, d.ChangedAt, "changed_at",
			d.Anchor, artifacts.RunDeletionKind, d.LeafHash()))
		if checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its run deletion: %w", checkErr)
		}
		if e.RunID != d.RunID {
			return checkedEntry{}, fmt.Errorf("it names run %d, and its deletion is run %d's", e.RunID, d.RunID)
		}
		link := d.Signal
		return checkedEntry{hash: d.DeletionHash, at: d.ChangedAt, logEntry: logEntryOf(d.Anchor), link: &link, runID: d.RunID,
			decidedBy: d.DecidedBy, ownerKey: ownerKeyOf(d.OwnerSignature), unlogged: unlogged}, nil
	case artifacts.SignalRunPublished, artifacts.SignalRunUnpublished:
		var p artifacts.RunPublication
		if decodeErr := strictDecode(e.Entry, &p); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not a run publication: %w", decodeErr)
		}
		unlogged, checkErr := unloggedOr(checkRunPublication(&p))
		if checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its run publication: %w", checkErr)
		}
		if p.Action != e.Kind {
			return checkedEntry{}, fmt.Errorf("it is a %s event, and its publication is a %s", e.Kind, p.Action)
		}
		if e.RunID != p.RunID {
			return checkedEntry{}, fmt.Errorf("it names run %d, and its publication is run %d's", e.RunID, p.RunID)
		}
		link := p.Signal
		return checkedEntry{hash: p.PublicationHash, at: p.ChangedAt, logEntry: logEntryOf(p.Anchor), link: &link, runID: p.RunID,
			decidedBy: p.Decider(), unlogged: unlogged}, nil
	case artifacts.SignalRunSealed:
		var rs artifacts.RunSealed
		if decodeErr := strictDecode(e.Entry, &rs); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not a run-sealed record: %w", decodeErr)
		}
		unlogged, checkErr := unloggedOr(checkSealedEntry(rs.Validate(), rs.ComputeHash(), rs.RunSealedHash, rs.SealedAt, "sealed_at",
			rs.Anchor, artifacts.RunSealedKind, rs.LeafHash()))
		if checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its run-sealed record: %w", checkErr)
		}
		if e.RunID != rs.RunID {
			return checkedEntry{}, fmt.Errorf("it names run %d, and its record is run %d's", e.RunID, rs.RunID)
		}
		link := rs.Signal
		return checkedEntry{hash: rs.RunSealedHash, at: rs.SealedAt, logEntry: logEntryOf(rs.Anchor), link: &link, runID: rs.RunID, unlogged: unlogged}, nil
	case artifacts.SignalChainGap:
		var g artifacts.RestoreGap
		if decodeErr := strictDecode(e.Entry, &g); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not a restore gap: %w", decodeErr)
		}
		unlogged, checkErr := unloggedOr(checkSealedEntry(g.Validate(), g.ComputeHash(), g.RestoreGapHash, g.RecordedAt, "recorded_at",
			g.Anchor, artifacts.RestoreGapKind, g.LeafHash()))
		if checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its restore gap: %w", checkErr)
		}
		link := g.Signal
		return checkedEntry{hash: g.RestoreGapHash, at: g.RecordedAt, logEntry: logEntryOf(g.Anchor), link: &link, unlogged: unlogged, gap: &g}, nil
	case artifacts.SignalChainInterrupted:
		// Round 57, N2: a sign-off or policy change the log never confirmed;
		// its record closes one place of its chain and names the entry it
		// would have made. It takes its own place in the feed.
		var c artifacts.ChainInterrupted
		if decodeErr := strictDecode(e.Entry, &c); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not an interrupted record: %w", decodeErr)
		}
		unlogged, checkErr := unloggedOr(checkSealedEntry(c.Validate(), c.ComputeHash(), c.InterruptedHash, c.RecordedAt, "recorded_at",
			c.Anchor, artifacts.ChainInterruptedKind, c.LeafHash()))
		if checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its interrupted record: %w", checkErr)
		}
		link := c.Signal
		return checkedEntry{hash: c.InterruptedHash, at: c.RecordedAt, logEntry: logEntryOf(c.Anchor), link: &link, unlogged: unlogged}, nil
	}
	return checkedEntry{}, fmt.Errorf("its kind %q is not one the feed emits", safePrefix(e.Kind))
}

// checkRunPublication checks one run publication: its shape, hash and
// public-log entry. The record it names is checked by its own record; the
// publication shows who decided about it, the owner or a Verdifax admin key,
// and when.
func checkRunPublication(p *artifacts.RunPublication) error {
	if shapeErr := p.Validate(); shapeErr != nil {
		return shapeErr
	}
	if got := p.ComputeHash(); got != p.PublicationHash {
		return fmt.Errorf("its hash recomputes to %s, not %s", truncate(got, 16), truncate(p.PublicationHash, 16))
	}
	at, clockErr := time.Parse(time.RFC3339Nano, p.ChangedAt)
	if clockErr != nil {
		return fmt.Errorf("changed_at %q is not an RFC 3339 time", safePrefix(p.ChangedAt))
	}
	return checkChainEntry(p.Anchor, artifacts.RunPublicationKind, p.PublicationHash, p.LeafHash(), at, "changed_at")
}

// checkSealedEntry checks one account record that carries its place in the
// feed: its shape, its hash, its clock and its public-log entry.
func checkSealedEntry(shapeErr error, recomputed, sealed, clock, clockName string, anchor *artifacts.ReceiptAnchor, kind, leaf string) error {
	if shapeErr != nil {
		return shapeErr
	}
	if recomputed != sealed {
		return fmt.Errorf("its hash recomputes to %s, not %s", truncate(recomputed, 16), truncate(sealed, 16))
	}
	at, clockErr := time.Parse(time.RFC3339Nano, clock)
	if clockErr != nil {
		return fmt.Errorf("%s %q is not an RFC 3339 time", clockName, safePrefix(clock))
	}
	return checkChainEntry(anchor, kind, sealed, leaf, at, clockName)
}

// checkPolicyChangeAlone checks one policy change without its chain: its
// shape, hash, signature and public-log entry.
func checkPolicyChangeAlone(a *artifacts.PolicyActivation) error {
	if shapeErr := a.Validate(); shapeErr != nil {
		return shapeErr
	}
	if got := a.ComputeHash(); got != a.ActivationHash {
		return fmt.Errorf("its hash recomputes to %s, not %s", truncate(got, 16), truncate(a.ActivationHash, 16))
	}
	at, clockErr := time.Parse(time.RFC3339Nano, a.ActivatedAt)
	if clockErr != nil {
		return fmt.Errorf("activated_at %q is not an RFC 3339 time", safePrefix(a.ActivatedAt))
	}
	if signErr := checkActivationSignature(a); signErr != nil {
		return signErr
	}
	return checkActivationEntry(a, at)
}

// checkKeyChange checks one key change: its shape, hash and public-log entry.
func checkKeyChange(k *artifacts.KeyChange) error {
	if shapeErr := k.Validate(); shapeErr != nil {
		return shapeErr
	}
	if got := k.ComputeHash(); got != k.KeyChangeHash {
		return fmt.Errorf("its hash recomputes to %s, not %s", truncate(got, 16), truncate(k.KeyChangeHash, 16))
	}
	if k.PublicKey != "" {
		if raw, _ := base64.StdEncoding.DecodeString(k.PublicKey); len(raw) != ed25519.PublicKeySize {
			return errors.New("its public key is not an Ed25519 key")
		}
	}
	at, clockErr := time.Parse(time.RFC3339Nano, k.ChangedAt)
	if clockErr != nil {
		return fmt.Errorf("changed_at %q is not an RFC 3339 time", safePrefix(k.ChangedAt))
	}
	return checkChainEntry(k.Anchor, artifacts.KeyChangeKind, k.KeyChangeHash, k.LeafHash(), at, "changed_at")
}

// checkSignalEnvelope checks the CloudEvents fields against the event inside.
func checkSignalEnvelope(ce *signalCloudEvent) error {
	d := &ce.Data
	switch {
	case ce.SpecVersion != "1.0":
		return fmt.Errorf("its specversion is %q, not 1.0", safePrefix(ce.SpecVersion))
	case ce.DataContentType != "application/json":
		return errors.New("its datacontenttype is not application/json")
	case d.Form != artifacts.SignalFormat:
		return fmt.Errorf("its data form is %q, not %s", safePrefix(d.Form), artifacts.SignalFormat)
	case !artifacts.IsSignalKind(d.Kind):
		return fmt.Errorf("its kind %q is not one the feed emits", safePrefix(d.Kind))
	case ce.Type != artifacts.SignalTypePrefix+d.Kind:
		return fmt.Errorf("its type %q does not match its kind %s", safePrefix(ce.Type), d.Kind)
	case ce.Source != signalSource+d.Account:
		return fmt.Errorf("its source %q is not account %s", safePrefix(ce.Source), d.Account)
	case ce.ID != d.Account+"/"+strconv.FormatInt(d.Sequence, 10):
		return fmt.Errorf("its id %q does not name its account and sequence", safePrefix(ce.ID))
	}
	return nil
}

// checkSignalFeed checks a feed file.
func checkSignalFeed(data []byte, after *signalPoint) SignalFeedCheck {
	return checkSignalFeedPinned(data, after, nil)
}

// checkSignalFeedPinned is checkSignalFeed with the owner's request keys
// pinned: a change the owner decided that one of them did not sign fails the
// feed, and so does a request key registered for the owner key that is not
// one of them (round 61). The record names the key that signed it, so
// without a pin the check proves that key signed, and the feed's request-key
// chain proves it was the owner key's request key from its registration on;
// the pin proves the registration itself was the owner's.
func checkSignalFeedPinned(data []byte, after *signalPoint, ownerKeys []string) SignalFeedCheck {
	c := SignalFeedCheck{Checked: true}
	pinned := map[string]bool{}
	for _, k := range ownerKeys {
		pinned[k] = true
	}
	seenOwnerKey := map[string]bool{}
	events, head, readErr := decodeSignalEvents(data)
	if readErr != nil {
		c.Reason = readErr.Error()
		return c
	}
	if len(events) == 0 {
		c.Reason = "the feed holds no events"
		return c
	}
	var previousHash string
	var previousSeq int64
	// The owner's blocks, as the feed has set them so far (round 60): while
	// one stands, Verdifax may not replace the owner key or delete a record.
	blocked := map[string]bool{}
	// Round 62, N28: an unconfirmed allow waiting on a block it cannot lift,
	// by setting, and every owner change the feed cannot tie to the owner.
	pendingAllow := map[string]UnconfirmedOwnerChange{}
	var unconfirmed []UnconfirmedOwnerChange
	chains := newRequestKeyChains()
	switch {
	case after != nil:
		previousSeq, previousHash, c.ContinuityFrom = after.sequence, after.hash, "given point"
	case events[0].Data.Sequence == 1,
		// A restore that lost an account's whole feed: its first event is a
		// gap following no event.
		events[0].Data.Kind == artifacts.SignalChainGap && events[0].Data.PreviousSignalHash == artifacts.NoPreviousSignal:
		previousSeq, previousHash, c.ContinuityFrom = 0, artifacts.NoPreviousSignal, "start"
	default:
		c.ContinuityFrom = "not checked"
	}
	for i := range events {
		ce := &events[i]
		d := &ce.Data
		fail := func(format string, args ...any) SignalFeedCheck {
			c.Reason = fmt.Sprintf("event %d (sequence %d): %s", i+1, d.Sequence, fmt.Sprintf(format, args...))
			c.Entries, c.RequestKeyChains, c.OwnerBlocks, c.Notes = nil, nil, nil, nil
			return c
		}
		if envErr := checkSignalEnvelope(ce); envErr != nil {
			return fail("%v", envErr)
		}
		if c.Account == "" {
			c.Account = d.Account
		} else if d.Account != c.Account {
			return fail("it belongs to %s, and the feed began with %s", d.Account, c.Account)
		}
		got, entryErr := checkSignalEntry(ce)
		if entryErr != nil {
			return fail("%v", entryErr)
		}
		// A feed skips places only where a sealed restore gap, anchored as
		// its own entry, names exactly the places skipped (round 56, E4).
		feedGap := got.gap != nil && got.gap.Chain == artifacts.GapChainSignals
		if previousHash != "" {
			switch {
			case feedGap && i == 0 && after != nil && after.sequence >= got.gap.LostFrom && after.sequence <= got.gap.LostTo:
				// The reader holds events the server lost in a restore.
				return fail("your point, event %d, is inside a restore gap that skips places %d to %d: a restore from backup lost events you already read. "+
					"Keep your copies of them; they and this gap's entry are the evidence of the loss. Check the feed from its start, or from event %d, to continue",
					after.sequence, got.gap.LostFrom, got.gap.LostTo, got.gap.LostFrom-1)
			case feedGap && (got.gap.LostFrom != previousSeq+1 || d.Sequence != got.gap.LostTo+1):
				return fail("its restore gap names places %d to %d, which are not the places between event %d and it",
					got.gap.LostFrom, got.gap.LostTo, previousSeq)
			case !feedGap && d.Sequence != previousSeq+1:
				return fail("it follows event %d, so an event is missing or out of order", previousSeq)
			}
			if d.PreviousSignalHash != previousHash {
				return fail("it does not name the event before it, so an event was removed, reordered or rewritten")
			}
		}
		link := artifacts.SignalLink{Account: d.Account, Sequence: d.Sequence, PreviousSignalHash: d.PreviousSignalHash}
		if *got.link != link {
			return fail("the place its entry seals (%s %d) is not its place in the feed", got.link.Account, got.link.Sequence)
		}
		if want := artifacts.SignalEventHash(d.Kind, got.hash, link); d.EventHash != want {
			return fail("its event hash is not the hash of its kind, entry and place")
		}
		if d.RunID != got.runID {
			return fail("it names run %d, and its entry names run %d", d.RunID, got.runID)
		}
		// Whether the owner's change is confirmed is read from the chain as
		// it stood before this event, which a setting does not change.
		var unconfirmedHere *UnconfirmedOwnerChange
		if got.ownerKey != "" {
			if isUnconfirmed, start := chains.unconfirmedOwnerSigner(got.ownerKey); isUnconfirmed {
				u := UnconfirmedOwnerChange{Sequence: d.Sequence, Kind: d.Kind, SignedBy: got.ownerKey,
					FreshStart: start.Route, FreshStartAt: start.Sequence}
				if got.change != nil {
					u.Action, u.Value = got.change.Action, got.change.Value
				}
				unconfirmedHere = &u
				unconfirmed = append(unconfirmed, u)
			}
		}
		if blockErr := checkOwnerBlocks(blocked, pendingAllow, d.Kind, &got, unconfirmedHere, chains.isOwnerKey); blockErr != "" {
			return fail("%s", blockErr)
		}
		if chainErr := chains.apply(d.Sequence, d.Kind, &got, pinned); chainErr != "" {
			return fail("%s", chainErr)
		}
		if got.ownerKey != "" {
			if len(pinned) > 0 && !pinned[got.ownerKey] {
				return fail("a change the owner decided is signed by request key %s, which is not one given with --owner-request-key", truncate(got.ownerKey, 12))
			}
			if !seenOwnerKey[got.ownerKey] {
				seenOwnerKey[got.ownerKey] = true
				c.OwnerSigningKeys = append(c.OwnerSigningKeys, got.ownerKey)
			}
		}
		entry := SignalFeedEntry{Sequence: d.Sequence, Kind: d.Kind, RunID: d.RunID, DecidedBy: got.decidedBy, At: got.at, LogEntry: got.logEntry,
			KeyScope: got.keyScope, KeyID: got.keyID, OwnerSignedBy: got.ownerKey, RecordDeletedBy: got.deletedBy, TombstoneSequence: got.tombstoneAt}
		if got.change != nil {
			entry.Change, entry.Value = got.change.Action, got.change.Value
		}
		if got.unlogged {
			entry.CommittedBy = -1 // resolved below, once the later events are checked
		}
		if got.gap != nil {
			entry.GapChain, entry.GapFrom, entry.GapTo = got.gap.Chain, got.gap.LostFrom, got.gap.LostTo
			c.DeclaredGaps++
		}
		c.Entries = append(c.Entries, entry)
		previousSeq, previousHash = d.Sequence, d.EventHash
	}
	// An event with no public-log entry of its own is committed by the next
	// event that has one: that entry's leaf seals the hash of the event
	// before it, and every hash in between was recomputed above and links to
	// the next, so changing the unlogged event would break the later entry.
	// Its time is proven only by that later entry. With no later logged
	// event in the feed, nothing commits it, and the feed fails.
	var committer int64
	for i := len(c.Entries) - 1; i >= 0; i-- {
		e := &c.Entries[i]
		if e.CommittedBy == 0 {
			committer = e.Sequence
			continue
		}
		if committer == 0 {
			c.Reason = fmt.Sprintf("event %d (sequence %d): it carries no public-log entry of its own, and no later event in the feed has one that commits it", i+1, e.Sequence)
			c.Entries = nil
			return c
		}
		e.CommittedBy = committer
		c.CommittedLater++
	}
	c.First, c.Last, c.LastEventHash = events[0].Data.Sequence, previousSeq, previousHash
	// Round 61, N23: the head statement says the feed's highest event as
	// Verdifax served it; a feed that ends below it was cut short.
	if head != nil {
		if headErr := checkFeedHead(head, c.Account, previousSeq, previousHash); headErr != nil {
			c.Reason, c.Entries = headErr.Error(), nil
			return c
		}
		asOf, age, ageErr := headAsOf(head.Anchor.IntegratedTime, feedHeadMaxAge, "--feed-head-max-age", "feed")
		if ageErr != nil {
			c.Reason, c.Entries = "the feed's head statement: "+ageErr.Error(), nil
			return c
		}
		c.HeadSequence, c.CompleteAsOf, c.CompleteAge = head.Sequence, asOf, age
	}
	if len(blocked) > 0 {
		c.OwnerBlocks = map[string]string{}
		for action, isBlocked := range blocked {
			c.OwnerBlocks[action] = map[bool]string{true: artifacts.SettingBlocked, false: artifacts.SettingAllowed}[isBlocked]
		}
		c.BlocksHeldAsOf = c.CompleteAsOf
	}
	c.RequestKeyChains, c.Notes = chains.report()
	c.UnconfirmedOwnerChanges = unconfirmed
	for _, action := range []string{artifacts.AccountSettingOwnerReplace, artifacts.AccountSettingVerdifaxDelete} {
		if p, waiting := pendingAllow[action]; waiting && blocked[action] {
			c.Notes = append(c.Notes, fmt.Sprintf("%s is held: the allow at event %d is signed by a key registered after %s at event %d, so it counts only with --owner-request-key.",
				settingName(action), p.Sequence, p.FreshStart, p.FreshStartAt))
		}
	}
	c.OwnerKeysPinned = len(pinned) > 0 && len(c.OwnerSigningKeys) > 0
	c.WebhookChanges, c.Webhooks, c.Notes = webhooksOf(c.Entries, c.ContinuityFrom == "start", c.Notes)
	c.OK = true
	return c
}

// webhooksOf counts the feed's webhook changes and, for a feed read from its
// start, lists the subscriptions in place at its end by their sealed values.
// A removal with no subscription before it in a feed read from its start is
// noted: the feed names a destination it never shows being added.
func webhooksOf(entries []SignalFeedEntry, fromStart bool, notes []string) (int, []string, []string) {
	changes := 0
	held := map[string]int{}
	for _, e := range entries {
		switch e.Change {
		case artifacts.AccountWebhookSubscribed:
			changes++
			held[e.Value]++
		case artifacts.AccountWebhookDeleted:
			changes++
			if held[e.Value] == 0 && fromStart {
				notes = append(notes, fmt.Sprintf("event %d removes a webhook (%s) the feed never shows being added.", e.Sequence, e.Value))
				continue
			}
			held[e.Value]--
		}
	}
	if !fromStart || changes == 0 {
		return changes, nil, notes
	}
	var active []string
	for value, n := range held {
		for i := 0; i < n; i++ {
			active = append(active, value)
		}
	}
	sort.Strings(active)
	return changes, active, notes
}

// checkFeedHead checks the head statement a feed page ends with: Verdifax's
// statement on the public log of the feed's highest event and that event's
// hash. A feed that ends below its head was cut short; one that goes past it,
// or ends on another event, was given a head that is not its own.
func checkFeedHead(h *artifacts.FeedHead, account string, last int64, lastHash string) error {
	if err := checkSealedEntry(h.Validate(), h.ComputeHash(), h.HeadStatementHash, h.StatedAt, "stated_at",
		h.Anchor, artifacts.FeedHeadKind, h.LeafHash()); err != nil {
		return fmt.Errorf("the feed's head statement: %w", err)
	}
	switch {
	case h.Account != account:
		return fmt.Errorf("the feed's head statement is %s's, not %s's", h.Account, account)
	case last < h.Sequence:
		return fmt.Errorf("the feed ends at event %d, and Verdifax's head statement of %s says the feed's highest event is %d, so events were left out of the end", last, h.StatedAt, h.Sequence)
	case last > h.Sequence:
		return fmt.Errorf("the feed goes on to event %d, and the head statement given with it, of %s, says the feed's highest event is %d, so the head is not this feed's", last, h.StatedAt, h.Sequence)
	case lastHash != h.HeadHash:
		return fmt.Errorf("the feed's event %d is not the event Verdifax's head statement of %s names, so the feed's end was rewritten", last, h.StatedAt)
	}
	return nil
}

// checkDeletedRecordEvent checks an event whose record was deleted (round
// 60): only a stopped run's event can stand for a record, its entry must be
// empty, and the tombstone served in its place must verify on its own (its
// shape, hash, owner signature and public-log entry), belong to this account
// and name this run. The event's hash is then checked against the record hash
// the tombstone seals, so the chain holds without the record.
func checkDeletedRecordEvent(ce *signalCloudEvent) (checkedEntry, error) {
	e := &ce.Data
	switch e.Kind {
	case artifacts.SignalRunRefused, artifacts.SignalRunHalted, artifacts.SignalRunFailed:
	default:
		return checkedEntry{}, fmt.Errorf("it is a %s event and carries a deletion tombstone; only a stopped run's event stands for a record", e.Kind)
	}
	if trimmed := bytes.TrimSpace(e.Entry); len(trimmed) != 0 && string(trimmed) != "null" {
		return checkedEntry{}, errors.New("it carries both an entry and a deletion tombstone")
	}
	d := e.Deleted
	if _, checkErr := unloggedOr(checkSealedEntry(d.Validate(), d.ComputeHash(), d.DeletionHash, d.ChangedAt, "changed_at",
		d.Anchor, artifacts.RunDeletionKind, d.LeafHash())); checkErr != nil {
		return checkedEntry{}, fmt.Errorf("the tombstone served for its deleted record: %w", checkErr)
	}
	switch {
	case d.Signal.Account != e.Account:
		return checkedEntry{}, fmt.Errorf("the tombstone served for its deleted record belongs to %s, not %s", d.Signal.Account, e.Account)
	case d.RunID != e.RunID:
		return checkedEntry{}, fmt.Errorf("it names run %d, and the tombstone served for its record is run %d's", e.RunID, d.RunID)
	case d.Signal.Sequence <= e.Sequence:
		return checkedEntry{}, errors.New("the tombstone served for its deleted record is not later in the feed than the event")
	}
	link := artifacts.SignalLink{Account: e.Account, Sequence: e.Sequence, PreviousSignalHash: e.PreviousSignalHash}
	logEntry := ""
	if len(d.LogEntries) > 0 {
		logEntry = d.LogEntries[0]
	}
	// Round 61, N25: the event reads at its own place in time, the time the
	// feed served it with; the tombstone's time is its own event's.
	return checkedEntry{hash: d.RecordHash, at: ce.Time, logEntry: logEntry, link: &link, runID: d.RunID, deletedBy: d.DecidedBy,
		tombstoneAt: d.Signal.Sequence}, nil
}

// deciderName reads a decider for the report: the owner, or Verdifax.
func deciderName(decidedBy string) string {
	if decidedBy == artifacts.DecidedByVerdifax {
		return "Verdifax"
	}
	return decidedBy
}

func ownerKeyOf(o *artifacts.OwnerSignature) string {
	if o == nil {
		return ""
	}
	return o.PublicKey
}

// checkOwnerBlocks applies the account owner's own settings to one event
// (round 60): after the owner blocks owner-key replacement, a Verdifax change
// to an owner key, or a request to replace it, fails the feed until the owner
// allows it again; after the owner blocks Verdifax deletion, a deletion
// Verdifax decided fails likewise. The account's first owner key, made when
// Verdifax created the account, comes before any setting the owner can make,
// so it never meets a block. A feed read from a later point sees only the
// settings made from that point on.
//
// Round 62, N28: a block counts whoever signed it, since a block only
// restricts Verdifax; an allow signed by an unconfirmed key lifts nothing and
// waits in pending, so a Verdifax action it alone would have permitted fails
// and says why. Verdifax clearing the owner key's request key after the owner
// blocked owner-key replacement fails, as any other owner-key change does.
func checkOwnerBlocks(blocked map[string]bool, pending map[string]UnconfirmedOwnerChange, kind string, got *checkedEntry,
	unconfirmed *UnconfirmedOwnerChange, isOwnerKey func(int64) bool) string {
	if c := got.change; c != nil && (c.Action == artifacts.AccountSettingOwnerReplace || c.Action == artifacts.AccountSettingVerdifaxDelete) {
		switch {
		case c.Value == artifacts.SettingBlocked || unconfirmed == nil:
			blocked[c.Action] = c.Value == artifacts.SettingBlocked
			delete(pending, c.Action)
		case blocked[c.Action]:
			pending[c.Action] = *unconfirmed
		}
		return ""
	}
	verdifax := got.decidedBy == artifacts.DecidedByVerdifax
	held := func(action, what string) string {
		if p, waiting := pending[action]; waiting {
			return fmt.Sprintf("Verdifax %s while the owner's %s block held: the allow at event %d is signed by a key registered after %s at event %d, so it counts only with --owner-request-key",
				what, settingName(action), p.Sequence, p.FreshStart, p.FreshStartAt)
		}
		return ""
	}
	switch {
	case verdifax && blocked[artifacts.AccountSettingOwnerReplace] && got.change != nil &&
		got.change.Action == artifacts.AccountRequestKeyCleared && isOwnerKey(got.change.KeyID):
		if why := held(artifacts.AccountSettingOwnerReplace, "cleared the owner key's request key"); why != "" {
			return why
		}
		return "Verdifax cleared the owner key's request key after the owner blocked owner-key replacement"
	case verdifax && blocked[artifacts.AccountSettingOwnerReplace] &&
		((kind == artifacts.SignalKeyCreated || kind == artifacts.SignalKeyRevoked) && got.keyScope == artifacts.KeyScopeOwner ||
			got.change != nil && got.change.Action == artifacts.AccountOwnerKeyReplacement):
		if why := held(artifacts.AccountSettingOwnerReplace, "changed the account's owner key"); why != "" {
			return why
		}
		return "Verdifax changed the account's owner key after the owner blocked owner-key replacement"
	case verdifax && blocked[artifacts.AccountSettingVerdifaxDelete] && kind == artifacts.SignalRunDeleted:
		if why := held(artifacts.AccountSettingVerdifaxDelete, "deleted a record"); why != "" {
			return why
		}
		return "Verdifax deleted a record after the owner blocked Verdifax deletion"
	}
	return ""
}

// settingName is an owner setting as the API names it.
func settingName(action string) string {
	switch action {
	case artifacts.AccountSettingOwnerReplace:
		return "owner-replacement"
	case artifacts.AccountSettingVerdifaxDelete:
		return "verdifax-deletion"
	}
	return action
}

// runSignalsMode is --signals run alone.
func runSignalsMode(path, after, ownerKeyFiles string, asJSON, allowPartial bool) int {
	point, pointErr := parseSignalPoint(after)
	if pointErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify:", pointErr)
		return 2
	}
	var ownerKeys []string
	if ownerKeyFiles != "" {
		for _, file := range strings.Split(ownerKeyFiles, ",") {
			key := strings.TrimSpace(string(readFlagFile("owner-request-key", strings.TrimSpace(file))))
			if raw, decodeErr := base64.StdEncoding.DecodeString(key); decodeErr != nil || len(raw) != 32 {
				fmt.Fprintf(os.Stderr, "verdifax-verify: --owner-request-key: %s does not hold a base64 Ed25519 public key\n", strings.TrimSpace(file))
				return 2
			}
			ownerKeys = append(ownerKeys, key)
		}
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify: read --signals:", readErr)
		return 2
	}
	c := checkSignalFeedPinned(data, point, ownerKeys)
	if asJSON {
		encoded, _ := json.MarshalIndent(c, "", "  ")
		fmt.Println(string(encoded))
	} else {
		printSignalFeed(&c)
	}
	if !c.OK {
		return 1
	}
	if c.CommittedLater > 0 && !allowPartial {
		return 3
	}
	return 0
}

// printSignalFeed renders the human report.
func printSignalFeed(c *SignalFeedCheck) {
	fmt.Println("Verdifax signal feed verification")
	if !c.OK {
		fmt.Printf("  %-18s✗ FAILED · %s\n", "Signal feed:", c.Reason)
		return
	}
	if c.CommittedLater == 0 {
		fmt.Printf("  %-18s✓ events %d to %d of %s, each entry on the public log, linked without a gap\n", "Signal feed:", c.First, c.Last, c.Account)
	} else {
		fmt.Printf("  %-18s◐ events %d to %d of %s, linked without a gap; %d carry no public-log entry of their own\n", "Signal feed:", c.First, c.Last, c.Account, c.CommittedLater)
		fmt.Println("                    Each is committed by a later event's entry, so it cannot have been changed since,")
		fmt.Println("                    but its time is proven only by that later entry, not by its own clock")
	}
	switch c.ContinuityFrom {
	case "start":
		fmt.Println("                    Checked from the account's first event")
	case "given point":
		fmt.Println("                    Checked from the point given with --signals-after")
	default:
		fmt.Printf("                    Not checked before event %d: pass --signals-after with the last event you read\n", c.First)
	}
	for _, e := range c.Entries {
		run := ""
		if e.RunID != 0 {
			run = " run " + strconv.FormatInt(e.RunID, 10)
		}
		late := ""
		if e.CommittedBy != 0 {
			late = fmt.Sprintf("  (no log entry of its own; committed by event %d)", e.CommittedBy)
		}
		by := ""
		if e.DecidedBy == artifacts.PublicationByVerdifax {
			by = " by a Verdifax admin key"
		}
		if e.GapChain != "" {
			by = fmt.Sprintf(": after a restore from backup, the %s chain skips places %d to %d, which may hold entries the restore lost",
				e.GapChain, e.GapFrom, e.GapTo)
		}
		if e.Change != "" && artifacts.IsRequestKeyAction(e.Change) {
			by += fmt.Sprintf(": %s for key %d", e.Change, e.KeyID)
		}
		if e.Change == artifacts.AccountWebhookSubscribed || e.Change == artifacts.AccountWebhookDeleted {
			by += fmt.Sprintf(": %s, %s", e.Change, e.Value)
		}
		if e.RecordDeletedBy != "" {
			// Round 61, N25: the event reads at its own time, and names the
			// tombstone that stands for its deleted record.
			by += fmt.Sprintf(", record deleted by %s, tombstone at event %d", deciderName(e.RecordDeletedBy), e.TombstoneSequence)
		}
		fmt.Printf("    %d. %s  %s%s%s%s\n", e.Sequence, e.At, e.Kind, run, by, late)
	}
	if c.DeclaredGaps > 0 {
		fmt.Printf("  %-18s%d declared restore gap(s): each is sealed and on the public log, and names the places it skips\n", "Restore gaps:", c.DeclaredGaps)
	}
	if c.CompleteAsOf != "" {
		fmt.Printf("  %-18sthe feed is complete as of %s, %s, by Verdifax's head statement on the public log\n", "Complete:", c.CompleteAsOf, c.CompleteAge)
	} else {
		fmt.Printf("  %-18sthe feed given ends with no head statement, so a later event may exist\n", "Complete:")
	}
	if len(c.OwnerBlocks) > 0 {
		var blocks []string
		for _, action := range []string{artifacts.AccountSettingOwnerReplace, artifacts.AccountSettingVerdifaxDelete} {
			if v, ok := c.OwnerBlocks[action]; ok {
				blocks = append(blocks, action+" "+v)
			}
		}
		if c.BlocksHeldAsOf != "" {
			fmt.Printf("  %-18sthe owner's blocks held as of %s (%s)\n", "Owner's blocks:", c.BlocksHeldAsOf, strings.Join(blocks, ", "))
		} else {
			fmt.Printf("  %-18sthe owner's blocks held through event %d (%s); with no head statement a later event may exist\n", "Owner's blocks:", c.Last, strings.Join(blocks, ", "))
		}
	}
	if c.WebhookChanges > 0 {
		switch {
		case c.ContinuityFrom != "start":
			fmt.Printf("  %-18s%d change(s) in this part of the feed; read it from its start to list the subscriptions in place\n", "Webhooks:", c.WebhookChanges)
		case len(c.Webhooks) == 0:
			fmt.Printf("  %-18snone in place at the end of the feed, after %d change(s)\n", "Webhooks:", c.WebhookChanges)
		default:
			fmt.Printf("  %-18s%d in place at the end of the feed: %s\n", "Webhooks:", len(c.Webhooks), strings.Join(c.Webhooks, "; "))
		}
	}
	for _, u := range c.UnconfirmedOwnerChanges {
		what := u.Kind
		if u.Action != "" {
			what = u.Action + " " + u.Value
		}
		fmt.Printf("  %-18sevent %d, %s, signed by %s, a key registered after %s at event %d; not counted as the owner's without --owner-request-key\n",
			"Unconfirmed:", u.Sequence, what, truncate(u.SignedBy, 12), u.FreshStart, u.FreshStartAt)
	}
	for _, ch := range c.RequestKeyChains {
		who := "key"
		if ch.OwnerKey {
			who = "owner key"
		}
		state := "holds " + truncate(ch.Current, 12)
		if ch.Current == "" {
			state = "holds none"
		}
		from := "followed from its registration"
		if ch.Unrooted {
			from = "followed from a key registered before this feed"
		}
		if ch.ClearedByVerdifax > 0 {
			from += fmt.Sprintf(", cleared by Verdifax at event %d", ch.ClearedByVerdifax)
		}
		fmt.Printf("  %-18s%s %d: %d change(s), %s, each replacement approved by the key before it; %s\n", "Request keys:", who, ch.KeyID, len(ch.Events), from, state)
	}
	for _, n := range c.Notes {
		fmt.Printf("  %-18s%s\n", "Note:", n)
	}
	fmt.Printf("  %-18s%d:%s\n", "Next point:", c.Last, c.LastEventHash)
	fmt.Println("                    The feed shows the signals Verdifax recorded for this account; it cannot show one it never recorded")
}
