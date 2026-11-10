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

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
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
}

// signalFeedPage is the body of GET /signals.
type signalFeedPage struct {
	Events    []signalCloudEvent `json:"events"`
	NextAfter int64              `json:"next_after"`
	Newest    int64              `json:"newest"`
}

// SignalFeedEntry is one checked event in the report.
type SignalFeedEntry struct {
	Sequence int64  `json:"sequence"`
	Kind     string `json:"kind"`
	RunID    int64  `json:"run_id,omitempty"`
	// DecidedBy, on a publication event, is who decided: owner, or
	// verdifax_admin when a Verdifax admin key withdrew the record (R160).
	DecidedBy string `json:"decided_by,omitempty"`
	At        string `json:"at"`
	LogEntry  string `json:"log_entry_id"`
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
	DeclaredGaps int    `json:"declared_gaps,omitempty"`
	Reason       string `json:"reason,omitempty"`
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
// unknown fields.
func decodeSignalEvents(data []byte) ([]signalCloudEvent, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var events []signalCloudEvent
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if decodeErr := dec.Decode(&events); decodeErr != nil {
			return nil, fmt.Errorf("the feed is not a list of signal events: %w", decodeErr)
		}
		return events, nil
	}
	var page signalFeedPage
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if decodeErr := dec.Decode(&page); decodeErr != nil {
		return nil, fmt.Errorf("the feed is not a GET /signals body: %w", decodeErr)
	}
	return page.Events, nil
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
func checkSignalEntry(e *signalEvent) (checkedEntry, error) {
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
		return checkedEntry{hash: k.KeyChangeHash, at: k.ChangedAt, logEntry: logEntryOf(k.Anchor), link: &link, unlogged: unlogged}, nil
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
	c := SignalFeedCheck{Checked: true}
	events, readErr := decodeSignalEvents(data)
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
			c.Entries = nil
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
		got, entryErr := checkSignalEntry(d)
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
		entry := SignalFeedEntry{Sequence: d.Sequence, Kind: d.Kind, RunID: d.RunID, DecidedBy: got.decidedBy, At: got.at, LogEntry: got.logEntry}
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
	c.OK = true
	return c
}

// runSignalsMode is --signals run alone.
func runSignalsMode(path, after string, asJSON, allowPartial bool) int {
	point, pointErr := parseSignalPoint(after)
	if pointErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify:", pointErr)
		return 2
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify: read --signals:", readErr)
		return 2
	}
	c := checkSignalFeed(data, point)
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
		fmt.Printf("    %d. %s  %s%s%s%s\n", e.Sequence, e.At, e.Kind, run, by, late)
	}
	if c.DeclaredGaps > 0 {
		fmt.Printf("  %-18s%d declared restore gap(s): each is sealed and on the public log, and names the places it skips\n", "Restore gaps:", c.DeclaredGaps)
	}
	fmt.Printf("  %-18s%d:%s\n", "Next point:", c.Last, c.LastEventHash)
	fmt.Println("                    The feed shows the signals Verdifax recorded for this account; it cannot show one it never recorded")
}
