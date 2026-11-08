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
	At       string `json:"at"`
	LogEntry string `json:"log_entry_id"`
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
	Reason         string `json:"reason,omitempty"`
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
		if !rep.AllPassed || rep.VerdictTier != "VERIFIED_ANCHORED" {
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
		return checkedEntry{hash: rep.ReceiptHash, at: rep.ReceiptClock, logEntry: rep.AnchorLogEntry, link: ctx.Signal, runID: doc.RunID}, nil
	case artifacts.SignalPolicyChanged:
		var a artifacts.PolicyActivation
		if decodeErr := strictDecode(e.Entry, &a); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not a policy change: %w", decodeErr)
		}
		if a.Signal == nil {
			return checkedEntry{}, errors.New("its policy change seals no place in the feed")
		}
		if checkErr := checkPolicyChangeAlone(&a); checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its policy change: %w", checkErr)
		}
		return checkedEntry{hash: a.ActivationHash, at: a.ActivatedAt, logEntry: a.Anchor.LogEntryID, link: a.Signal}, nil
	case artifacts.SignalSignOffRecorded:
		var s artifacts.SignOff
		if decodeErr := strictDecode(e.Entry, &s); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not a sign-off: %w", decodeErr)
		}
		if s.Signal == nil {
			return checkedEntry{}, errors.New("its sign-off seals no place in the feed")
		}
		if checkErr := checkOneSignOff(&s); checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its sign-off: %w", checkErr)
		}
		return checkedEntry{hash: s.SignOffHash, at: s.RecordedAt, logEntry: s.Anchor.LogEntryID, link: s.Signal, runID: s.Target.RunID}, nil
	case artifacts.SignalApproverRegistered, artifacts.SignalApproverRevoked, artifacts.SignalKeyCreated, artifacts.SignalKeyRevoked:
		var k artifacts.KeyChange
		if decodeErr := strictDecode(e.Entry, &k); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not a key change: %w", decodeErr)
		}
		if checkErr := checkKeyChange(&k); checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its key change: %w", checkErr)
		}
		if k.Action != e.Kind {
			return checkedEntry{}, fmt.Errorf("it is a %s event, and its key change is a %s", e.Kind, k.Action)
		}
		link := k.Signal
		return checkedEntry{hash: k.KeyChangeHash, at: k.ChangedAt, logEntry: k.Anchor.LogEntryID, link: &link}, nil
	case artifacts.SignalRunPublished, artifacts.SignalRunUnpublished:
		var p artifacts.RunPublication
		if decodeErr := strictDecode(e.Entry, &p); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not a run publication: %w", decodeErr)
		}
		if checkErr := checkRunPublication(&p); checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its run publication: %w", checkErr)
		}
		if p.Action != e.Kind {
			return checkedEntry{}, fmt.Errorf("it is a %s event, and its publication is a %s", e.Kind, p.Action)
		}
		if e.RunID != p.RunID {
			return checkedEntry{}, fmt.Errorf("it names run %d, and its publication is run %d's", e.RunID, p.RunID)
		}
		link := p.Signal
		return checkedEntry{hash: p.PublicationHash, at: p.ChangedAt, logEntry: p.Anchor.LogEntryID, link: &link, runID: p.RunID}, nil
	}
	return checkedEntry{}, fmt.Errorf("its kind %q is not one the feed emits", safePrefix(e.Kind))
}

// checkRunPublication checks one run publication: its shape, hash and
// public-log entry. The record it names is checked by its own record; the
// publication shows the owner's decision about it and when.
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
	case events[0].Data.Sequence == 1:
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
		if previousHash != "" {
			if d.Sequence != previousSeq+1 {
				return fail("it follows event %d, so an event is missing or out of order", previousSeq)
			}
			if d.PreviousSignalHash != previousHash {
				return fail("it does not name the event before it, so an event was removed, reordered or rewritten")
			}
		}
		got, entryErr := checkSignalEntry(d)
		if entryErr != nil {
			return fail("%v", entryErr)
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
		c.Entries = append(c.Entries, SignalFeedEntry{Sequence: d.Sequence, Kind: d.Kind, RunID: d.RunID, At: got.at, LogEntry: got.logEntry})
		previousSeq, previousHash = d.Sequence, d.EventHash
	}
	c.First, c.Last, c.LastEventHash = events[0].Data.Sequence, previousSeq, previousHash
	c.OK = true
	return c
}

// runSignalsMode is --signals run alone.
func runSignalsMode(path, after string, asJSON bool) int {
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
	return 0
}

// printSignalFeed renders the human report.
func printSignalFeed(c *SignalFeedCheck) {
	fmt.Println("Verdifax signal feed verification")
	if !c.OK {
		fmt.Printf("  %-18s✗ FAILED · %s\n", "Signal feed:", c.Reason)
		return
	}
	fmt.Printf("  %-18s✓ events %d to %d of %s, each entry on the public log, linked without a gap\n", "Signal feed:", c.First, c.Last, c.Account)
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
		fmt.Printf("    %d. %s  %s%s\n", e.Sequence, e.At, e.Kind, run)
	}
	fmt.Printf("  %-18s%d:%s\n", "Next point:", c.Last, c.LastEventHash)
	fmt.Println("                    The feed shows the signals Verdifax recorded for this account; it cannot show one it never recorded")
}
