package main

// Round 64 in the signal feed (v0.38.0, part 1): setup changes, review dates
// and the rule in force.
//
// setup.changed (record verdifax.setup-change.v1): under a policy's setup
// watch, a run whose setup fingerprint differs from the last one the watch
// saw in its scope is preceded in the feed by a sealed setup change. --signals
// checks each record as its own kind, that it is followed at once by the run
// it names (the run's record or receipt, whose sealed setup_hash is the new
// fingerprint), that each previous_setup_hash is the setup_hash of the scope's
// change before it, and that every counted run's fingerprint is one the feed
// shows. The record states what the request declared and what Verdifax's AI
// review stated about itself; it never says which model ran.
//
// review.due (record verdifax.policy-review-due.v1): when the review date a
// policy declares passes while one of its activations is in force, Verdifax
// seals one review.due for that activation. --signals checks each record, that
// it names an activation the feed shows as it is, that it was logged at or
// after its due time, and, with the policy documents given by
// --signals-policy, that its declaration is the policy's own; a feed whose
// head is past a due date its policy declares, with no review.due for that
// activation, fails. A review.due says only that the declared date passed; it
// says nothing about whether anyone reviewed the policy.
//
// Rule in force: an attestation-gap receipt that seals the policy change it
// was made under must name the change of its chain in force when it was made.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/policyhash"
)

// reviewDueGrace is how long after a due date the feed may still lack its
// review.due: the server's sweep runs once a minute (reviewSweepEvery,
// verdifax-orchestrator internal/api/review_due.go) and the record is then
// anchored within the receipt anchoring window.
const reviewDueGrace = time.Minute + time.Duration(artifacts.ReceiptAnchoringWindowSeconds)*time.Second

// isReadSignalKind reports a feed kind this verifier reads: every kind the
// feed emitted before round 64 and every round 64 kind (v0.38.0): setup and
// review dates (part 1), and account stops, sign-offs refused during a stop
// and passed response targets (part 2). A kind outside both lists is
// refused, as any kind this release does not read.
func isReadSignalKind(kind string) bool {
	return artifacts.IsSignalKind(kind) || artifacts.IsStagedSignalKind(kind)
}

// feedActivation is one policy change the feed shows.
type feedActivation struct {
	a       artifacts.PolicyActivation
	feedSeq int64
	// replacedAt is the activation time of the next change of the same
	// chain the feed shows, zero while none follows.
	replacedAt time.Time
	replacedBy int64
	// dueAt is the review date its policy declares, from a document given
	// with --signals-policy; zero when none is declared or none was given.
	dueAt       time.Time
	documentSet bool
	reviewBy    string
	interval    int
	reviewDue   int64
}

// round64Feed follows the round 64 facts through one feed.
type round64Feed struct {
	documents map[string][]byte
	used      map[string]bool
	fromStart bool
	// activations by hash, and the latest of each chain.
	activations map[string]*feedActivation
	latest      map[string]*feedActivation
	order       []*feedActivation
	// setup is each scope's last fingerprint the feed shows, and known
	// whether the feed shows the scope from its first setup.
	setup   map[string]string
	pending *artifacts.SetupChange
	// round64Seen is whether the feed carries any round 64 fact.
	round64Seen bool
	changes     int
	reviews     int
	notes       []string
}

func newRound64Feed(documents map[string][]byte, fromStart bool) *round64Feed {
	return &round64Feed{documents: documents, used: map[string]bool{}, fromStart: fromStart,
		activations: map[string]*feedActivation{}, latest: map[string]*feedActivation{}, setup: map[string]string{}}
}

// readFeedPolicies reads --signals-policy: policy documents by the SHA-256 of
// their exact text, the document_hash a policy change seals.
func readFeedPolicies(files string) (map[string][]byte, error) {
	out := map[string][]byte{}
	if files == "" {
		return out, nil
	}
	for _, file := range strings.Split(files, ",") {
		doc, readErr := os.ReadFile(strings.TrimSpace(file))
		if readErr != nil {
			return nil, fmt.Errorf("--signals-policy: %w", readErr)
		}
		if _, docErr := policyhash.FromDocument(doc); docErr != nil {
			return nil, fmt.Errorf("--signals-policy: %s is not a policy this verifier reads: %w", strings.TrimSpace(file), docErr)
		}
		sum := sha256.Sum256(doc)
		out[hex.EncodeToString(sum[:])] = doc
	}
	return out, nil
}

// event applies one checked event, in feed order. It returns a failure, or "".
func (f *round64Feed) event(kind string, seq int64, got *checkedEntry) string {
	if p := f.pending; p != nil {
		f.pending = nil
		if why := setupChangeFollowedBy(p, kind, got); why != "" {
			return why
		}
	}
	switch {
	case got.activation != nil:
		return f.activation(seq, got.activation)
	case got.setupChange != nil:
		return f.setupChange(seq, got.setupChange)
	case got.reviewDue != nil:
		return f.reviewDue(seq, got.reviewDue)
	case got.gap != nil && got.gap.Chain == artifacts.GapChainSignals:
		// A restore from backup may also have restored the server's setup
		// state; the feed shows the scopes afresh after it.
		f.setup = map[string]string{}
		f.fromStart = false
	}
	if got.setupHash != "" {
		f.round64Seen = true
		if why := f.countedRun(got); why != "" {
			return why
		}
	}
	if got.gapActivation != "" {
		f.round64Seen = true
		return f.ruleInForce(got)
	}
	return ""
}

func (f *round64Feed) activation(seq int64, a *artifacts.PolicyActivation) string {
	fa := &feedActivation{a: *a, feedSeq: seq}
	at, _ := time.Parse(time.RFC3339Nano, a.ActivatedAt)
	if prev := f.latest[a.ChainID]; prev != nil {
		prev.replacedAt, prev.replacedBy = at, seq
	}
	if doc, given := f.documents[a.DocumentHash]; given {
		f.used[a.DocumentHash] = true
		got, docErr := policyhash.FromDocument(doc)
		if docErr != nil || got.PolicyHash != a.PolicyHash {
			return fmt.Sprintf("the policy document given with --signals-policy for this policy change hashes to policy %s, and the change puts policy %s in force", truncate(got.PolicyHash, 16), truncate(a.PolicyHash, 16))
		}
		by, days, declared, reviewErr := policyhash.ReviewDeclaration(doc)
		if reviewErr != nil {
			return fmt.Sprintf("the policy document given with --signals-policy for this policy change: %v", reviewErr)
		}
		fa.documentSet, fa.reviewBy, fa.interval = true, by, days
		if declared {
			due, dueErr := artifacts.ReviewDueAt(by, days, a.ActivatedAt)
			if dueErr != nil {
				return fmt.Sprintf("the review date its policy declares: %v", dueErr)
			}
			fa.dueAt, _ = time.Parse(time.RFC3339Nano, due)
			f.round64Seen = true
		}
	}
	f.activations[a.ActivationHash], f.latest[a.ChainID] = fa, fa
	f.order = append(f.order, fa)
	return ""
}

// inForce checks that the activation a record names is the latest of its
// chain the feed shows at this point; one the feed does not show is noted.
func (f *round64Feed) inForce(what, activation string) string {
	fa, shown := f.activations[activation]
	if !shown {
		f.notes = append(f.notes, fmt.Sprintf("%s names policy change %s, which this part of the feed does not show; check it with the policy history.", what, truncate(activation, 16)))
		return ""
	}
	if latest := f.latest[fa.a.ChainID]; latest != fa {
		return fmt.Sprintf("%s names change %d of %s as the policy in force, and change %d (event %d) had already replaced it", what, fa.a.Sequence, fa.a.ChainID, latest.a.Sequence, latest.feedSeq)
	}
	return ""
}

func (f *round64Feed) setupChange(seq int64, c *artifacts.SetupChange) string {
	f.round64Seen = true
	f.changes++
	if why := f.inForce("the setup change", c.ActivationHash); why != "" {
		return why
	}
	last, seen := f.setup[c.Scope]
	switch {
	case seen && c.PreviousSetupHash != last:
		return fmt.Sprintf("its setup change in scope %s names previous fingerprint %s, and the scope's change before it set %s", c.Scope, orNone(truncate(c.PreviousSetupHash, 16)), truncate(last, 16))
	case !seen && f.fromStart && c.PreviousSetupHash != "":
		return fmt.Sprintf("its setup change is the first in scope %s in a feed read from its start, and names previous fingerprint %s, which no change in the feed set", c.Scope, truncate(c.PreviousSetupHash, 16))
	}
	f.setup[c.Scope] = c.SetupHash
	f.pending = c
	return ""
}

// setupChangeFollowedBy holds a setup change to the run event after it: the
// server stores the change and the run's own event together, the change
// first, so the next event is the run's record or receipt, with the new
// fingerprint.
func setupChangeFollowedBy(c *artifacts.SetupChange, kind string, got *checkedEntry) string {
	wantKind := artifacts.SignalRunSealed
	if c.RecordKind != artifacts.SetupRecordKindRecord {
		wantKind = receiptSignalKind(c.RecordKind)
	}
	switch {
	case kind != wantKind || got.runID != c.RunID || got.recordHash != c.RecordHash:
		return fmt.Sprintf("the setup change before it names run %d's %s, and this event is not that run's event", c.RunID, c.RecordKind)
	case c.RecordKind != artifacts.SetupRecordKindRecord && got.receiptKind != c.RecordKind:
		return fmt.Sprintf("the setup change before it names a %s, and this event's receipt is a %s", c.RecordKind, got.receiptKind)
	case got.setupHash != c.SetupHash:
		return fmt.Sprintf("the setup change before it sets fingerprint %s, and the run's own entry seals %s", truncate(c.SetupHash, 16), orNone(truncate(got.setupHash, 16)))
	}
	return ""
}

// countedRun holds a counted run's fingerprint to a setup the feed shows.
func (f *round64Feed) countedRun(got *checkedEntry) string {
	for _, h := range f.setup {
		if h == got.setupHash {
			return ""
		}
	}
	if f.fromStart {
		return fmt.Sprintf("its run seals setup fingerprint %s, and no setup change in the feed set it", truncate(got.setupHash, 16))
	}
	return ""
}

func (f *round64Feed) ruleInForce(got *checkedEntry) string {
	fa, shown := f.activations[got.gapActivation]
	if shown && got.gapClock != "" {
		clock, clockErr := time.Parse(time.RFC3339Nano, got.gapClock)
		at, _ := time.Parse(time.RFC3339Nano, fa.a.ActivatedAt)
		if clockErr == nil && clock.Before(at) {
			return fmt.Sprintf("its refusal for missing fields is dated %s, before change %d it names as the rule in force was activated", got.gapClock, fa.a.Sequence)
		}
	}
	return f.inForce("its refusal for missing fields", got.gapActivation)
}

func (f *round64Feed) reviewDue(seq int64, r *artifacts.ReviewDue) string {
	f.round64Seen = true
	f.reviews++
	fa, shown := f.activations[r.ActivationHash]
	if !shown {
		f.notes = append(f.notes, fmt.Sprintf("event %d, review.due, names policy change %s, which this part of the feed does not show; check it with the policy history.", seq, truncate(r.ActivationHash, 16)))
		return ""
	}
	a := fa.a
	switch {
	case r.ChainID != a.ChainID || r.ActivationSequence != a.Sequence || r.DocumentHash != a.DocumentHash || r.ActivatedAt != a.ActivatedAt:
		return fmt.Sprintf("its review date names change %d of %s, and does not repeat that change as the feed shows it", r.ActivationSequence, r.ChainID)
	case fa.reviewDue != 0:
		return fmt.Sprintf("it is a second review.due for change %d of %s, after event %d; one is sealed per activation", a.Sequence, a.ChainID, fa.reviewDue)
	}
	due, _ := time.Parse(time.RFC3339Nano, r.DueAt)
	if r.Anchor != nil && r.Anchor.IntegratedTime < due.Unix() {
		return fmt.Sprintf("its review date record was logged at %s, before the due date %s it says has passed", time.Unix(r.Anchor.IntegratedTime, 0).UTC().Format(time.RFC3339), r.DueAt)
	}
	if !fa.replacedAt.IsZero() && !fa.replacedAt.After(due) {
		return fmt.Sprintf("its review date %s is for change %d of %s, which change %d replaced before that date, so it was not in force when the date passed", r.DueAt, a.Sequence, a.ChainID, f.activationAt(fa.replacedBy))
	}
	if fa.documentSet && (fa.dueAt.IsZero() || r.ReviewBy != fa.reviewBy || r.IntervalDays != fa.interval) {
		return fmt.Sprintf("its review date declaration (%s) is not the one the policy document given for change %d declares", reviewDeclarationText(r.ReviewBy, r.IntervalDays), a.Sequence)
	}
	fa.reviewDue = seq
	return ""
}

// activationAt names the change at a feed place, for a message.
func (f *round64Feed) activationAt(seq int64) int64 {
	for _, fa := range f.order {
		if fa.feedSeq == seq {
			return fa.a.Sequence
		}
	}
	return 0
}

// finish checks what only the whole feed shows: a setup change waiting for its
// run, and, once Verdifax's head statement says the feed is complete as of a
// time, every declared review date passed by then with no review.due.
func (f *round64Feed) finish(headAt int64, haveHead bool) string {
	if f.pending != nil {
		if haveHead {
			return fmt.Sprintf("the feed ends with a setup change for run %d, and Verdifax's head statement says it is complete, so the run's own event is missing", f.pending.RunID)
		}
		f.notes = append(f.notes, fmt.Sprintf("the feed ends with a setup change for run %d; the run's own event follows it in the next page.", f.pending.RunID))
	}
	for _, fa := range f.order {
		if fa.dueAt.IsZero() || fa.reviewDue != 0 {
			continue
		}
		if !fa.replacedAt.IsZero() && !fa.replacedAt.After(fa.dueAt) {
			continue
		}
		switch {
		case haveHead && time.Unix(headAt, 0).After(fa.dueAt.Add(reviewDueGrace)):
			return fmt.Sprintf("the policy put in force by change %d of %s (event %d) declares a review date, %s, and the feed, complete as of %s, holds no review.due for it",
				fa.a.Sequence, fa.a.ChainID, fa.feedSeq, fa.dueAt.UTC().Format(time.RFC3339Nano), time.Unix(headAt, 0).UTC().Format(time.RFC3339))
		case !haveHead:
			f.notes = append(f.notes, fmt.Sprintf("change %d of %s declares a review date, %s; with no head statement the feed cannot show whether its review.due is missing.",
				fa.a.Sequence, fa.a.ChainID, fa.dueAt.UTC().Format(time.RFC3339Nano)))
		}
	}
	if f.round64Seen || len(f.documents) > 0 {
		unread := 0
		for _, fa := range f.order {
			if !fa.documentSet {
				unread++
			}
		}
		if unread > 0 {
			f.notes = append(f.notes, fmt.Sprintf("%d policy change(s) in the feed were not checked for a review date: give their policy documents with --signals-policy.", unread))
		}
		for hash := range f.documents {
			if !f.used[hash] {
				f.notes = append(f.notes, fmt.Sprintf("a document given with --signals-policy (text hash %s) is not put in force by any change in this feed.", truncate(hash, 16)))
			}
		}
	}
	return ""
}

// reviewDeclarationText says a review declaration in plain words.
func reviewDeclarationText(reviewBy string, intervalDays int) string {
	if reviewBy != "" {
		return "review_by " + reviewBy
	}
	return fmt.Sprintf("interval_days %d", intervalDays)
}

// setupStatement says what a setup change shows, in plain words: what the
// request declared and what Verdifax's AI review stated, never which model
// ran.
func setupStatement(c *artifacts.SetupChange) string {
	var declared, stated []string
	for _, fact := range c.Fields {
		value := c.Setup.Fact(fact)
		text := "nothing"
		if value != "" {
			text = fmt.Sprintf("%q", value)
		}
		if artifacts.SetupFactStatedBy(fact) == artifacts.SetupStatedByCaller {
			declared = append(declared, fact+" "+text)
		} else {
			stated = append(stated, fact+" "+text)
		}
	}
	var parts []string
	if len(declared) > 0 {
		parts = append(parts, "the request declared "+strings.Join(declared, ", "))
	}
	if len(stated) > 0 {
		parts = append(parts, "Verdifax's AI review stated "+strings.Join(stated, ", "))
	}
	from := "the first setup the watch saw in scope " + c.Scope
	if c.PreviousSetupHash != "" {
		from = "changed from " + truncate(c.PreviousSetupHash, 12) + " in scope " + c.Scope
	}
	return strings.Join(parts, "; ") + " (" + from + ")"
}
