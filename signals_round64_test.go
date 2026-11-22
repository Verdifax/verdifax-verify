package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/policyhash"
)

// The round 64 feed: a policy change whose policy declares a review date, two
// setup changes each followed by its run, a run with an unchanged setup, and
// the review date's record.

var feedReviewBy = feedStart.Add(2*time.Minute + 30*time.Second)

// feedRound64Policy is a policy declaring a review date between the feed's
// second and fourth events.
var feedRound64Policy = strings.Replace(strings.Replace(round64Policy, `"effective_at":"2026-11-17T00:00:00Z"`, `"effective_at":"2026-11-01T00:00:00Z"`, 1),
	`"default_effect":"deny",`, `"default_effect":"deny","review":{"review_by":"`+feedReviewBy.Format(time.RFC3339)+`"},`, 1)

func feedRound64Documents(t *testing.T) map[string][]byte {
	t.Helper()
	docs := map[string][]byte{}
	sum := sha256.Sum256([]byte(feedRound64Policy))
	docs[hex.EncodeToString(sum[:])] = []byte(feedRound64Policy)
	return docs
}

// activationOf adds a policy change of the account's chain putting doc in force.
func (f *feedBuilder) activationOf(doc string, sequence int64, previous string) artifacts.PolicyActivation {
	link, at := f.next()
	sum := sha256.Sum256([]byte(doc))
	a := artifacts.PolicyActivation{Format: artifacts.PolicyActivationFormat, ChainID: feedAccount, Sequence: sequence,
		PreviousActivationHash: previous, PolicyID: "r64-claims", PolicyVersion: "1", PolicyHash: strings.Repeat("4", 64),
		DocumentHash: hex.EncodeToString(sum[:]), ActivatedAt: at.Format(time.RFC3339Nano), Signal: &link}
	if got, err := policyHashOf(doc); err == nil {
		a.PolicyHash = got
	}
	a.ActivationHash = a.ComputeHash()
	a.Anchor = f.anchor(artifacts.PolicyActivationKind, a.ActivationHash, a.LeafHash(), at)
	f.add(artifacts.SignalPolicyChanged, link, a.ActivationHash, 0, a)
	return a
}

// setupChangeFor adds a setup change for the next run, whose record hash is
// recordHash; it returns the new fingerprint.
func (f *feedBuilder) setupChangeFor(activation, previous, model string, mutate func(*artifacts.SetupChange)) string {
	link, at := f.next()
	c := artifacts.SetupChange{Format: artifacts.SetupChangeFormat, RunID: f.runID + 1, RecordKind: artifacts.SetupRecordKindRecord,
		RecordHash: strings.Repeat("7", 64), Scope: "account", ActivationHash: activation, Fields: []string{"model_name", "review_prompt_id"},
		PreviousSetupHash: previous,
		Setup: artifacts.SetupFacts{DeclaredByCaller: &artifacts.DeclaredSetup{ModelName: model},
			AttestedByVerdifax: &artifacts.AttestedSetup{ReviewPromptID: "statements-v1"}},
		ChangedAt: at.Format(time.RFC3339Nano), Signal: link}
	c.SetupHash = artifacts.SetupHash(c.Fields, &c.Setup)
	if mutate != nil {
		mutate(&c)
	}
	c.SetupChangeHash = c.ComputeHash()
	c.Anchor = f.anchor(artifacts.SetupChangeKind, c.SetupChangeHash, c.LeafHash(), at)
	f.add(artifacts.SignalSetupChanged, link, c.SetupChangeHash, c.RunID, c)
	return c.SetupHash
}

// runSealedWithSetup adds a counted run's event carrying its fingerprint.
func (f *feedBuilder) runSealedWithSetup(setupHash string) {
	link, at := f.next()
	f.runID++
	r := artifacts.RunSealed{Format: artifacts.RunSealedFormat, RunID: f.runID, RecordHash: strings.Repeat("7", 64),
		SealedAt: at.Format(time.RFC3339Nano), Signal: link, SetupHash: setupHash}
	r.RunSealedHash = r.ComputeHash()
	r.Anchor = f.anchor(artifacts.RunSealedKind, r.RunSealedHash, r.LeafHash(), at)
	f.add(artifacts.SignalRunSealed, link, r.RunSealedHash, f.runID, r)
}

// reviewDueFor adds the review date's record of an activation.
func (f *feedBuilder) reviewDueFor(a artifacts.PolicyActivation, mutate func(*artifacts.ReviewDue), anchorShift time.Duration) {
	link, at := f.next()
	r := artifacts.ReviewDue{Format: artifacts.ReviewDueFormat, ChainID: a.ChainID, ActivationSequence: a.Sequence,
		ActivationHash: a.ActivationHash, DocumentHash: a.DocumentHash, ActivatedAt: a.ActivatedAt,
		ReviewBy: feedReviewBy.Format(time.RFC3339), Statement: artifacts.ReviewDueStatement(a.Sequence),
		StatedAt: at.Format(time.RFC3339Nano), Signal: link}
	r.DueAt, _ = artifacts.ReviewDueAt(r.ReviewBy, 0, r.ActivatedAt)
	if mutate != nil {
		mutate(&r)
	}
	r.ReviewDueHash = r.ComputeHash()
	r.Anchor = f.anchor(artifacts.ReviewDueKind, r.ReviewDueHash, r.LeafHash(), at.Add(anchorShift))
	f.add(artifacts.SignalReviewDue, link, r.ReviewDueHash, 0, r)
}

// headAt makes Verdifax's head statement for the feed so far, stated at.
func (f *feedBuilder) headAt(at time.Time) *artifacts.FeedHead {
	last := f.events[len(f.events)-1].Data
	h := &artifacts.FeedHead{Format: artifacts.FeedHeadFormat, Account: feedAccount, Sequence: last.Sequence, HeadHash: last.EventHash,
		StatedAt: at.Format(time.RFC3339Nano)}
	h.HeadStatementHash = h.ComputeHash()
	h.Anchor = f.anchor(artifacts.FeedHeadKind, h.HeadStatementHash, h.LeafHash(), at)
	return h
}

// feedRound64Options are the breaks one test feed can carry.
type feedRound64Options struct {
	noReviewDue, secondReviewDue, wrongPrevious, runDiffers, unknownRun, earlyAnchor, replaced bool
}

func buildRound64Feed(t *testing.T, o feedRound64Options) []byte {
	t.Helper()
	f := newFeedBuilder(t)
	a := f.activationOf(feedRound64Policy, 1, artifacts.NoPreviousActivation)
	if o.replaced {
		f.activationOf(feedRound64Policy, 2, a.ActivationHash)
	}
	first := f.setupChangeFor(a.ActivationHash, "", "claims-model-2", nil)
	if o.replaced {
		// The watching policy named is the replaced one.
		first = artifacts.SetupHash([]string{"model_name", "review_prompt_id"}, &artifacts.SetupFacts{})
	}
	f.runSealedWithSetup(first)
	if !o.noReviewDue && !o.replaced {
		shift := 20 * time.Second
		var mutate func(*artifacts.ReviewDue)
		if o.earlyAnchor {
			// Stated at its due time, logged two minutes before it.
			mutate = func(r *artifacts.ReviewDue) { r.StatedAt = r.DueAt }
			shift = -2*time.Minute - 50*time.Second
		}
		f.reviewDueFor(a, mutate, shift)
		if o.secondReviewDue {
			f.reviewDueFor(a, nil, 20*time.Second)
		}
	}
	previous := first
	if o.wrongPrevious {
		previous = strings.Repeat("c", 64)
	}
	second := f.setupChangeFor(a.ActivationHash, previous, "claims-model-3", nil)
	if o.runDiffers {
		f.runSealedWithSetup(first)
	} else {
		f.runSealedWithSetup(second)
	}
	if o.unknownRun {
		f.runSealedWithSetup(strings.Repeat("d", 64))
	} else {
		f.runSealedWithSetup(second)
	}
	headTime := feedStart.Add(time.Hour)
	before := checkClock
	checkClock = func() time.Time { return headTime.Add(time.Minute) }
	t.Cleanup(func() { checkClock = before })
	return pageWithHead(t, f.events, f.headAt(headTime))
}

// policyHashOf is the policy hash of a document, as the verifier reads it.
func policyHashOf(doc string) (string, error) {
	got, err := policyhash.FromDocument([]byte(doc))
	return got.PolicyHash, err
}

// R316: a feed with setup changes and a review date verifies, says what was
// declared and stated, and never which model ran.
func TestARound64FeedVerifies(t *testing.T) {
	c := checkSignalFeedWith(buildRound64Feed(t, feedRound64Options{}), nil, nil, feedRound64Documents(t))
	if !c.OK {
		t.Fatalf("a sound feed fails: %s", c.Reason)
	}
	if c.SetupChanges != 2 || c.ReviewsDue != 1 {
		t.Fatalf("setup changes %d, reviews due %d", c.SetupChanges, c.ReviewsDue)
	}
	setup := c.Entries[1].Setup
	if !strings.Contains(setup, `the request declared model_name "claims-model-2"; Verdifax's AI review stated review_prompt_id "statements-v1"`) ||
		strings.Contains(setup, "ran") {
		t.Fatalf("setup line %q", setup)
	}
	if due := c.Entries[3].ReviewDue; !strings.Contains(due, "says nothing about whether anyone reviewed the policy") {
		t.Fatalf("review line %q", due)
	}
	// Without the policy document the review date is checked against the
	// record's own declaration only, and the report says how to check more.
	c = checkSignalFeedWith(buildRound64Feed(t, feedRound64Options{noReviewDue: true}), nil, nil, nil)
	if !c.OK || !strings.Contains(strings.Join(c.Notes, " "), "--signals-policy") {
		t.Fatalf("without documents: %s %v", c.Reason, c.Notes)
	}
}

// R316: each break of a setup change's chain, of its run, of a review date or
// of the rule in force fails the feed.
func TestABrokenRound64FeedFails(t *testing.T) {
	for name, b := range map[string]struct {
		o    feedRound64Options
		want string
	}{
		"review date missing":       {feedRound64Options{noReviewDue: true}, "holds no review.due for it"},
		"review date sealed twice":  {feedRound64Options{secondReviewDue: true}, "second review.due"},
		"previous fingerprint":      {feedRound64Options{wrongPrevious: true}, "names previous fingerprint"},
		"run seals another setup":   {feedRound64Options{runDiffers: true}, "the run's own entry seals"},
		"run's setup never sealed":  {feedRound64Options{unknownRun: true}, "no setup change in the feed set it"},
		"logged before its due":     {feedRound64Options{earlyAnchor: true}, "before the due date"},
		"replaced activation named": {feedRound64Options{replaced: true}, "had already replaced it"},
	} {
		c := checkSignalFeedWith(buildRound64Feed(t, b.o), nil, nil, feedRound64Documents(t))
		if c.OK || !strings.Contains(c.Reason, b.want) {
			t.Errorf("%s: ok %v, reason %q, want %q", name, c.OK, c.Reason, b.want)
		}
	}
}

// R317, R340: every round 64 kind is read (part 2 adds the stop, refusal and
// target kinds), and a kind outside the feed's lists is still refused, as
// any kind this release does not read.
func TestEveryRound64KindIsReadAndAnUnknownOneRefused(t *testing.T) {
	for _, kind := range append(append([]string{}, artifacts.StagedSignalKinds...), artifacts.SignalKinds...) {
		if !isReadSignalKind(kind) {
			t.Errorf("%s must be read", kind)
		}
	}
	for _, kind := range []string{"account.paused", "signoff.late", ""} {
		if isReadSignalKind(kind) {
			t.Errorf("%q is read, and no feed emits it", kind)
		}
	}
}

// R314, in a feed: an attestation-gap receipt naming a replaced change as the
// rule in force fails.
func TestAGapReceiptInAFeedNamesTheChangeInForce(t *testing.T) {
	f := newRound64Feed(nil, true)
	a1 := artifacts.PolicyActivation{ChainID: feedAccount, Sequence: 1, ActivationHash: strings.Repeat("a", 64), ActivatedAt: "2026-11-17T10:00:00Z"}
	a2 := artifacts.PolicyActivation{ChainID: feedAccount, Sequence: 2, ActivationHash: strings.Repeat("b", 64), ActivatedAt: "2026-11-17T11:00:00Z"}
	f.event(artifacts.SignalPolicyChanged, 1, &checkedEntry{activation: &a1})
	if why := f.event(artifacts.SignalRunRefused, 2, &checkedEntry{gapActivation: a1.ActivationHash, gapClock: "2026-11-17T10:30:00Z"}); why != "" {
		t.Fatalf("the change in force: %s", why)
	}
	if why := f.event(artifacts.SignalRunRefused, 3, &checkedEntry{gapActivation: a1.ActivationHash, gapClock: "2026-11-17T09:30:00Z"}); why == "" {
		t.Fatal("a refusal dated before its change was activated must fail")
	}
	f.event(artifacts.SignalPolicyChanged, 4, &checkedEntry{activation: &a2})
	if why := f.event(artifacts.SignalRunRefused, 5, &checkedEntry{gapActivation: a1.ActivationHash, gapClock: "2026-11-17T11:30:00Z"}); why == "" {
		t.Fatal("a refusal naming a replaced change must fail")
	}
}
