package main

// Round 64, part 2 (v0.38.0): passed response targets in the signal feed.
//
// A customer's policy may declare how long a result waits for a sign-off
// (signoff.within on an allowing rule, response_targets for refused and
// halted runs). When its notice is event or both, Verdifax seals one
// signoff.target_passed (verdifax.signoff-target-passed.v1, leaf kind
// signoff_target) for a result whose deadline passed with no sign-off of the
// compared kind on the public log by then. --signals checks each record as
// its own kind and against the feed: it names an earlier result event of its
// own kind, run and hash; its start is that result's public-log time (or,
// for a result with none, its sealed record time); the target is the one the
// result sealed, when it sealed one; the record's own public-log time is at
// or after the deadline; no sign-off of the compared kind on that result was
// logged by the deadline; and one is sealed per result. The record states a
// time and the customer's own target; it judges neither.

import (
	"fmt"
	"strconv"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// feedResult is a result the feed shows: a run.sealed record, or a refused
// or halted run's receipt.
type feedResult struct {
	kind        string
	runID       int64
	hash        string
	logged      int64
	recordClock string
	target      *artifacts.SealedTarget
}

// feedSignOff is a sign-off the feed shows, with its public-log time.
type feedSignOff struct {
	sequence int64
	s        *artifacts.SignOff
}

// targetFeed follows results, sign-offs and passed targets through a feed.
type targetFeed struct {
	results  map[int64]*feedResult
	present  map[int64]string
	signOffs []feedSignOff
	passed   map[string]int64
	count    int
	notes    []string
}

func newTargetFeed() *targetFeed {
	return &targetFeed{results: map[int64]*feedResult{}, present: map[int64]string{}, passed: map[string]int64{}}
}

// resultKindOf is the result kind of a feed kind, or "".
func resultKindOf(kind string) string {
	switch kind {
	case artifacts.SignalRunSealed:
		return artifacts.TargetResultRecord
	case artifacts.SignalRunRefused, artifacts.SignalRunHalted:
		return artifacts.TargetResultReceipt
	}
	return ""
}

// signOffNames reports whether a sign-off names a result, by the one
// definition artifacts NamesResult holds: a receipt by a receipt sign-off, a
// record by a record or a job sign-off, on the same run. The feed does not
// carry the digest a record's sign-off covers (its bundle's anchored
// digest), so the match is by run and kind, as the server's target sweep
// and the counting rules make it.
func signOffNames(t artifacts.SignOffTarget, resultKind string, runID int64) bool {
	kind := artifacts.SignOffTargetRecord
	if resultKind == artifacts.TargetResultReceipt {
		kind = artifacts.SignOffTargetReceipt
	}
	return t.NamesResult(artifacts.SignOffResult{Kind: kind, RunID: runID, Digest: t.Digest})
}

// event applies one checked event, in feed order. It returns a failure, or "".
func (f *targetFeed) event(kind string, seq int64, got *checkedEntry) string {
	f.present[seq] = kind
	switch {
	case got.targetPassed != nil:
		return f.check(seq, got)
	case got.signOff != nil:
		f.signOffs = append(f.signOffs, feedSignOff{sequence: seq, s: got.signOff})
	case resultKindOf(kind) != "" && got.deletedBy == "":
		f.results[seq] = &feedResult{kind: kind, runID: got.runID, hash: got.hash, logged: got.logged, recordClock: got.recordClock, target: got.resultTarget}
	}
	return ""
}

// targetSource is the policy field a result of this feed kind takes its
// target from.
func targetSource(kind string) string {
	switch kind {
	case artifacts.SignalRunSealed:
		return artifacts.TargetSourceSignOff
	case artifacts.SignalRunRefused:
		return artifacts.TargetSourceRefusals
	}
	return artifacts.TargetSourceStops
}

func (f *targetFeed) check(seq int64, got *checkedEntry) string {
	r := got.targetPassed
	f.count++
	res := f.results[r.ResultSequence]
	if res == nil {
		if k, inFeed := f.present[r.ResultSequence]; inFeed {
			return fmt.Sprintf("its target names event %d as its result, and event %d is a %s, not a result whose record the feed shows", r.ResultSequence, r.ResultSequence, k)
		}
		f.notes = append(f.notes, fmt.Sprintf("event %d states a passed target for the result at event %d, which is not in this part of the feed; its start and sign-offs are not checked.", seq, r.ResultSequence))
		return ""
	}
	key := r.ResultKind + ":" + strconv.FormatInt(r.RunID, 10)
	if earlier, twice := f.passed[key]; twice {
		return fmt.Sprintf("it is a second passed target for run %d's %s, after event %d; one is sealed per result", r.RunID, r.ResultKind, earlier)
	}
	f.passed[key] = seq
	switch {
	case resultKindOf(res.kind) != r.ResultKind:
		return fmt.Sprintf("its target names a %s, and event %d is a %s", r.ResultKind, r.ResultSequence, res.kind)
	case res.runID != r.RunID || res.hash != r.ResultHash:
		return fmt.Sprintf("its target names run %d's result %s, and event %d is run %d's %s", r.RunID, truncate(r.ResultHash, 16), r.ResultSequence, res.runID, truncate(res.hash, 16))
	case r.Source != targetSource(res.kind):
		return fmt.Sprintf("its target comes from %s, and a %s result's target comes from %s", r.Source, res.kind, targetSource(res.kind))
	case res.target != nil && (res.target.Within != r.Within || res.target.Compare != r.Compare || res.target.Notice != r.Notice):
		return fmt.Sprintf("its target (%d seconds, %s, %s) is not the one its result sealed (%d seconds, %s, %s)",
			r.Within, r.Compare, r.Notice, res.target.Within, res.target.Compare, res.target.Notice)
	}
	if why := targetStartMatches(r, res); why != "" {
		return why
	}
	deadline, _ := time.Parse(time.RFC3339Nano, r.Deadline)
	if got.logged > 0 && time.Unix(got.logged, 0).Before(deadline) {
		return fmt.Sprintf("it says the target passed at %s, and its own public-log entry is at %s, before that deadline", r.Deadline, logTimeText(got.logged))
	}
	if got.logged == 0 {
		f.notes = append(f.notes, fmt.Sprintf("event %d, a passed target, carries no public-log entry of its own, so the log does not show it was made after its deadline %s.", seq, r.Deadline))
	}
	for _, so := range f.signOffs {
		s := so.s
		if !signOffNames(s.Target, r.ResultKind, r.RunID) || (r.Compare == artifacts.TargetCompareFirstApproval && s.Decision != artifacts.SignOffApprove) {
			continue
		}
		at, parseErr := time.Parse(time.RFC3339Nano, s.RecordedAt)
		on := "sealed"
		if r.StartBasis == artifacts.TargetStartPublicLog && s.Anchor != nil && s.Anchor.IntegratedTime > 0 {
			at, parseErr, on = time.Unix(s.Anchor.IntegratedTime, 0), nil, "on the public log"
		}
		if parseErr == nil && !at.After(deadline) {
			return fmt.Sprintf("it says no %s sign-off was on the public log by the deadline %s, and event %d, a sign-off on that result, was %s at %s",
				r.Compare, r.Deadline, so.sequence, on, at.UTC().Format(time.RFC3339Nano))
		}
	}
	return ""
}

// targetStartMatches holds a target's start to its result: the result's
// public-log time when its entry has one, else its sealed record time.
func targetStartMatches(r *artifacts.SignOffTargetPassed, res *feedResult) string {
	if res.logged > 0 {
		want := time.Unix(res.logged, 0).UTC().Format(time.RFC3339Nano)
		if r.StartBasis != artifacts.TargetStartPublicLog || r.Start != want {
			return fmt.Sprintf("its start is %s (%s), and its result's entry is on the public log at %s", r.Start, r.StartBasis, want)
		}
		return ""
	}
	clock, parseErr := time.Parse(time.RFC3339Nano, res.recordClock)
	if parseErr != nil {
		return fmt.Sprintf("its result's record time %q is not an RFC 3339 time", safePrefix(res.recordClock))
	}
	if want := clock.UTC().Format(time.RFC3339Nano); r.StartBasis != artifacts.TargetStartRecordTime || r.Start != want {
		return fmt.Sprintf("its start is %s (%s), and its result, which has no public-log entry of its own, was sealed at %s", r.Start, r.StartBasis, want)
	}
	return ""
}
