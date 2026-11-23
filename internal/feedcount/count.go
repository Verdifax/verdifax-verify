package feedcount

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Figure is one counted figure: its name, its value, and the exact events it
// counts. A count's value is the number of its events; a figure whose name
// ends in _seconds is a time, in whole seconds, over the events it lists.
type Figure struct {
	Name   string
	Value  int64
	Events []EventRef
}

// figures collects the figures of one count.
type figures struct {
	counts map[string][]EventRef
	values map[string]Figure
}

func (fs *figures) add(name string, ref EventRef) { fs.counts[name] = append(fs.counts[name], ref) }

func (fs *figures) value(name string, v int64, refs []EventRef) {
	fs.values[name] = Figure{Name: name, Value: v, Events: append([]EventRef(nil), refs...)}
}

// codePart is a sealed code as it is written in a figure's name: lowercase,
// every character outside a-z, 0-9, dot, underscore and hyphen written as an
// underscore, at most 64 bytes, and "none" for an empty code.
func codePart(code string) string {
	if code == "" {
		return "none"
	}
	b := []byte(strings.ToLower(code))
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			b[i] = '_'
		}
	}
	if len(b) > 64 {
		b = b[:64]
	}
	return string(b)
}

// decider is a decided_by as it is written in a figure's name.
func decider(by string) string {
	if by == "" {
		return "unstated"
	}
	return codePart(by)
}

// stopHolder names who placed a stop for its figures. Under v2 an owner's
// stop is owner.signed when the owner's request-key signature came with it
// and owner.unsigned when the record is the server's word (round 64, N32);
// under v1, and for Verdifax's stops, it is the decider alone.
func stopHolder(f *facts, rules string) string {
	by := decider(f.decidedBy)
	if rules == CountingRulesV1 || by != "owner" {
		return by
	}
	if f.ownerSigned {
		return "owner.signed"
	}
	return "owner.unsigned"
}

// Summarize counts the figures of the period from (included) to to
// (excluded) over the feed up to the head. Every event is placed by its own
// sealed time; an event whose record was deleted has none to read, and is
// counted apart (events.record_deleted.unplaced) when its place lies between
// the first and the last event placed in the period. The figures are sorted
// by name.
func Summarize(events []Event, from, to time.Time, head Head) ([]Figure, error) {
	return SummarizeByRules(CountingRules, events, from, to, head)
}

// SummarizeByRules counts as Summarize does, by the named counting rules:
// a summary stated under v1 is recounted by v1, which has no signed and
// unsigned stop figures.
func SummarizeByRules(rules string, events []Event, from, to time.Time, head Head) ([]Figure, error) {
	if !KnownCountingRules(rules) {
		return nil, fmt.Errorf("%w: counting rules %q are not ones this package holds", errFeed, rules)
	}
	l, ledgerErr := readLedger(events, head)
	if ledgerErr != nil {
		return nil, ledgerErr
	}
	fs := &figures{counts: map[string][]EventRef{}, values: map[string]Figure{}}
	var firstPlaced, lastPlaced int64
	for _, f := range l.events {
		if !placed(f.clock, from, to) {
			continue
		}
		if firstPlaced == 0 {
			firstPlaced = f.ev.Sequence
		}
		lastPlaced = f.ev.Sequence
		countEvent(fs, f, rules)
	}
	for _, ev := range l.deleted {
		if firstPlaced > 0 && ev.Sequence > firstPlaced && ev.Sequence < lastPlaced {
			fs.add("events.record_deleted.unplaced", ev.ref())
		}
	}
	l.countDecisions(fs, from, to)
	l.countStops(fs, from, to, rules)
	l.countResponseTimes(fs, from, to, head)
	out := make([]Figure, 0, len(fs.counts)+len(fs.values))
	for name, refs := range fs.counts {
		out = append(out, Figure{Name: name, Value: int64(len(refs)), Events: refs})
	}
	for _, f := range fs.values {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// countEvent counts one event placed in the period.
func countEvent(fs *figures, f *facts, rules string) {
	ref := f.ev.ref()
	e := &f.e
	switch f.ev.Kind {
	case kindRunSealed:
		fs.add("runs.sealed", ref)
		if e.JobID != "" {
			fs.add("runs.sealed.job_steps", ref)
		}
		if e.SignOffRequired {
			fs.add("runs.sealed.signoff_required", ref)
		}
		if e.SignOffTarget != nil {
			fs.add("runs.sealed.target_sealed", ref)
		}
	case kindRunRefused:
		fs.add("runs.refused", ref)
		fs.add("runs.refused.receipt:"+f.receiptKind, ref)
		fs.add("runs.refused.code:"+codePart(f.code), ref)
		if f.code == "ACCOUNT_STOPPED" {
			fs.add("runs.refused.account_stopped", ref)
		}
		if f.dataUse {
			fs.add("runs.refused.data_use_declared", ref)
		}
		if f.target != nil {
			fs.add("runs.refused.target_sealed", ref)
		}
	case kindRunHalted:
		fs.add("runs.halted", ref)
		fs.add("runs.halted.receipt:"+f.receiptKind, ref)
		fs.add("runs.halted.code:"+codePart(f.code), ref)
		if f.target != nil {
			fs.add("runs.halted.target_sealed", ref)
		}
	case kindRunFailed:
		fs.add("runs.failed", ref)
		fs.add("runs.failed.class:"+codePart(f.class), ref)
		fs.add("runs.failed.stage:"+codePart(f.stage), ref)
	case kindSignOffRecorded:
		fs.add("signoffs.made", ref)
		fs.add("signoffs.made."+codePart(e.Decision), ref)
		fs.add("signoffs.made.target:"+codePart(e.Target.Kind), ref)
	case kindSignOffRefused:
		fs.add("signoffs.refused", ref)
	case kindPolicyChanged:
		fs.add("policy.changed", ref)
		if len(e.Signature) > 0 && string(e.Signature) != "null" {
			fs.add("policy.changed.signed", ref)
		}
		if strings.HasPrefix(e.ChainID, "account-") {
			fs.add("policy.changed.chain:account", ref)
		} else {
			fs.add("policy.changed.chain:key", ref)
		}
	case kindKeyCreated, kindKeyRevoked, kindApproverRegistered, kindApproverRevoked:
		name := map[string]string{kindKeyCreated: "keys.created", kindKeyRevoked: "keys.revoked",
			kindApproverRegistered: "approvers.registered", kindApproverRevoked: "approvers.revoked"}[f.ev.Kind]
		fs.add(name, ref)
		fs.add(name+".by:"+decider(f.decidedBy), ref)
	case kindAccountChanged:
		fs.add("account.changed", ref)
		fs.add("account.changed.by:"+decider(f.decidedBy), ref)
	case kindRunDeleted:
		fs.add("runs.deleted", ref)
		fs.add("runs.deleted.by:"+decider(f.decidedBy), ref)
	case kindRunPublished:
		fs.add("runs.published", ref)
		fs.add("runs.published.by:"+decider(f.decidedBy), ref)
	case kindRunUnpublished:
		fs.add("runs.unpublished", ref)
		fs.add("runs.unpublished.by:"+decider(f.decidedBy), ref)
	case kindChainGap:
		fs.add("chain.gaps", ref)
	case kindChainInterrupted:
		fs.add("chain.interrupted", ref)
	case kindSetupChanged:
		fs.add("setup.changed", ref)
	case kindReviewDue:
		fs.add("review.due", ref)
	case kindAccountStopped:
		fs.add("account.stops", ref)
		fs.add("account.stops.by:"+decider(f.decidedBy), ref)
		if by := stopHolder(f, rules); by != decider(f.decidedBy) {
			fs.add("account.stops.by:"+by, ref)
		}
	case kindAccountResumed:
		fs.add("account.resumes", ref)
		fs.add("account.resumes.by:"+decider(f.decidedBy), ref)
	case kindTargetPassed:
		fs.add("signoff.target_passed", ref)
		fs.add("signoff.target_passed.result:"+codePart(e.ResultKind), ref)
	}
}

// countDecisions counts the results placed in the period by the decision in
// force on each at the period's end, from the sign-offs sealed before the
// end, and the results that require a sign-off and have none in force then;
// each figure lists the result events. A result whose run was deleted before
// the end is left out.
func (l *ledger) countDecisions(fs *figures, from, to time.Time) {
	for _, f := range l.events {
		if !placed(f.clock, from, to) || f.resultKind() == "" {
			continue
		}
		if gone, deleted := l.runGone[runOf(f)]; deleted && gone.Before(to) {
			continue
		}
		_, _, inForce := l.endsOf(f, &to)
		switch {
		case inForce != nil:
			fs.add("results.decision_in_force."+codePart(inForce.f.e.Decision), f.ev.ref())
		case f.ev.Kind == kindRunSealed && f.e.SignOffRequired:
			fs.add("results.signoff_required.none_in_force", f.ev.ref())
		}
	}
}

// countStops states how long the account was stopped inside the period, by
// the stop and resume records' sealed times: in all (any hold standing) and
// by each holder, with the stop and resume events that bound each stretch.
func (l *ledger) countStops(fs *figures, from, to time.Time, rules string) {
	type stretch struct {
		by, signed string
		start, end time.Time
		refs       []EventRef
	}
	var stretches []*stretch
	open := map[int64]*stretch{}
	for _, f := range l.events {
		if f.clock.After(to) || f.clock.Equal(to) {
			continue
		}
		switch f.ev.Kind {
		case kindAccountStopped:
			s := &stretch{by: decider(f.decidedBy), signed: stopHolder(f, rules), start: f.clock, end: to, refs: []EventRef{f.ev.ref()}}
			open[f.ev.Sequence] = s
			stretches = append(stretches, s)
		case kindAccountResumed:
			if s, ok := open[f.e.LiftsSequence]; ok {
				s.end = f.clock
				s.refs = append(s.refs, f.ev.ref())
				delete(open, f.e.LiftsSequence)
			}
		}
	}
	clip := func(s *stretch) (time.Time, time.Time, bool) {
		start, end := s.start, s.end
		if start.Before(from) {
			start = from
		}
		if end.After(to) {
			end = to
		}
		return start, end, end.After(start)
	}
	var all []EventRef
	var spans [][2]time.Time
	byHolder := map[string]time.Duration{}
	refsBy := map[string][]EventRef{}
	for _, s := range stretches {
		start, end, inside := clip(s)
		if !inside {
			continue
		}
		byHolder[s.by] += end.Sub(start)
		refsBy[s.by] = append(refsBy[s.by], s.refs...)
		if s.signed != s.by {
			byHolder[s.signed] += end.Sub(start)
			refsBy[s.signed] = append(refsBy[s.signed], s.refs...)
		}
		all = append(all, s.refs...)
		spans = append(spans, [2]time.Time{start, end})
	}
	if len(spans) == 0 {
		return
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i][0].Before(spans[j][0]) })
	var union time.Duration
	cur := spans[0]
	for _, sp := range spans[1:] {
		if sp[0].After(cur[1]) {
			union += cur[1].Sub(cur[0])
			cur = sp
			continue
		}
		if sp[1].After(cur[1]) {
			cur[1] = sp[1]
		}
	}
	union += cur[1].Sub(cur[0])
	fs.value("account.stopped_seconds", int64(union/time.Second), all)
	for by, d := range byHolder {
		fs.value("account.stopped_seconds.by:"+by, int64(d/time.Second), refsBy[by])
	}
}

// countResponseTimes adds the response-time report's figures for the period.
func (l *ledger) countResponseTimes(fs *figures, from, to time.Time, head Head) {
	rep := l.responseTimes(from, to, head, nil)
	a := &rep.Aggregates
	if a.Results == 0 && a.ResultsDeleted == 0 {
		return
	}
	for name, refs := range a.lists {
		fs.counts["response_times."+name] = refs
	}
	for name, end := range map[string]*EndAggregate{EndFirstSignOff: &a.FirstSignOff, EndFirstApproval: &a.FirstApproval,
		EndDecisionInForce: &a.DecisionInForce} {
		if end.Reached == 0 {
			continue
		}
		fs.counts["response_times."+name+".reached"] = end.events
		for clock, sp := range map[string]*Spread{"log": end.PublicLog, "record": end.RecordTime} {
			if sp == nil {
				continue
			}
			prefix := "response_times." + name + "." + clock + "."
			fs.value(prefix+"median_seconds", sp.MedianSeconds, sp.events)
			fs.value(prefix+"p90_seconds", sp.P90Seconds, sp.events)
			fs.value(prefix+"longest_seconds", sp.LongestSeconds, sp.events)
		}
	}
}
