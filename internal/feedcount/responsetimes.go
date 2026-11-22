package feedcount

import (
	"sort"
	"time"
)

// Head is the feed-head statement a count is made up to: its place, its
// public-log time (whole seconds, 0 when it states none) and its sealed
// statement time.
type Head struct {
	Sequence int64
	Logged   int64
	StatedAt time.Time
}

// The end points a wait is measured to, and the standings of a result.
const (
	EndFirstSignOff    = "first_signoff"
	EndFirstApproval   = "first_approval"
	EndDecisionInForce = "decision_in_force"

	OnPublicLog  = "public_log"
	OnRecordTime = "record_time"

	StandingWithinTarget             = "within_target"
	StandingLongerSignedAfter        = "longer_than_target_signed_after"
	StandingUnsignedWithinAsOfHead   = "unsigned_within_target_as_of_head"
	StandingUnsignedLongerAsOfHead   = "unsigned_longer_than_target_as_of_head"
	StandingSignedNoTarget           = "signed_no_target"
	StandingUnsignedNoTargetAsOfHead = "unsigned_no_target_as_of_head"

	TargetSealed  = "sealed"
	TargetRequest = "request"
)

// Target is a response target: whole seconds, and the end point compared.
type Target struct {
	Within  int64  `json:"within"`
	Compare string `json:"compare"`
	Notice  string `json:"notice,omitempty"`
	Source  string `json:"source"`
}

// EndPoint is one sign-off a wait is measured to: its feed place, decision
// and times, and the wait on the public log (when both entries carry a log
// time) and on the sealed record times, each stated as measured.
type EndPoint struct {
	Sequence      int64  `json:"sequence"`
	Decision      string `json:"decision"`
	RecordedAt    string `json:"recorded_at"`
	LoggedAt      string `json:"logged_at,omitempty"`
	LogSeconds    *int64 `json:"log_seconds,omitempty"`
	RecordSeconds int64  `json:"record_seconds"`
}

// ResultTime is one result's measured waits.
type ResultTime struct {
	RunID      int64  `json:"run_id"`
	ResultKind string `json:"result_kind"`
	EventKind  string `json:"event_kind"`
	Sequence   int64  `json:"sequence"`
	// RecordedAt is the result entry's sealed time as sealed; LoggedAt its
	// public-log time, the start every log wait is counted from.
	RecordedAt      string    `json:"recorded_at"`
	LoggedAt        string    `json:"logged_at,omitempty"`
	SignOffRequired bool      `json:"signoff_required,omitempty"`
	Target          *Target   `json:"target,omitempty"`
	FirstSignOff    *EndPoint `json:"first_signoff,omitempty"`
	FirstApproval   *EndPoint `json:"first_approval,omitempty"`
	DecisionInForce *EndPoint `json:"decision_in_force,omitempty"`
	// Compared names the end point held against the target (first_signoff
	// when there is none); ComparedOn the clock the comparison used;
	// ComparedSeconds the wait compared, to the end point, or to the head
	// for a result still unsigned; Standing the outcome, stated as measured.
	Compared        string `json:"compared"`
	ComparedOn      string `json:"compared_on"`
	ComparedSeconds int64  `json:"compared_seconds"`
	Standing        string `json:"standing"`
	ev              EventRef
	ends            map[string]EventRef
}

// Spread is one end point's waits over the results that reached it on one
// clock: how many, the median (the lower middle), the 90th percentile by
// nearest rank, and the longest with its run.
type Spread struct {
	Count          int   `json:"count"`
	MedianSeconds  int64 `json:"median_seconds"`
	P90Seconds     int64 `json:"p90_seconds"`
	LongestSeconds int64 `json:"longest_seconds"`
	LongestRunID   int64 `json:"longest_run_id"`
	events         []EventRef
}

// EndAggregate is one end point's figures.
type EndAggregate struct {
	Reached    int     `json:"reached"`
	PublicLog  *Spread `json:"public_log,omitempty"`
	RecordTime *Spread `json:"record_time,omitempty"`
	events     []EventRef
}

// Aggregates are the report's figures.
type Aggregates struct {
	Results                     int          `json:"results"`
	ResultsDeleted              int          `json:"results_deleted"`
	WithTarget                  int          `json:"with_target"`
	FirstSignOff                EndAggregate `json:"first_signoff"`
	FirstApproval               EndAggregate `json:"first_approval"`
	DecisionInForce             EndAggregate `json:"decision_in_force"`
	UnsignedAsOfHead            int          `json:"unsigned_as_of_head"`
	LongerThanTargetSignedAfter int          `json:"longer_than_target_signed_after"`
	LongerThanTargetUnsigned    int          `json:"longer_than_target_unsigned_as_of_head"`
	lists                       map[string][]EventRef
}

// Report is the response-time report: every result of the period, in feed
// order, and the aggregates.
type Report struct {
	Results    []ResultTime `json:"results"`
	Aggregates Aggregates   `json:"aggregates"`
}

// signOff is one recorded sign-off.
type signOff struct {
	f *facts
}

func (s signOff) end(start *facts) *EndPoint {
	p := &EndPoint{Sequence: s.f.ev.Sequence, Decision: s.f.e.Decision, RecordedAt: s.f.clockText,
		RecordSeconds: int64(s.f.clock.Sub(start.clock) / time.Second)}
	if s.f.logged > 0 {
		p.LoggedAt = logTime(s.f.logged)
	}
	if s.f.logged > 0 && start.logged > 0 {
		d := s.f.logged - start.logged
		p.LogSeconds = &d
	}
	return p
}

func logTime(seconds int64) string { return time.Unix(seconds, 0).UTC().Format(time.RFC3339) }

// placed reports a sealed time inside the period: from included, to excluded.
func placed(at, from, to time.Time) bool { return !at.Before(from) && at.Before(to) }

// ledger holds the facts of every event up to the head, in feed order.
type ledger struct {
	events   []*facts
	deleted  []*Event
	signOffs []signOff
	// runGone names each run a run.deleted event up to the head deleted.
	runGone map[int64]time.Time
}

func readLedger(events []Event, head Head) (*ledger, error) {
	l := &ledger{runGone: map[int64]time.Time{}}
	sorted := make([]*Event, 0, len(events))
	for i := range events {
		if events[i].Sequence <= head.Sequence {
			sorted = append(sorted, &events[i])
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Sequence < sorted[j].Sequence })
	for _, ev := range sorted {
		f, factsErr := readFacts(ev)
		if factsErr != nil {
			return nil, factsErr
		}
		if f == nil {
			l.deleted = append(l.deleted, ev)
			continue
		}
		l.events = append(l.events, f)
		switch ev.Kind {
		case kindSignOffRecorded:
			l.signOffs = append(l.signOffs, signOff{f})
		case kindRunDeleted:
			if _, seen := l.runGone[f.e.RunID]; !seen && f.e.RunID > 0 {
				l.runGone[f.e.RunID] = f.clock
			}
		}
	}
	return l, nil
}

// endsOf finds a result's first sign-off, first approval and decision in
// force among the sign-offs up to the head, in feed order, optionally only
// those sealed before a time. On a record the latest job sign-off governs,
// else the latest record sign-off; on a receipt the latest receipt sign-off.
func (l *ledger) endsOf(result *facts, before *time.Time) (first, approval, inForce *signOff) {
	runID, kind := result.ev.RunID, result.resultKind()
	if result.ev.Kind == kindRunSealed {
		runID = result.e.RunID
	}
	var job, other *signOff
	for i := range l.signOffs {
		s := &l.signOffs[i]
		if !names(s.f.e.Target, runID, kind) || (before != nil && !s.f.clock.Before(*before)) {
			continue
		}
		if first == nil {
			first = s
		}
		if approval == nil && s.f.e.Decision == "approve" {
			approval = s
		}
		if s.f.e.Target.Kind == "job" {
			job = s
		} else {
			other = s
		}
	}
	if job != nil {
		return first, approval, job
	}
	return first, approval, other
}

// runOf is the run a result names.
func runOf(f *facts) int64 {
	if f.ev.Kind == kindRunSealed {
		return f.e.RunID
	}
	return f.ev.RunID
}

// isResult reports whether a placed event is a result the report measures:
// a run.sealed record that requires a sign-off or seals a target, a refused
// or halted run's receipt that seals a target, or any of these that a
// sign-off names by the head.
func (l *ledger) isResult(f *facts) bool {
	switch f.ev.Kind {
	case kindRunSealed:
		if f.e.SignOffRequired || f.target != nil {
			return true
		}
	case kindRunRefused, kindRunHalted:
		if f.target != nil {
			return true
		}
	default:
		return false
	}
	first, _, _ := l.endsOf(f, nil)
	return first != nil
}

// ResponseTimes measures every result placed in the period by its sealed
// time, up to the head. request, when not nil, is a target in whole seconds
// applied to each result that seals none, compared with its first sign-off.
func ResponseTimes(events []Event, from, to time.Time, head Head, request *int64) (*Report, error) {
	l, ledgerErr := readLedger(events, head)
	if ledgerErr != nil {
		return nil, ledgerErr
	}
	return l.responseTimes(from, to, head, request), nil
}

func (l *ledger) responseTimes(from, to time.Time, head Head, request *int64) *Report {
	rep := &Report{Results: []ResultTime{}}
	agg := &rep.Aggregates
	agg.lists = map[string][]EventRef{}
	ends := map[string]*EndAggregate{EndFirstSignOff: &agg.FirstSignOff, EndFirstApproval: &agg.FirstApproval, EndDecisionInForce: &agg.DecisionInForce}
	waits := map[string][]wait{}
	for _, f := range l.events {
		if !placed(f.clock, from, to) || !l.isResult(f) {
			continue
		}
		run := runOf(f)
		if _, deleted := l.runGone[run]; deleted {
			agg.ResultsDeleted++
			agg.lists["results_deleted"] = append(agg.lists["results_deleted"], f.ev.ref())
			continue
		}
		r := ResultTime{RunID: run, ResultKind: f.resultKind(), EventKind: f.ev.Kind, Sequence: f.ev.Sequence, RecordedAt: f.clockText,
			SignOffRequired: f.ev.Kind == kindRunSealed && f.e.SignOffRequired, ev: f.ev.ref(), ends: map[string]EventRef{}}
		if f.logged > 0 {
			r.LoggedAt = logTime(f.logged)
		}
		switch {
		case f.target != nil:
			r.Target = &Target{Within: f.target.Within, Compare: f.target.Compare, Notice: f.target.Notice, Source: TargetSealed}
		case request != nil:
			r.Target = &Target{Within: *request, Compare: EndFirstSignOff, Source: TargetRequest}
		}
		first, approval, inForce := l.endsOf(f, nil)
		points := map[string]*signOff{EndFirstSignOff: first, EndFirstApproval: approval, EndDecisionInForce: inForce}
		for name, s := range points {
			if s == nil {
				continue
			}
			p := s.end(f)
			switch name {
			case EndFirstSignOff:
				r.FirstSignOff = p
			case EndFirstApproval:
				r.FirstApproval = p
			case EndDecisionInForce:
				r.DecisionInForce = p
			}
			r.ends[name] = s.f.ev.ref()
			a := ends[name]
			a.Reached++
			a.events = append(a.events, f.ev.ref())
			if p.LogSeconds != nil {
				waits[name+"/log"] = append(waits[name+"/log"], wait{run, *p.LogSeconds, f.ev.ref()})
			}
			waits[name+"/record"] = append(waits[name+"/record"], wait{run, p.RecordSeconds, f.ev.ref()})
		}
		r.Compared = EndFirstSignOff
		if r.Target != nil {
			r.Compared = r.Target.Compare
			agg.WithTarget++
			agg.lists["with_target"] = append(agg.lists["with_target"], f.ev.ref())
		}
		end := points[r.Compared]
		switch {
		case end != nil:
			p := end.end(f)
			r.ComparedOn, r.ComparedSeconds = OnRecordTime, p.RecordSeconds
			if p.LogSeconds != nil {
				r.ComparedOn, r.ComparedSeconds = OnPublicLog, *p.LogSeconds
			}
		default:
			agg.UnsignedAsOfHead++
			agg.lists["unsigned_as_of_head"] = append(agg.lists["unsigned_as_of_head"], f.ev.ref())
			r.ComparedOn, r.ComparedSeconds = OnRecordTime, int64(head.StatedAt.Sub(f.clock)/time.Second)
			if f.logged > 0 && head.Logged > 0 {
				r.ComparedOn, r.ComparedSeconds = OnPublicLog, head.Logged-f.logged
			}
		}
		switch {
		case r.Target == nil && end != nil:
			r.Standing = StandingSignedNoTarget
		case r.Target == nil:
			r.Standing = StandingUnsignedNoTargetAsOfHead
		case end != nil && r.ComparedSeconds <= r.Target.Within:
			r.Standing = StandingWithinTarget
		case end != nil:
			r.Standing = StandingLongerSignedAfter
			agg.LongerThanTargetSignedAfter++
			agg.lists["longer_than_target.signed_after"] = append(agg.lists["longer_than_target.signed_after"], f.ev.ref())
		case r.ComparedSeconds <= r.Target.Within:
			r.Standing = StandingUnsignedWithinAsOfHead
		default:
			r.Standing = StandingUnsignedLongerAsOfHead
			agg.LongerThanTargetUnsigned++
			agg.lists["longer_than_target.unsigned_as_of_head"] = append(agg.lists["longer_than_target.unsigned_as_of_head"], f.ev.ref())
		}
		agg.Results++
		agg.lists["results"] = append(agg.lists["results"], f.ev.ref())
		rep.Results = append(rep.Results, r)
	}
	for name, a := range ends {
		a.PublicLog = spreadOf(waits[name+"/log"])
		a.RecordTime = spreadOf(waits[name+"/record"])
	}
	return rep
}

// wait is one result's wait to one end point on one clock.
type wait struct {
	run     int64
	seconds int64
	ev      EventRef
}

// spreadOf states a list of waits, or nil for none. The median is the lower
// middle of the sorted waits; the 90th percentile the nearest rank, the
// ceil(0.9 n)-th smallest; the longest the longest, the first in feed order
// among equals.
func spreadOf(list []wait) *Spread {
	if len(list) == 0 {
		return nil
	}
	values := make([]int64, len(list))
	s := &Spread{Count: len(list)}
	longest := 0
	for i, w := range list {
		values[i] = w.seconds
		s.events = append(s.events, w.ev)
		if w.seconds > list[longest].seconds {
			longest = i
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	n := len(values)
	s.MedianSeconds = values[(n-1)/2]
	s.P90Seconds = values[(9*n+9)/10-1]
	s.LongestSeconds, s.LongestRunID = list[longest].seconds, list[longest].run
	return s
}
