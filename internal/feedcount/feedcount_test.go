package feedcount

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// The shared vector (testdata/feedcount_vector.json) holds a synthetic feed
// of every kind the counting rules read, a period and a head, and every
// figure and the response-time report they give. verdifax-verify and the
// four SDKs read the same file: a change to what any figure counts changes
// the vector, and every copy fails until it is changed with it.

func at(text string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		panic(err)
	}
	return t
}

func unix(text string) int64 { return at(text).Unix() }

func hashOf(seq int64) string { return fmt.Sprintf("%064x", seq) }

// vectorFeed builds the vector's feed, in feed order.
func vectorFeed() []Event {
	var events []Event
	add := func(kind string, runID int64, entry any) {
		seq := int64(len(events) + 1)
		raw, _ := json.Marshal(entry)
		events = append(events, Event{Sequence: seq, Kind: kind, EventHash: hashOf(seq), RunID: runID, Entry: raw})
	}
	anchor := func(text string) map[string]any { return map[string]any{"integrated_time": unix(text)} }
	signoff := func(kind string, run int64, decision, recorded, logged string) map[string]any {
		return map[string]any{"format": "verdifax.signoff.v1", "decision": decision, "target": map[string]any{"kind": kind, "run_id": run},
			"recorded_at": recorded, "anchor": anchor(logged)}
	}
	add(kindKeyCreated, 0, map[string]any{"format": "verdifax.key-change.v1", "changed_at": "2026-10-31T23:00:00Z"})
	add(kindAccountStopped, 0, map[string]any{"action": "stop", "decided_by": "verdifax_admin", "changed_at": "2026-10-31T23:30:00Z"})
	add(kindAccountResumed, 0, map[string]any{"action": "resume", "decided_by": "verdifax_admin", "lifts_sequence": 2, "changed_at": "2026-11-01T00:30:00Z"})
	add(kindRunSealed, 10, map[string]any{"run_id": 10, "job_id": "job-a", "signoff_required": true, "sealed_at": "2026-11-01T01:00:00Z",
		"signoff_target": map[string]any{"within": 600, "compare": "first_signoff", "notice": "both"}, "run_sealed_hash": hashOf(104),
		"anchor": anchor("2026-11-01T01:00:01Z")})
	add(kindRunRefused, 11, map[string]any{"ok": true, "run_id": 11, "deny_receipt": map[string]any{"deny_clock": "2026-11-01T01:10:00+01:00",
		"decision_reason_code": "ACCOUNT_STOPPED", "hash": hashOf(105)}, "receipt_anchor": anchor("2026-11-01T00:10:05Z"),
		"receipt_context": map[string]any{"data_use": map[string]any{"purpose": "claims.review"},
			"response_target": map[string]any{"within": 300, "compare": "first_approval", "notice": "event"}}})
	add(kindSignOffRecorded, 10, signoff("record", 10, "approve", "2026-11-01T01:05:00Z", "2026-11-01T01:05:02Z"))
	add(kindSignOffRecorded, 10, signoff("job", 10, "reject", "2026-11-01T01:20:00Z", "2026-11-01T01:20:01Z"))
	add(kindRunHalted, 12, map[string]any{"ok": true, "run_id": 12, "ccv_halt_receipt": map[string]any{"halt_clock": "2026-11-01T02:00:00Z",
		"halt_reason_code": "CCV_BUDGET_EXCEEDED", "hash": hashOf(108)}, "receipt_anchor": anchor("2026-11-01T02:00:00Z"),
		"receipt_context": map[string]any{"response_target": map[string]any{"within": 60, "compare": "first_signoff", "notice": "head"}}})
	add(kindSignOffRecorded, 12, signoff("receipt", 12, "approve", "2026-11-01T02:10:00Z", "2026-11-01T02:10:00Z"))
	add(kindRunFailed, 13, map[string]any{"ok": true, "run_id": 13, "failure_receipt": map[string]any{"fail_clock": "2026-11-01T03:00:00Z",
		"failed_stage": "SEAL", "error_class": "STORE_ERROR", "hash": hashOf(110)}})
	add(kindPolicyChanged, 0, map[string]any{"chain_id": "account-7", "activated_at": "2026-11-01T04:00:00Z", "signature": map[string]any{"signed_at": "x"}})
	events = append(events, Event{Sequence: 12, Kind: kindRunRefused, EventHash: hashOf(12), RunID: 14, Entry: json.RawMessage("null"), Deleted: true})
	add(kindRunDeleted, 14, map[string]any{"run_id": 14, "decided_by": "owner", "changed_at": "2026-11-01T05:00:00Z"})
	add(kindSetupChanged, 15, map[string]any{"run_id": 15, "changed_at": "2026-11-01T05:10:00Z"})
	add(kindReviewDue, 0, map[string]any{"stated_at": "2026-11-01T06:00:00Z"})
	add(kindRunPublished, 10, map[string]any{"format": "verdifax.run-publication.v1", "changed_at": "2026-11-01T07:00:00Z"})
	add(kindKeyCreated, 0, map[string]any{"format": "verdifax.key-change.v2", "decided_by": "verdifax_admin", "changed_at": "2026-11-01T08:00:00Z"})
	add(kindApproverRegistered, 0, map[string]any{"format": "verdifax.key-change.v2", "decided_by": "owner", "changed_at": "2026-11-01T08:30:00Z"})
	add(kindChainGap, 0, map[string]any{"recorded_at": "2026-11-01T09:00:00Z"})
	add(kindChainInterrupted, 0, map[string]any{"recorded_at": "2026-11-01T09:10:00Z"})
	add(kindAccountChanged, 0, map[string]any{"decided_by": "owner", "changed_at": "2026-11-01T09:20:00Z"})
	add(kindAccountStopped, 0, map[string]any{"action": "stop", "decided_by": "owner", "changed_at": "2026-11-01T23:00:00Z"})
	add(kindSignOffRefused, 10, map[string]any{"refused_at": "2026-11-01T23:10:00Z"})
	add(kindTargetPassed, 11, map[string]any{"result_kind": "receipt", "stated_at": "2026-11-01T23:30:00Z"})
	add(kindRunSealed, 16, map[string]any{"run_id": 16, "signoff_required": true, "sealed_at": "2026-11-02T00:00:00Z", "run_sealed_hash": hashOf(126)})
	add(kindSignOffRecorded, 16, signoff("record", 16, "approve", "2026-11-02T00:30:00Z", "2026-11-02T00:30:00Z"))
	// Run 20: the job's approval governs a later record rejection.
	add(kindRunSealed, 20, map[string]any{"run_id": 20, "job_id": "job-b", "signoff_required": true, "sealed_at": "2026-11-01T10:00:00Z",
		"run_sealed_hash": hashOf(128), "anchor": anchor("2026-11-01T10:00:00Z")})
	add(kindSignOffRecorded, 20, signoff("job", 20, "approve", "2026-11-01T10:01:00Z", "2026-11-01T10:01:00Z"))
	add(kindSignOffRecorded, 20, signoff("record", 20, "reject", "2026-11-01T10:02:00Z", "2026-11-01T10:02:00Z"))
	// Verdifax's stop overlaps the owner's: the time stopped in all counts
	// the overlap once.
	add(kindAccountStopped, 0, map[string]any{"action": "stop", "decided_by": "verdifax_admin", "changed_at": "2026-11-01T23:30:00Z"})
	return events
}

var (
	vectorFrom = at("2026-11-01T00:00:00Z")
	vectorTo   = at("2026-11-02T00:00:00Z")
	vectorHead = Head{Sequence: 30, Logged: unix("2026-11-02T01:00:00Z"), StatedAt: at("2026-11-02T01:00:00Z")}
)

type vectorFigure struct {
	Name      string  `json:"name"`
	Value     int64   `json:"value"`
	Sequences []int64 `json:"sequences"`
}

type vectorFile struct {
	Note          string            `json:"note"`
	CountingRules string            `json:"counting_rules"`
	From          string            `json:"from"`
	To            string            `json:"to"`
	Head          map[string]any    `json:"head"`
	Events        []json.RawMessage `json:"events"`
	Figures       []vectorFigure    `json:"figures"`
	ResponseTimes json.RawMessage   `json:"response_times"`
}

func figuresOf(figs []Figure) []vectorFigure {
	out := make([]vectorFigure, len(figs))
	for i, f := range figs {
		seqs := []int64{}
		for _, e := range f.Events {
			seqs = append(seqs, e.Sequence)
		}
		sort.Slice(seqs, func(a, b int) bool { return seqs[a] < seqs[b] })
		out[i] = vectorFigure{f.Name, f.Value, seqs}
	}
	return out
}

func buildVector(t *testing.T) vectorFile {
	t.Helper()
	events := vectorFeed()
	figs, err := Summarize(events, vectorFrom, vectorTo, vectorHead)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := ResponseTimes(events, vectorFrom, vectorTo, vectorHead, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt, _ := json.Marshal(rep)
	v := vectorFile{Note: "verdifax.period-summary-counting.v1 over a synthetic feed; each event's entry carries only the fields the counting rules read",
		CountingRules: CountingRules, From: "2026-11-01T00:00:00Z", To: "2026-11-02T00:00:00Z",
		Head:    map[string]any{"sequence": vectorHead.Sequence, "integrated_time": vectorHead.Logged, "stated_at": "2026-11-02T01:00:00Z"},
		Figures: figuresOf(figs), ResponseTimes: rt}
	for _, e := range events {
		raw, _ := json.Marshal(map[string]any{"sequence": e.Sequence, "kind": e.Kind, "event_hash": e.EventHash, "run_id": e.RunID,
			"entry": e.Entry, "deleted": e.Deleted})
		v.Events = append(v.Events, raw)
	}
	return v
}

// R331: the counting rules give the vector's figures and report, and the
// stored vector is the one every copy reads (VERDIFAX_WRITE_VECTOR=1
// rewrites it after a deliberate change to the rules).
func TestTheCountingRulesGiveTheSharedVector(t *testing.T) {
	v := buildVector(t)
	got, _ := json.MarshalIndent(v, "", "  ")
	path := "testdata/feedcount_vector.json"
	if os.Getenv("VERDIFAX_WRITE_VECTOR") == "1" {
		if err := os.WriteFile(path, append(got, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != strings.TrimSpace(string(got)) {
		t.Fatalf("the counting rules no longer give the shared vector; a change to them is a new counting_rules name and a new vector:\n%s", got)
	}
}

// R331: the vector's figures, checked one by one against the rules as the
// documentation states them.
func TestTheFiguresCountWhatTheRulesSay(t *testing.T) {
	figs, err := Summarize(vectorFeed(), vectorFrom, vectorTo, vectorHead)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]vectorFigure{}
	for _, f := range figuresOf(figs) {
		byName[f.Name] = f
	}
	want := map[string]string{
		// Placed by their own sealed time: run 16's record sealed at the
		// period's end is outside it, and the offset deny clock is 00:10Z.
		"runs.sealed": "2 [4 27]", "runs.sealed.job_steps": "2 [4 27]", "runs.sealed.signoff_required": "2 [4 27]", "runs.sealed.target_sealed": "1 [4]",
		"runs.refused": "1 [5]", "runs.refused.code:account_stopped": "1 [5]", "runs.refused.account_stopped": "1 [5]",
		"runs.refused.data_use_declared": "1 [5]", "runs.refused.receipt:deny_receipt": "1 [5]", "runs.refused.target_sealed": "1 [5]",
		"runs.halted": "1 [8]", "runs.halted.receipt:ccv_halt_receipt": "1 [8]", "runs.halted.code:ccv_budget_exceeded": "1 [8]",
		"runs.failed": "1 [10]", "runs.failed.class:store_error": "1 [10]", "runs.failed.stage:seal": "1 [10]",
		"events.record_deleted.unplaced": "1 [12]",
		"signoffs.made":                  "5 [6 7 9 28 29]", "signoffs.made.approve": "3 [6 9 28]", "signoffs.made.reject": "2 [7 29]",
		"signoffs.made.target:job": "2 [7 28]", "signoffs.made.target:record": "2 [6 29]", "signoffs.made.target:receipt": "1 [9]",
		// The job's reject governs run 10's record approval, and the job's
		// approval governs run 20's later record rejection.
		"results.decision_in_force.reject": "1 [4]", "results.decision_in_force.approve": "2 [8 27]",
		"policy.changed": "1 [11]", "policy.changed.signed": "1 [11]", "policy.changed.chain:account": "1 [11]",
		"runs.deleted": "1 [13]", "runs.deleted.by:owner": "1 [13]", "runs.published.by:owner": "1 [16]",
		"keys.created.by:verdifax_admin": "1 [17]", "approvers.registered.by:owner": "1 [18]",
		"chain.gaps": "1 [19]", "chain.interrupted": "1 [20]", "account.changed.by:owner": "1 [21]",
		"account.stops": "2 [22 30]", "account.stops.by:owner": "1 [22]", "account.resumes.by:verdifax_admin": "1 [3]",
		// Verdifax's stop stood from before the period to 00:30 and again
		// from 23:30; the owner's from 23:00 to the period's end, so in all
		// the account was stopped 30 minutes and then one hour.
		"account.stopped_seconds": "5400 [2 3 22 30]", "account.stopped_seconds.by:verdifax_admin": "3600 [2 3 30]",
		"account.stopped_seconds.by:owner": "3600 [22]",
		"signoffs.refused":                 "1 [23]", "signoff.target_passed": "1 [24]", "signoff.target_passed.result:receipt": "1 [24]",
		"setup.changed": "1 [14]", "review.due": "1 [15]",
		"response_times.results": "4 [4 5 8 27]", "response_times.with_target": "3 [4 5 8]", "response_times.unsigned_as_of_head": "1 [5]",
		"response_times.longer_than_target.signed_after": "1 [8]", "response_times.longer_than_target.unsigned_as_of_head": "1 [5]",
		"response_times.first_signoff.reached": "3 [4 8 27]", "response_times.first_signoff.log.median_seconds": "301 [4 8 27]",
		"response_times.first_signoff.log.p90_seconds": "600 [4 8 27]", "response_times.first_signoff.log.longest_seconds": "600 [4 8 27]",
		"response_times.first_signoff.record.median_seconds":   "300 [4 8 27]",
		"response_times.decision_in_force.log.longest_seconds": "1200 [4 8 27]",
	}
	for name, w := range want {
		f, ok := byName[name]
		if got := fmt.Sprintf("%d %v", f.Value, f.Sequences); !ok || got != w {
			t.Errorf("%s = %s (present %v), want %s", name, got, ok, w)
		}
	}
	for name := range byName {
		if strings.HasPrefix(name, "runs.sealed") && byName[name].Value == 0 {
			t.Errorf("%s: a figure with nothing to count is left out", name)
		}
	}
	for i := 1; i < len(figs); i++ {
		if figs[i-1].Name >= figs[i].Name {
			t.Fatalf("figures out of order: %s then %s", figs[i-1].Name, figs[i].Name)
		}
	}
}

// R331: from is included, to is excluded, and every clock is read as the
// instant it states, whatever its offset.
func TestAnEventIsPlacedByItsOwnSealedTime(t *testing.T) {
	events := vectorFeed()
	for _, c := range []struct {
		from, to string
		want     int64
	}{
		{"2026-11-01T01:00:00Z", "2026-11-01T01:00:01Z", 1},
		{"2026-11-01T00:59:59Z", "2026-11-01T01:00:00Z", 0},
		{"2026-11-02T00:00:00Z", "2026-11-03T00:00:00Z", 1},
	} {
		figs, err := Summarize(events, at(c.from), at(c.to), vectorHead)
		if err != nil {
			t.Fatal(err)
		}
		var got int64
		for _, f := range figs {
			if f.Name == "runs.sealed" {
				got = f.Value
			}
		}
		if got != c.want {
			t.Errorf("runs.sealed from %s to %s = %d, want %d", c.from, c.to, got, c.want)
		}
	}
	// An event after the head is not counted, however it is placed.
	short := vectorHead
	short.Sequence = 3
	figs, _ := Summarize(events, vectorFrom, vectorTo, short)
	for _, f := range figs {
		if f.Name == "runs.sealed" {
			t.Fatal("an event after the head was counted")
		}
	}
	// A sealed time that is not RFC 3339 makes the feed uncountable.
	bad := append([]Event(nil), events...)
	bad[3].Entry = json.RawMessage(`{"run_id":10,"sealed_at":"yesterday"}`)
	if _, err := Summarize(bad, vectorFrom, vectorTo, vectorHead); err == nil {
		t.Fatal("an unreadable sealed time must refuse the count")
	}
}

// R332: the report states each result's waits as measured, on the public
// log first with the record times beside, never judging them; a request
// target applies only where none is sealed.
func TestTheResponseTimesAreMeasuredAsTheRulesSay(t *testing.T) {
	rep, err := ResponseTimes(vectorFeed(), vectorFrom, vectorTo, vectorHead, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 4 {
		t.Fatalf("results %+v", rep.Results)
	}
	r10, r11, r12, r20 := rep.Results[0], rep.Results[1], rep.Results[2], rep.Results[3]
	if r20.DecisionInForce == nil || r20.DecisionInForce.Decision != "approve" || r20.Standing != StandingSignedNoTarget {
		t.Errorf("run 20: the job's approval governs: %+v", r20)
	}
	if r10.Standing != StandingWithinTarget || r10.ComparedOn != OnPublicLog || r10.ComparedSeconds != 301 ||
		r10.FirstSignOff.RecordSeconds != 300 || *r10.FirstSignOff.LogSeconds != 301 || r10.DecisionInForce.Sequence != 7 ||
		r10.DecisionInForce.Decision != "reject" || r10.FirstApproval.Sequence != 6 {
		t.Errorf("run 10: %+v", r10)
	}
	if r11.Standing != StandingUnsignedLongerAsOfHead || r11.Compared != EndFirstApproval || r11.FirstSignOff != nil ||
		r11.ComparedSeconds != unix("2026-11-02T01:00:00Z")-unix("2026-11-01T00:10:05Z") {
		t.Errorf("run 11: %+v", r11)
	}
	if r12.Standing != StandingLongerSignedAfter || r12.ComparedSeconds != 600 || r12.Target.Source != TargetSealed {
		t.Errorf("run 12: %+v", r12)
	}
	// A negative wait is stated as measured: the sign-off's entry reached
	// the log before the result's.
	events := vectorFeed()
	var e map[string]any
	_ = json.Unmarshal(events[5].Entry, &e)
	e["anchor"] = map[string]any{"integrated_time": unix("2026-11-01T00:59:00Z")}
	events[5].Entry, _ = json.Marshal(e)
	neg, _ := ResponseTimes(events, vectorFrom, vectorTo, vectorHead, nil)
	if got := *neg.Results[0].FirstSignOff.LogSeconds; got != -61 {
		t.Errorf("a negative wait is %d, want -61 as measured", got)
	}
	// A request target applies only to results that seal none.
	plain := vectorFeed()[:3]
	plain = append(plain, Event{Sequence: 4, Kind: kindRunSealed, EventHash: hashOf(4), RunID: 30,
		Entry: json.RawMessage(`{"run_id":30,"signoff_required":true,"sealed_at":"2026-11-01T01:00:00Z"}`)})
	req := int64(45)
	got, _ := ResponseTimes(plain, vectorFrom, vectorTo, Head{Sequence: 4, StatedAt: at("2026-11-01T01:00:30Z")}, &req)
	if len(got.Results) != 1 || got.Results[0].Target == nil || got.Results[0].Target.Source != TargetRequest ||
		got.Results[0].Standing != StandingUnsignedWithinAsOfHead || got.Results[0].ComparedOn != OnRecordTime || got.Results[0].ComparedSeconds != 30 {
		t.Errorf("request target: %+v", got.Results)
	}
	sealedOnly, _ := ResponseTimes(vectorFeed(), vectorFrom, vectorTo, vectorHead, &req)
	if !reflect.DeepEqual(sealedOnly.Results[0].Target, rep.Results[0].Target) {
		t.Errorf("a request target replaced a sealed one: %+v", sealedOnly.Results[0].Target)
	}
}

// R332: the median is the lower middle, the 90th percentile the nearest
// rank, the longest the first longest in feed order.
func TestTheSpreadIsTheStatedOne(t *testing.T) {
	waits := []wait{{1, 40, EventRef{1, "a"}}, {2, 10, EventRef{2, "b"}}, {3, 40, EventRef{3, "c"}}, {4, 20, EventRef{4, "d"}}}
	s := spreadOf(waits)
	if s.MedianSeconds != 20 || s.P90Seconds != 40 || s.LongestSeconds != 40 || s.LongestRunID != 1 || s.Count != 4 {
		t.Fatalf("spread %+v", s)
	}
	ten := make([]wait, 10)
	for i := range ten {
		ten[i] = wait{int64(i), int64(i + 1), EventRef{int64(i), ""}}
	}
	if s := spreadOf(ten); s.MedianSeconds != 5 || s.P90Seconds != 9 {
		t.Fatalf("ten waits: %+v", s)
	}
	if spreadOf(nil) != nil {
		t.Fatal("no waits, no spread")
	}
}

// R331: a code is written into a figure's name in one way only.
func TestACodeIsWrittenIntoANameOneWay(t *testing.T) {
	for in, want := range map[string]string{"ACCOUNT_STOPPED": "account_stopped", "": "none", "A B/C": "a_b_c", "x.y-z": "x.y-z",
		strings.Repeat("Q", 80): strings.Repeat("q", 64)} {
		if got := codePart(in); got != want {
			t.Errorf("codePart(%q) = %q, want %q", in, got, want)
		}
	}
}
