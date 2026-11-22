package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/feedcount"
)

// Round 64, part 2: the response-time report (--response-times) and the
// board summary (--summary), each recounted from the feed.

// reportFeed is a feed with results to measure: a record with a sealed
// target signed after it, a record that requires a sign-off and has none, a
// refused run, and a stop and its lift.
func reportFeed(t *testing.T) *feedBuilder {
	f := stopFeedStart(t, nil)
	f.runSealedTarget(&artifacts.SealedTarget{Within: 60, Compare: artifacts.TargetCompareFirstSignOff, Notice: artifacts.TargetNoticeHead})
	signed := f.runID
	f.runSealedTarget(nil)
	f.denyRun(false, strings.Repeat("4", 64))
	s := f.stopAccount("verdifax", 0, artifacts.StopSignoffsAccept, 0, false, nil)
	f.resumeAccount("verdifax", 0, s, nil)
	f.recordSignOff(signed, artifacts.SignOffApprove)
	return f
}

// atCheck sets this check's clock to after for the test.
func atCheck(t *testing.T, after time.Time) {
	before := checkClock
	checkClock = func() time.Time { return after }
	t.Cleanup(func() { checkClock = before })
}

// packOf is the server's response-time report with pack=1 for the feed.
func packOf(t *testing.T, f *feedBuilder, h *artifacts.FeedHead, from, to time.Time, request *int64) responseTimesPack {
	t.Helper()
	rep, err := feedcount.ResponseTimes(countedEvents(f.events, h.Sequence), from, to, countHead(h), request)
	if err != nil {
		t.Fatal(err)
	}
	return responseTimesPack{Form: feedcount.ResponseTimesForm, Account: feedAccount, From: from.UTC().Format(time.RFC3339Nano), To: to.UTC().Format(time.RFC3339Nano),
		CountingRules: feedcount.CountingRules, RequestTarget: request, HeadSequence: h.Sequence, Head: h, Results: rep.Results, Aggregates: rep.Aggregates,
		Feed: f.events}
}

// R342: a pack whose figures the feed gives verifies; each changed figure,
// a report of another period or target, and a pending claim over an old
// head fail.
func TestAResponseTimeReportIsRecounted(t *testing.T) {
	f := reportFeed(t)
	h := f.head()
	from, to := feedStart, feedStart.Add(time.Hour)
	headLogged := time.Unix(h.Anchor.IntegratedTime, 0)
	atCheck(t, headLogged.Add(time.Minute))
	request := int64(120)
	p := packOf(t, f, h, from, to, &request)
	c := checkResponseTimes(encode(t, p), nil, nil, nil, nil, time.Time{}, time.Time{})
	if !c.OK || !c.Recounted || len(c.Results) != 2 || c.Aggregates.FirstSignOff.Reached != 1 || c.Aggregates.UnsignedAsOfHead != 1 {
		t.Fatalf("a sound pack: %s %+v", c.Reason, c.Aggregates)
	}
	for name, b := range map[string]struct {
		mutate     func(p *responseTimesPack)
		target     *int64
		from, to   time.Time
		checkAfter time.Duration
		want       string
	}{
		"a result's wait": {func(p *responseTimesPack) { p.Results[0].ComparedSeconds++ }, nil, time.Time{}, time.Time{}, time.Minute, "compared_seconds stated"},
		"a standing":      {func(p *responseTimesPack) { p.Results[1].Standing = feedcount.StandingWithinTarget }, nil, time.Time{}, time.Time{}, time.Minute, "standing stated"},
		"an aggregate":    {func(p *responseTimesPack) { p.Aggregates.UnsignedAsOfHead = 0 }, nil, time.Time{}, time.Time{}, time.Minute, "unsigned_as_of_head stated 0"},
		"a result left out": {func(p *responseTimesPack) { p.Results = p.Results[:1] }, nil, time.Time{}, time.Time{}, time.Minute,
			"lists 1 result(s), and the feed holds 2"},
		"a median":                          {func(p *responseTimesPack) { p.Aggregates.FirstSignOff.PublicLog.MedianSeconds = 1 }, nil, time.Time{}, time.Time{}, time.Minute, "median_seconds"},
		"another target":                    {nil, func() *int64 { n := int64(30); return &n }(), time.Time{}, time.Time{}, time.Minute, "--target gives 30 seconds"},
		"another period":                    {nil, nil, from.Add(time.Minute), to, time.Minute, "give another period"},
		"other rules":                       {func(p *responseTimesPack) { p.CountingRules = "verdifax.period-summary-counting.v2" }, nil, time.Time{}, time.Time{}, time.Minute, "this verifier holds"},
		"a pending result over an old head": {nil, nil, time.Time{}, time.Time{}, 48 * time.Hour, "as of the feed's head, and the head statement"},
		"a head of another event":           {func(p *responseTimesPack) { p.HeadSequence-- }, nil, time.Time{}, time.Time{}, time.Minute, "carries is event"},
		"no feed":                           {func(p *responseTimesPack) { p.Feed = nil }, nil, time.Time{}, time.Time{}, time.Minute, "pack=1"},
	} {
		atCheck(t, headLogged.Add(b.checkAfter))
		q := packOf(t, f, h, from, to, &request)
		if b.mutate != nil {
			b.mutate(&q)
		}
		c := checkResponseTimes(encode(t, q), nil, nil, nil, b.target, b.from, b.to)
		if c.OK || !strings.Contains(c.Reason, b.want) {
			t.Errorf("%s: ok %v, reason %q, want %q", name, c.OK, c.Reason, b.want)
		}
	}
	// A report that states nothing as of the head is not held to its age.
	atCheck(t, headLogged.Add(48*time.Hour))
	settled := packOf(t, f, h, from, feedStart.Add(6*time.Minute), &request)
	if c := checkResponseTimes(encode(t, settled), nil, nil, nil, nil, time.Time{}, time.Time{}); !c.OK || len(c.Results) != 1 {
		t.Fatalf("a settled report over an old head: %s %d", c.Reason, len(c.Results))
	}
	// A plain feed page is measured for the period given.
	atCheck(t, headLogged.Add(time.Minute))
	c = checkResponseTimes(pageWithHead(t, f.events, h), nil, nil, nil, nil, from, to)
	if !c.OK || c.Recounted || len(c.Results) != 2 {
		t.Fatalf("a plain feed: %s", c.Reason)
	}
	if c := checkResponseTimes(pageWithHead(t, f.events, h), nil, nil, nil, nil, time.Time{}, time.Time{}); c.OK {
		t.Fatal("a plain feed with no period passed")
	}
}

// R342: the report's words state waits as measured and never judge them.
func TestResponseTimeWordsNeverJudge(t *testing.T) {
	for _, s := range []string{feedcount.StandingWithinTarget, feedcount.StandingLongerSignedAfter, feedcount.StandingUnsignedWithinAsOfHead,
		feedcount.StandingUnsignedLongerAsOfHead, feedcount.StandingSignedNoTarget, feedcount.StandingUnsignedNoTargetAsOfHead} {
		w := standingWords(s)
		if w == s || containsJudgment(w) {
			t.Errorf("standing %s reads %q", s, w)
		}
	}
	if w := seconds(-5); !strings.Contains(w, "-5 s") || !strings.Contains(w, "as measured") {
		t.Errorf("a negative wait reads %q", w)
	}
}

// containsJudgment reports a word the reports never use.
func containsJudgment(text string) bool {
	lower := strings.ToLower(text)
	for _, w := range []string{"late", "slow", "compliant", "correct", "pass rate", "a person approved", "overdue"} {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// summaryOf is the server's sealed summary of the period over the feed up to
// the head, stated at.
func summaryOf(t *testing.T, f *feedBuilder, h *artifacts.FeedHead, from, to, at time.Time, mutate func(*artifacts.PeriodSummary)) []byte {
	t.Helper()
	figs, err := feedcount.Summarize(countedEvents(f.events, h.Sequence), from, to, countHead(h))
	if err != nil {
		t.Fatal(err)
	}
	p := artifacts.PeriodSummary{Format: artifacts.PeriodSummaryFormat, Account: feedAccount, From: from.UTC().Format(time.RFC3339Nano),
		To: to.UTC().Format(time.RFC3339Nano), CountingRules: feedcount.CountingRules, HeadSequence: h.Sequence, HeadHash: h.HeadHash,
		HeadStatementHash: h.HeadStatementHash, StatedAt: at.UTC().Format(time.RFC3339Nano)}
	for _, fig := range figs {
		p.Figures = append(p.Figures, artifacts.SummaryFigure{Name: fig.Name, Value: fig.Value, EventsDigest: figureDigest(fig)})
	}
	if mutate != nil {
		mutate(&p)
	}
	p.SummaryHash = p.ComputeHash()
	p.Anchor = f.anchor(artifacts.PeriodSummaryKind, p.SummaryHash, p.LeafHash(), at)
	return encode(t, p)
}

// R343: a sealed summary verifies with its feed, every figure recounted the
// same and said in plain words, and its own head is not held to the feed's
// age limit.
func TestAPeriodSummaryIsRecounted(t *testing.T) {
	f := reportFeed(t)
	h := f.head()
	from, to := feedStart, time.Unix(h.Anchor.IntegratedTime, 0).Add(-time.Minute)
	stated := time.Unix(h.Anchor.IntegratedTime, 0).Add(time.Minute)
	atCheck(t, stated.Add(30*24*time.Hour))
	c := checkSummary(summaryOf(t, f, h, from, to, stated, nil), pageWithHead(t, f.events, h), nil, nil, nil, nil)
	if !c.OK {
		t.Fatalf("a sound summary fails: %s", c.Reason)
	}
	words := map[string]string{}
	for _, fig := range c.Figures {
		if !fig.Same {
			t.Errorf("figure %s not recounted the same: %s", fig.Name, fig.Why)
		}
		words[fig.Name] = fig.Words
		if containsJudgment(fig.Words) || fig.Words == fig.Name {
			t.Errorf("figure %s reads %q", fig.Name, fig.Words)
		}
	}
	for name, want := range map[string]string{"signoffs.made.approve": "a registered approver key signed approve",
		"results.decision_in_force.approve": "as a registered approver key signed it", "account.stops.by:verdifax_admin": "by Verdifax",
		"runs.sealed.signoff_required": "requires a sign-off"} {
		if !strings.Contains(words[name], want) {
			t.Errorf("figure %s reads %q, want %q", name, words[name], want)
		}
	}
}

// R343: each break of a summary, its head or its figures fails, and says
// which figure.
func TestABrokenPeriodSummaryFails(t *testing.T) {
	f := reportFeed(t)
	h := f.head()
	from, to := feedStart, time.Unix(h.Anchor.IntegratedTime, 0).Add(-time.Minute)
	stated := time.Unix(h.Anchor.IntegratedTime, 0).Add(time.Minute)
	atCheck(t, stated.Add(time.Minute))
	page := pageWithHead(t, f.events, h)
	for name, b := range map[string]struct {
		mutate func(*artifacts.PeriodSummary)
		want   string
	}{
		"a figure's value": {func(p *artifacts.PeriodSummary) {
			for i := range p.Figures {
				if p.Figures[i].Name == "runs.sealed" {
					p.Figures[i].Value++
				}
			}
		}, "1 stated figure(s) are not what the feed counts"},
		"a figure's events": {func(p *artifacts.PeriodSummary) {
			for i := range p.Figures {
				if p.Figures[i].Name == "runs.refused" {
					p.Figures[i].EventsDigest = strings.Repeat("0", 64)
				}
			}
		}, "1 stated figure(s)"},
		"a figure left out": {func(p *artifacts.PeriodSummary) { p.Figures = p.Figures[1:] }, "1 figure(s) the feed counts are not stated"},
		"a figure added": {func(p *artifacts.PeriodSummary) {
			p.Figures = append(p.Figures, artifacts.SummaryFigure{Name: "zz.made_up", Value: 0, EventsDigest: strings.Repeat("0", 64)})
		}, "1 stated figure(s)"},
		"a head stated before the end": {func(p *artifacts.PeriodSummary) {
			p.To = time.Unix(h.Anchor.IntegratedTime, 0).Add(time.Minute).UTC().Format(time.RFC3339)
		},
			"not after the period's end"},
		"other counting rules": {func(p *artifacts.PeriodSummary) { p.CountingRules = "verdifax.period-summary-counting.v2" }, "this verifier holds"},
		"another head":         {func(p *artifacts.PeriodSummary) { p.HeadStatementHash = strings.Repeat("5", 64) }, "neither the feed page's head"},
	} {
		c := checkSummary(summaryOf(t, f, h, from, to, stated, b.mutate), page, nil, nil, nil, nil)
		if c.OK || !strings.Contains(c.Reason, b.want) {
			t.Errorf("%s: ok %v, reason %q, want %q", name, c.OK, c.Reason, b.want)
		}
	}
	// A summary whose hash or entry is not its own.
	raw := summaryOf(t, f, h, from, to, stated, nil)
	var p artifacts.PeriodSummary
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	p.Figures[0].Value++
	if c := checkSummary(encode(t, p), page, nil, nil, nil, nil); c.OK || !strings.Contains(c.Reason, "hash recomputes") {
		t.Errorf("a changed summary: %s", c.Reason)
	}
	p.Figures[0].Value--
	p.Anchor = nil
	if c := checkSummary(encode(t, p), page, nil, nil, nil, nil); c.OK || !strings.Contains(c.Reason, "no public-log entry") {
		t.Errorf("an unlogged summary: %s", c.Reason)
	}
	// The feed must reach the summary's head.
	if c := checkSummary(raw, pageWithHead(t, f.events[:len(f.events)-1], f.headOver(len(f.events)-1)), nil, nil, nil, nil); c.OK || !strings.Contains(c.Reason, "before the summary's head") {
		t.Errorf("a feed short of the head: %s", c.Reason)
	}
}

// headOver is Verdifax's head statement over the feed's first n events.
func (f *feedBuilder) headOver(n int) *artifacts.FeedHead {
	return f.headOverAt(n, feedStart.Add(time.Duration(f.events[n-1].Data.Sequence)*time.Minute+time.Minute))
}

// headOverAt is the head statement over the first n events, stated at.
func (f *feedBuilder) headOverAt(n int, at time.Time) *artifacts.FeedHead {
	last := f.events[n-1].Data
	h := &artifacts.FeedHead{Format: artifacts.FeedHeadFormat, Account: feedAccount, Sequence: last.Sequence, HeadHash: last.EventHash,
		StatedAt: at.Format(time.RFC3339Nano)}
	h.HeadStatementHash = h.ComputeHash()
	h.Anchor = f.anchor(artifacts.FeedHeadKind, h.HeadStatementHash, h.LeafHash(), at)
	return h
}

// R343: with a later feed, the summary's head is given with --summary-head;
// an event after the head that was sealed before the period ended fails.
func TestASummaryOverALaterFeed(t *testing.T) {
	f := reportFeed(t)
	n := len(f.events)
	// The head over the first n events is stated 50 seconds after event
	// n+1 is sealed; the period ends 30 seconds after it.
	sealedAt := feedStart.Add(time.Duration(n+1) * time.Minute)
	h := f.headOverAt(n, sealedAt.Add(50*time.Second))
	f.runSealed()
	later := f.head()
	stated := time.Unix(later.Anchor.IntegratedTime, 0).Add(time.Minute)
	atCheck(t, time.Unix(later.Anchor.IntegratedTime, 0).Add(time.Minute))
	page := pageWithHead(t, f.events, later)
	settled := summaryOf(t, f, h, feedStart, sealedAt.Add(-30*time.Second), stated, nil)
	if c := checkSummary(settled, page, nil, nil, nil, nil); c.OK || !strings.Contains(c.Reason, "--summary-head") {
		t.Fatalf("without the summary's head: %s", c.Reason)
	}
	if c := checkSummary(settled, page, h, nil, nil, nil); !c.OK {
		t.Fatalf("with --summary-head: %s", c.Reason)
	}
	missed := summaryOf(t, f, h, feedStart, sealedAt.Add(30*time.Second), stated, nil)
	if c := checkSummary(missed, page, h, nil, nil, nil); c.OK || !strings.Contains(c.Reason, "so the summary did not count it") {
		t.Fatalf("an event after the head inside the period: %s", c.Reason)
	}
	forged := *h
	forged.StatedAt = h.StatedAt[:len(h.StatedAt)-1] + ".5Z"
	if c := checkSummary(settled, page, &forged, nil, nil, nil); c.OK {
		t.Fatal("a head statement whose hash is not its own passed")
	}
}

// R342, R343: the two modes print their reports and exit 0 for a sound
// report and 1 for a changed one, in words and as JSON.
func TestTheReportModesExit(t *testing.T) {
	f := reportFeed(t)
	h := f.head()
	logged := time.Unix(h.Anchor.IntegratedTime, 0)
	atCheck(t, logged.Add(time.Minute))
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	request := int64(120)
	pack := packOf(t, f, h, feedStart, feedStart.Add(time.Hour), &request)
	good := write("pack.json", encode(t, pack))
	pack.Aggregates.Results++
	bad := write("bad-pack.json", encode(t, pack))
	feed := write("feed.json", pageWithHead(t, f.events, h))
	summary := write("summary.json", summaryOf(t, f, h, feedStart, logged.Add(-time.Minute), logged.Add(time.Minute), nil))
	changed := write("changed.json", summaryOf(t, f, h, feedStart, logged.Add(-time.Minute), logged.Add(time.Minute), func(p *artifacts.PeriodSummary) {
		p.Figures[0].Value++
	}))
	for _, asJSON := range []bool{false, true} {
		for name, b := range map[string]struct {
			got, want int
		}{
			"a sound pack":          {runResponseTimesMode(good, "", "", "", "", "", "", asJSON, false), 0},
			"a changed pack":        {runResponseTimesMode(bad, "", "", "", "", "", "", asJSON, false), 1},
			"a plain feed measured": {runResponseTimesMode(feed, "", "", "", "", "2026-11-08T12:00:00Z", "2026-11-08T13:00:00Z", asJSON, false), 0},
			"a bad --target":        {runResponseTimesMode(good, "", "", "", "soon", "", "", asJSON, false), 2},
			"a sound summary":       {runSummaryMode(summary, "", feed, "", "", "", asJSON, false), 0},
			"a changed summary":     {runSummaryMode(changed, "", feed, "", "", "", asJSON, false), 1},
			"a missing head file":   {runSummaryMode(summary, filepath.Join(dir, "none.json"), feed, "", "", "", asJSON, false), 2},
		} {
			if b.got != b.want {
				t.Errorf("%s (json %v): exit %d, want %d", name, asJSON, b.got, b.want)
			}
		}
	}
}
