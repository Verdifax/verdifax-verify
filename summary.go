package main

// The board summary (round 64, v0.38.0). A period summary,
// verdifax.period-summary.v1, is a statement Verdifax makes beside an
// account's signal feed, never an event in it: one period's figures, each
// committed to the digest of the exact feed events it counts, counted from
// the feed up to a feed head stated after the period, and anchored on the
// public log under its own leaf kind (period_summary).
//
// --summary summary.json --signals feed.json checks the feed as --signals
// does, then the summary: its hash, leaf and public-log entry; that its head
// statement (the feed page's own head when it is the summary's, or the one
// given with --summary-head) is the summary's, names the feed's event and was
// stated after the period ended; that no event after the head was sealed
// before the period ended; and it recounts every figure and every events
// digest with the counting rules the server uses (internal/feedcount, a
// byte-for-byte copy of the server's). It prints each figure in plain words
// with whether the recount reached it. --feed-head-max-age does not apply to
// the summary's own head: a summary speaks of its period, as of its head.
//
// The figures are counts and measured times. A sign-off figure says a
// registered approver key signed; it never says a person approved, and no
// figure says a result was right or a time too long.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/feedcount"
)

// SummaryFigureCheck is one stated figure and its recount.
type SummaryFigureCheck struct {
	Name      string `json:"name"`
	Words     string `json:"words"`
	Stated    int64  `json:"stated"`
	Recounted *int64 `json:"recounted,omitempty"`
	// Same says the recount reached the stated value and the stated digest
	// of the exact events the figure counts.
	Same bool   `json:"same"`
	Why  string `json:"why,omitempty"`
}

// SummaryCheck is the --summary result.
type SummaryCheck struct {
	Checked      bool                 `json:"checked"`
	OK           bool                 `json:"ok"`
	Account      string               `json:"account,omitempty"`
	From         string               `json:"from,omitempty"`
	To           string               `json:"to,omitempty"`
	StatedAt     string               `json:"stated_at,omitempty"`
	OnPublicLog  string               `json:"on_public_log,omitempty"`
	LogEntry     string               `json:"log_entry_id,omitempty"`
	HeadSequence int64                `json:"head_sequence,omitempty"`
	HeadStatedAt string               `json:"head_stated_at,omitempty"`
	HeadOnLog    string               `json:"head_on_public_log,omitempty"`
	Figures      []SummaryFigureCheck `json:"figures,omitempty"`
	// Unstated are figures the feed counts that the summary does not state.
	Unstated []string        `json:"unstated,omitempty"`
	Feed     SignalFeedCheck `json:"feed"`
	Notes    []string        `json:"notes,omitempty"`
	Reason   string          `json:"reason,omitempty"`
}

// readSummaryHead reads --summary-head: the summary's head statement, as a
// feed page served it.
func readSummaryHead(path string) (*artifacts.FeedHead, error) {
	if path == "" {
		return nil, nil
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil, fmt.Errorf("read --summary-head: %w", readErr)
	}
	var h artifacts.FeedHead
	if decodeErr := strictDecode(data, &h); decodeErr != nil {
		return nil, fmt.Errorf("--summary-head is not a feed head statement: %w", decodeErr)
	}
	return &h, nil
}

// checkSummary checks a period summary with the account's feed.
func checkSummary(summaryData, feedData []byte, given *artifacts.FeedHead, after *signalPoint, ownerKeys []string, documents map[string][]byte) SummaryCheck {
	c := SummaryCheck{Checked: true}
	fail := func(format string, args ...any) SummaryCheck {
		c.Reason, c.OK = fmt.Sprintf(format, args...), false
		return c
	}
	var p artifacts.PeriodSummary
	if decodeErr := strictDecode(summaryData, &p); decodeErr != nil {
		return fail("the summary is not a %s statement: %v", artifacts.PeriodSummaryFormat, decodeErr)
	}
	c.Account, c.From, c.To, c.StatedAt, c.HeadSequence = p.Account, p.From, p.To, p.StatedAt, p.HeadSequence
	if p.Anchor == nil {
		return fail("the summary carries no public-log entry; a summary is served only once it is on the log")
	}
	if entryErr := checkSealedEntry(p.Validate(), p.ComputeHash(), p.SummaryHash, p.StatedAt, "stated_at", p.Anchor,
		artifacts.PeriodSummaryKind, p.LeafHash()); entryErr != nil {
		return fail("the summary: %v", entryErr)
	}
	c.OnPublicLog, c.LogEntry = logTimeText(p.Anchor.IntegratedTime), p.Anchor.LogEntryID
	if p.CountingRules != feedcount.CountingRules {
		return fail("the summary was counted by rules %q, and this verifier holds %s", safePrefix(p.CountingRules), feedcount.CountingRules)
	}
	from, _ := time.Parse(time.RFC3339, p.From)
	to, _ := time.Parse(time.RFC3339, p.To)
	c.Feed = checkSignalFeedPinned(feedData, after, ownerKeys, feedOptions{documents: documents, headAgeExempt: p.HeadStatementHash})
	if !c.Feed.OK {
		return fail("the feed: %s", c.Feed.Reason)
	}
	if c.Feed.Account != p.Account {
		return fail("the summary belongs to %s, and the feed given belongs to %s", p.Account, c.Feed.Account)
	}
	if why := summaryHeadInFeed(&p, &c.Feed, after); why != "" {
		return fail("%s", why)
	}
	head := given
	if h := c.Feed.head; h != nil && h.HeadStatementHash == p.HeadStatementHash {
		head = h
	}
	if head == nil {
		return fail("the head statement of the summary (%s) is neither the head of the feed page nor given with --summary-head, so the time it was stated cannot be shown; "+
			"fetch the feed when nothing new is in it, or give the head statement saved with the summary (GET /account/summaries/{id}/head) with --summary-head", truncate(p.HeadStatementHash, 16))
	}
	if head != c.Feed.head {
		if headErr := checkSealedEntry(head.Validate(), head.ComputeHash(), head.HeadStatementHash, head.StatedAt, "stated_at", head.Anchor,
			artifacts.FeedHeadKind, head.LeafHash()); headErr != nil {
			return fail("the head statement given with --summary-head: %v", headErr)
		}
	}
	headAt, _ := time.Parse(time.RFC3339Nano, head.StatedAt)
	switch {
	case head.HeadStatementHash != p.HeadStatementHash:
		return fail("the head statement given is %s, and the summary names %s", truncate(head.HeadStatementHash, 16), truncate(p.HeadStatementHash, 16))
	case head.Account != p.Account || head.Sequence != p.HeadSequence || head.HeadHash != p.HeadHash:
		return fail("the head statement of the summary names event %d of %s, and the summary names event %d of %s", head.Sequence, head.Account, p.HeadSequence, p.Account)
	case !headAt.After(to):
		return fail("the head of the summary was stated at %s, not after the end of the period, %s, so an event of the period could be missing from what it counted", head.StatedAt, p.To)
	case head.Anchor == nil || head.Anchor.IntegratedTime < to.Unix():
		return fail("the head of the summary is on the public log at %s, before the end of the period, %s", logTimeText(headLogged(head)), p.To)
	}
	c.HeadStatedAt, c.HeadOnLog = head.StatedAt, logTimeText(head.Anchor.IntegratedTime)
	if why := eventsAfterHead(&p, &c.Feed, to); why != "" {
		return fail("%s", why)
	}
	counted, countErr := feedcount.Summarize(countedEvents(c.Feed.events, p.HeadSequence), from, to, countHead(head))
	if countErr != nil {
		return fail("the feed cannot be counted: %v", countErr)
	}
	recounted := map[string]feedcount.Figure{}
	for _, f := range counted {
		recounted[f.Name] = f
	}
	differ := 0
	for _, f := range p.Figures {
		fc := SummaryFigureCheck{Name: f.Name, Words: figureWords(f.Name), Stated: f.Value}
		r, found := recounted[f.Name]
		switch {
		case !found:
			fc.Why = "the feed counts nothing under this figure"
		case r.Value != f.Value:
			v := r.Value
			fc.Recounted, fc.Why = &v, fmt.Sprintf("stated %d, recounted %d", f.Value, r.Value)
		case figureDigest(r) != f.EventsDigest:
			v := r.Value
			fc.Recounted, fc.Why = &v, "the same value over a different list of events"
		default:
			v := r.Value
			fc.Recounted, fc.Same = &v, true
		}
		if !fc.Same {
			differ++
		}
		delete(recounted, f.Name)
		c.Figures = append(c.Figures, fc)
	}
	for name, r := range recounted {
		c.Unstated = append(c.Unstated, fmt.Sprintf("%s (%s): %d", name, figureWords(name), r.Value))
	}
	sort.Strings(c.Unstated)
	if c.Feed.ContinuityFrom != "start" {
		c.Notes = append(c.Notes, fmt.Sprintf("the feed given starts at event %d; a stop placed, a sign-off or a deletion before it counts in some figures, so give the feed from its start.", c.Feed.First))
	}
	if differ > 0 || len(c.Unstated) > 0 {
		return fail("%d stated figure(s) are not what the feed counts, and %d figure(s) the feed counts are not stated", differ, len(c.Unstated))
	}
	c.OK = true
	return c
}

func headLogged(h *artifacts.FeedHead) int64 {
	if h == nil || h.Anchor == nil {
		return 0
	}
	return h.Anchor.IntegratedTime
}

// figureDigest is the digest of the events a recounted figure lists.
func figureDigest(f feedcount.Figure) string {
	refs := make([]artifacts.SummaryEvent, len(f.Events))
	for i, e := range f.Events {
		refs[i] = artifacts.SummaryEvent{Sequence: e.Sequence, EventHash: e.EventHash}
	}
	return artifacts.SummaryEventsDigest(refs)
}

// summaryHeadInFeed holds the summary's head event to the feed given.
func summaryHeadInFeed(p *artifacts.PeriodSummary, feed *SignalFeedCheck, after *signalPoint) string {
	if p.HeadSequence > feed.Last {
		return fmt.Sprintf("the feed given ends at event %d, before the head of the summary, event %d", feed.Last, p.HeadSequence)
	}
	if p.HeadSequence < feed.First {
		if after != nil && after.sequence == p.HeadSequence && after.hash == p.HeadHash {
			return ""
		}
		return fmt.Sprintf("the feed given starts at event %d, after the head of the summary, event %d; give it from before the period", feed.First, p.HeadSequence)
	}
	for i := range feed.events {
		if d := &feed.events[i].Data; d.Sequence == p.HeadSequence {
			if d.EventHash != p.HeadHash {
				return fmt.Sprintf("the head of the summary names event %d with hash %s, and event %d of the feed is %s", p.HeadSequence, truncate(p.HeadHash, 16), d.Sequence, truncate(d.EventHash, 16))
			}
			return ""
		}
	}
	return fmt.Sprintf("the feed given does not hold event %d, the head of the summary", p.HeadSequence)
}

// eventsAfterHead fails an event after the summary's head that the counting
// rules place before the period's end: the summary did not count it. An
// event whose record was deleted has no sealed time to read and is noted.
func eventsAfterHead(p *artifacts.PeriodSummary, feed *SignalFeedCheck, to time.Time) string {
	var later []feedcount.Event
	at := map[int64]string{}
	for _, e := range feed.Entries {
		at[e.Sequence] = e.At
	}
	var last int64
	for _, ev := range countedEvents(feed.events, 0) {
		if ev.Sequence > p.HeadSequence {
			later = append(later, ev)
			last = ev.Sequence
		}
	}
	if len(later) == 0 {
		return ""
	}
	figs, countErr := feedcount.Summarize(later, time.Time{}, to, feedcount.Head{Sequence: last})
	if countErr != nil {
		return fmt.Sprintf("the events after the head of the summary cannot be counted: %v", countErr)
	}
	placed := map[int64]bool{}
	for _, f := range figs {
		if strings.HasSuffix(f.Name, "_seconds") {
			continue
		}
		for _, e := range f.Events {
			placed[e.Sequence] = true
		}
	}
	var seqs []int64
	for s := range placed {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	if len(seqs) > 0 {
		s := seqs[0]
		return fmt.Sprintf("event %d, after the head of the summary (event %d), was sealed at %s, before the end of the period, %s, so the summary did not count it", s, p.HeadSequence, at[s], p.To)
	}
	return ""
}

// figureWords says a figure's name in plain words. A sign-off figure says a
// registered approver key signed, never that a person approved.
func figureWords(name string) string {
	base, qualifier, _ := strings.Cut(name, ":")
	by := func(v string) string {
		switch v {
		case "owner":
			return "the owner"
		case "verdifax_admin":
			return "Verdifax"
		case "unstated":
			return "a decider the record does not state"
		}
		return v
	}
	words := map[string]string{
		"runs.sealed":                            "runs sealed, each a successful run with its record",
		"runs.sealed.job_steps":                  "runs sealed as steps of a job",
		"runs.sealed.signoff_required":           "runs sealed whose rule requires a sign-off",
		"runs.sealed.target_sealed":              "runs sealed with a response target sealed in the result",
		"runs.refused":                           "runs refused",
		"runs.refused.receipt":                   "runs refused with a " + qualifier,
		"runs.refused.code":                      "runs refused with code " + qualifier,
		"runs.refused.account_stopped":           "runs refused because the account was stopped",
		"runs.refused.data_use_declared":         "runs refused that sealed a declared data use",
		"runs.refused.target_sealed":             "runs refused with a response target sealed in the receipt",
		"runs.halted":                            "runs halted",
		"runs.halted.receipt":                    "runs halted with a " + qualifier,
		"runs.halted.code":                       "runs halted with code " + qualifier,
		"runs.halted.target_sealed":              "runs halted with a response target sealed in the receipt",
		"runs.failed":                            "runs that failed with a server error",
		"runs.failed.class":                      "runs that failed with error class " + qualifier,
		"runs.failed.stage":                      "runs that failed at stage " + qualifier,
		"signoffs.made":                          "sign-offs a registered approver key signed",
		"signoffs.made.target":                   "sign-offs a registered approver key signed on a " + qualifier,
		"signoffs.refused":                       "sign-offs refused because the account was stopped",
		"results.signoff_required.none_in_force": "results whose rule requires a sign-off, with no sign-off in force at the period's end",
		"policy.changed":                         "policy changes",
		"policy.changed.signed":                  "policy changes signed by the owner's request key",
		"policy.changed.chain":                   "policy changes to " + qualifier + " policies",
		"keys.created":                           "keys created",
		"keys.created.by":                        "keys created by " + by(qualifier),
		"keys.revoked":                           "keys revoked",
		"keys.revoked.by":                        "keys revoked by " + by(qualifier),
		"approvers.registered":                   "approver keys registered",
		"approvers.registered.by":                "approver keys registered by " + by(qualifier),
		"approvers.revoked":                      "approver keys revoked",
		"approvers.revoked.by":                   "approver keys revoked by " + by(qualifier),
		"account.changed":                        "account changes",
		"account.changed.by":                     "account changes by " + by(qualifier),
		"runs.deleted":                           "records deleted",
		"runs.deleted.by":                        "records deleted by " + by(qualifier),
		"runs.published":                         "records made public",
		"runs.published.by":                      "records made public by " + by(qualifier),
		"runs.unpublished":                       "records withdrawn from public view",
		"runs.unpublished.by":                    "records withdrawn from public view by " + by(qualifier),
		"chain.gaps":                             "declared restore gaps",
		"chain.interrupted":                      "entries the public log never confirmed, each closed by its own record",
		"setup.changed":                          "setup changes the policy's watch saw",
		"review.due":                             "declared policy review dates that passed",
		"account.stops":                          "stops placed on the account",
		"account.stops.by":                       "stops placed on the account by " + by(qualifier),
		"account.resumes":                        "stops lifted",
		"account.resumes.by":                     "stops lifted by " + by(qualifier),
		"account.stopped_seconds":                "seconds the account was stopped inside the period, any stop standing",
		"account.stopped_seconds.by":             "seconds the account was stopped inside the period by " + by(qualifier),
		"signoff.target_passed":                  "response targets that passed with no sign-off of the compared kind on the public log",
		"signoff.target_passed.result":           "response targets that passed on a " + qualifier,
		"events.record_deleted.unplaced":         "events whose record was deleted, inside the period's span of events, whose sealed time can no longer be read",
	}
	if w, ok := words[base]; ok {
		return w
	}
	switch {
	case strings.HasPrefix(name, "signoffs.made."):
		return "sign-offs in which a registered approver key signed " + strings.TrimPrefix(name, "signoffs.made.")
	case strings.HasPrefix(name, "results.decision_in_force."):
		return "results whose decision in force at the period's end is " + strings.TrimPrefix(name, "results.decision_in_force.") + ", as a registered approver key signed it"
	case strings.HasPrefix(name, "response_times."):
		return responseTimeFigureWords(strings.TrimPrefix(name, "response_times."))
	}
	return name
}

// responseTimeFigureWords says a response-time figure in plain words.
func responseTimeFigureWords(rest string) string {
	lists := map[string]string{
		"results":                                "results measured for a response time",
		"results_deleted":                        "results measured whose run was deleted",
		"with_target":                            "results with a response target",
		"unsigned_as_of_head":                    "results with no sign-off of the compared kind as of the head",
		"longer_than_target.signed_after":        "results whose wait was longer than the target, signed after it",
		"longer_than_target.unsigned_as_of_head": "results unsigned as of the head and longer than the target",
	}
	if w, ok := lists[rest]; ok {
		return w
	}
	ends := map[string]string{"first_signoff": "the first sign-off", "first_approval": "the first approval", "decision_in_force": "the decision in force"}
	parts := strings.Split(rest, ".")
	end, known := ends[parts[0]]
	if !known {
		return "response_times." + rest
	}
	if len(parts) == 2 && parts[1] == "reached" {
		return "results that reached " + end
	}
	if len(parts) == 3 {
		clock := map[string]string{"log": "on the public log", "record": "on the sealed record times"}[parts[1]]
		stat := map[string]string{"median_seconds": "median (lower middle) wait in seconds", "p90_seconds": "90th percentile wait in seconds",
			"longest_seconds": "longest wait in seconds"}[parts[2]]
		if clock != "" && stat != "" {
			return stat + " to " + end + ", " + clock + ", as measured"
		}
	}
	return "response_times." + rest
}

// runSummaryMode is --summary with --signals.
func runSummaryMode(summaryPath, headPath, feedPath, after, ownerKeyFiles, policyFiles string, asJSON, allowPartial bool) int {
	point, pointErr := parseSignalPoint(after)
	documents, documentsErr := readFeedPolicies(policyFiles)
	ownerKeys, keysErr := readOwnerKeys(ownerKeyFiles)
	head, headErr := readSummaryHead(headPath)
	for _, flagErr := range []error{pointErr, documentsErr, keysErr, headErr} {
		if flagErr != nil {
			fmt.Fprintln(os.Stderr, "verdifax-verify:", flagErr)
			return 2
		}
	}
	summaryData, summaryErr := os.ReadFile(summaryPath)
	feedData, feedErr := os.ReadFile(feedPath)
	for name, readErr := range map[string]error{"--summary": summaryErr, "--signals": feedErr} {
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "verdifax-verify: read %s: %v\n", name, readErr)
			return 2
		}
	}
	c := checkSummary(summaryData, feedData, head, point, ownerKeys, documents)
	if asJSON {
		encoded, _ := json.MarshalIndent(c, "", "  ")
		fmt.Println(string(encoded))
	} else {
		printSummary(&c)
	}
	switch {
	case !c.OK:
		return 1
	case c.Feed.CommittedLater > 0 && !allowPartial:
		return 3
	}
	return 0
}

// printSummary renders the human report.
func printSummary(c *SummaryCheck) {
	fmt.Println("Verdifax period summary verification")
	if c.OK {
		fmt.Printf("  %-18s✓ %s, %s to %s, stated %s, on the public log %s (entry %s)\n", "Summary:", c.Account, c.From, c.To, c.StatedAt, c.OnPublicLog, c.LogEntry)
		fmt.Printf("  %-18scounted up to event %d, whose head was stated %s and logged %s, after the period ended\n", "Head:", c.HeadSequence, c.HeadStatedAt, c.HeadOnLog)
	} else {
		fmt.Printf("  %-18s✗ FAILED · %s\n", "Summary:", c.Reason)
	}
	for _, f := range c.Figures {
		if f.Same {
			fmt.Printf("    ✓ %s: %d, recounted the same, over the same events (%s)\n", f.Words, f.Stated, f.Name)
		} else {
			fmt.Printf("    ✗ %s: %s (%s)\n", f.Words, f.Why, f.Name)
		}
	}
	for _, u := range c.Unstated {
		fmt.Printf("    ✗ not stated: %s\n", u)
	}
	for _, n := range append(c.Notes, c.Feed.Notes...) {
		fmt.Printf("  %-18s%s\n", "Note:", n)
	}
	fmt.Println("                    Every figure is a count or a measured time from the feed; a sign-off figure shows a registered approver key signed, and no figure judges a result")
}
