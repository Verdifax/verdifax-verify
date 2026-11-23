package main

// Response times (round 64, v0.38.0). GET /account/signoffs/response-times
// states, for each result placed in a period by its sealed time, the wait from
// the result's public-log entry to its first sign-off, its first approval and
// the decision in force, with the sealed record times beside, and the
// customer's own target where one applies (form verdifax.response-times.v1).
// With pack=1 it carries the feed it was counted from and the feed's head.
//
// --signals pack.json --response-times checks the pack's feed as --signals
// checks any feed, recounts the report from that feed alone with the same
// counting rules the server uses (internal/feedcount, a byte-for-byte copy of
// the server's), and fails any stated figure that differs. Given a plain feed
// page instead of a pack, it measures the period --from to --to and states
// the report. A result still unsigned as of the head, or one longer than its
// target, is a claim about the head's time, so it fails unless the head is
// within --feed-head-max-age; a report that makes no such claim is not held
// to the head's age.
//
// Every wait is stated as measured, a negative one too (a sign-off whose
// entry reached the log before its result's did). The report never says a
// wait was too long: a wait over the customer's target is "longer than the
// target".

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/feedcount"
)

// responseTimesPack is the body of GET /account/signoffs/response-times.
type responseTimesPack struct {
	Form          string                 `json:"form"`
	Account       string                 `json:"account"`
	From          string                 `json:"from"`
	To            string                 `json:"to"`
	CountingRules string                 `json:"counting_rules"`
	RequestTarget *int64                 `json:"request_target,omitempty"`
	HeadSequence  int64                  `json:"head_sequence"`
	Head          *artifacts.FeedHead    `json:"head"`
	Results       []feedcount.ResultTime `json:"results"`
	Aggregates    feedcount.Aggregates   `json:"aggregates"`
	Feed          []signalCloudEvent     `json:"feed,omitempty"`
}

// ResponseTimesCheck is the --response-times result.
type ResponseTimesCheck struct {
	Checked bool `json:"checked"`
	OK      bool `json:"ok"`
	// Recounted says the report was a pack whose stated figures were
	// recounted; false when a plain feed was measured.
	Recounted     bool                   `json:"recounted"`
	Account       string                 `json:"account,omitempty"`
	From          string                 `json:"from,omitempty"`
	To            string                 `json:"to,omitempty"`
	RequestTarget *int64                 `json:"request_target,omitempty"`
	HeadSequence  int64                  `json:"head_sequence,omitempty"`
	CompleteAsOf  string                 `json:"complete_as_of,omitempty"`
	CompleteAge   string                 `json:"complete_as_of_age,omitempty"`
	Results       []feedcount.ResultTime `json:"results,omitempty"`
	Aggregates    *feedcount.Aggregates  `json:"aggregates,omitempty"`
	// Differences are the stated figures the recount did not reach.
	Differences []string        `json:"differences,omitempty"`
	Feed        SignalFeedCheck `json:"feed"`
	Notes       []string        `json:"notes,omitempty"`
	Reason      string          `json:"reason,omitempty"`
}

// parseTargetFlag reads --target: whole seconds, or a duration such as 4h.
func parseTargetFlag(v string) (*int64, error) {
	if v == "" {
		return nil, nil
	}
	var seconds int64
	if n, parseErr := strconv.ParseInt(v, 10, 64); parseErr == nil {
		seconds = n
	} else {
		d, durationErr := time.ParseDuration(v)
		if durationErr != nil || d%time.Second != 0 {
			return nil, fmt.Errorf("--target must be whole seconds or a duration such as 4h, not %q", v)
		}
		seconds = int64(d / time.Second)
	}
	if seconds < 1 || seconds > artifacts.MaxTargetSeconds {
		return nil, fmt.Errorf("--target must be from 1 second to 366 days, not %q", v)
	}
	return &seconds, nil
}

// parseInstantFlag reads --from or --to, an RFC 3339 time, or nothing.
func parseInstantFlag(name, v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	t, parseErr := time.Parse(time.RFC3339Nano, v)
	if parseErr != nil {
		return time.Time{}, fmt.Errorf("--%s must be an RFC 3339 time such as 2026-11-01T00:00:00Z, not %q", name, v)
	}
	return t, nil
}

// countedEvents is a checked feed's events as the counting rules read them.
func countedEvents(events []signalCloudEvent, upTo int64) []feedcount.Event {
	out := make([]feedcount.Event, 0, len(events))
	for i := range events {
		d := &events[i].Data
		if upTo > 0 && d.Sequence > upTo {
			continue
		}
		out = append(out, feedcount.Event{Sequence: d.Sequence, Kind: d.Kind, EventHash: d.EventHash, RunID: d.RunID, Entry: d.Entry, Deleted: d.Deleted != nil})
	}
	return out
}

// countHead is a head statement as the counting rules read it: its place,
// its public-log time and its sealed time.
func countHead(h *artifacts.FeedHead) feedcount.Head {
	out := feedcount.Head{Sequence: h.Sequence}
	out.StatedAt, _ = time.Parse(time.RFC3339Nano, h.StatedAt)
	if h.Anchor != nil && h.Anchor.IntegratedTime > 0 {
		out.Logged = h.Anchor.IntegratedTime
	}
	return out
}

// isResponseTimesPack reports a file that is a response-time report.
func isResponseTimesPack(data []byte) bool {
	var probe struct {
		Form string `json:"form"`
	}
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && trimmed[0] == '{' && json.Unmarshal(trimmed, &probe) == nil && probe.Form == feedcount.ResponseTimesForm
}

// headClaims lists the results whose standing is a claim about the head's
// time: still pending (unsigned as of the head) or past the target with no
// sign-off as of the head. A result signed after its target passed is
// shown by its sign-off, whatever the head's age.
func headClaims(results []feedcount.ResultTime) []string {
	var out []string
	for _, r := range results {
		switch r.Standing {
		case feedcount.StandingUnsignedWithinAsOfHead, feedcount.StandingUnsignedLongerAsOfHead, feedcount.StandingUnsignedNoTargetAsOfHead:
			out = append(out, fmt.Sprintf("the %s of run %d", r.ResultKind, r.RunID))
		}
	}
	return out
}

// checkResponseTimes checks a pack, or measures a plain feed page, with the
// options of the --signals check.
func checkResponseTimes(data []byte, after *signalPoint, ownerKeys []string, documents map[string][]byte, request *int64, from, to time.Time) ResponseTimesCheck {
	c := ResponseTimesCheck{Checked: true}
	fail := func(format string, args ...any) ResponseTimesCheck {
		c.Reason, c.OK, c.Results, c.Aggregates = fmt.Sprintf(format, args...), false, nil, nil
		return c
	}
	opts := feedOptions{documents: documents, headAgeApart: true}
	var stated *responseTimesPack
	feedData := data
	if isResponseTimesPack(data) {
		var p responseTimesPack
		if decodeErr := strictDecode(bytes.TrimSpace(data), &p); decodeErr != nil {
			return fail("the report is not a %s body: %v", feedcount.ResponseTimesForm, decodeErr)
		}
		stated, c.Recounted = &p, true
		switch {
		case p.CountingRules != feedcount.CountingRules:
			return fail("the report was counted by rules %q, and this verifier holds %s", safePrefix(p.CountingRules), feedcount.CountingRules)
		case p.Head == nil:
			return fail("the report carries no feed head, so nothing it states about a result unsigned as of a head can be checked; the account's feed had no event when it was made")
		case len(p.Feed) == 0:
			return fail("the report carries no feed to recount it from; ask for it with pack=1")
		case p.HeadSequence != p.Head.Sequence:
			return fail("the report says it was counted up to event %d, and the head it carries is that of event %d", p.HeadSequence, p.Head.Sequence)
		}
		statedFrom, fromErr := time.Parse(time.RFC3339Nano, p.From)
		statedTo, toErr := time.Parse(time.RFC3339Nano, p.To)
		switch {
		case fromErr != nil || toErr != nil:
			return fail("the period of the report (%q to %q) is not two RFC 3339 times", safePrefix(p.From), safePrefix(p.To))
		case !from.IsZero() && !from.Equal(statedFrom), !to.IsZero() && !to.Equal(statedTo):
			return fail("the report covers %s to %s, and --from and --to give another period", p.From, p.To)
		case request != nil && (p.RequestTarget == nil || *p.RequestTarget != *request):
			return fail("the report was asked with request target %s, and --target gives %d seconds", targetText(p.RequestTarget), *request)
		}
		from, to, request = statedFrom, statedTo, p.RequestTarget
		last := p.Feed[len(p.Feed)-1].Data.Sequence
		page, _ := json.Marshal(signalFeedPage{Events: p.Feed, NextAfter: last, Newest: last, Head: p.Head})
		feedData = page
	} else if from.IsZero() || to.IsZero() {
		return fail("a feed page that is not a response-time report is measured for the period --from to --to; give both")
	}
	if !to.After(from) {
		return fail("the period must end after it starts")
	}
	c.Feed = checkSignalFeedPinned(feedData, after, ownerKeys, opts)
	if !c.Feed.OK {
		return fail("the feed: %s", c.Feed.Reason)
	}
	head := c.Feed.head
	if head == nil {
		return fail("the feed ends with no head statement, so no result can be shown unsigned as of a head; fetch the feed to its end")
	}
	if stated != nil && stated.Account != c.Feed.Account {
		return fail("the report belongs to %s, and its feed belongs to %s", stated.Account, c.Feed.Account)
	}
	c.Account, c.From, c.To, c.RequestTarget = c.Feed.Account, from.UTC().Format(time.RFC3339Nano), to.UTC().Format(time.RFC3339Nano), request
	c.HeadSequence, c.CompleteAsOf, c.CompleteAge = head.Sequence, c.Feed.CompleteAsOf, c.Feed.CompleteAge
	if c.Feed.ContinuityFrom != "start" {
		c.Notes = append(c.Notes, fmt.Sprintf("the feed given starts at event %d: a sign-off or a deletion before it is not counted; give the feed from its start.", c.Feed.First))
	}
	rep, countErr := feedcount.ResponseTimes(countedEvents(c.Feed.events, head.Sequence), from, to, countHead(head), request)
	if countErr != nil {
		return fail("the feed cannot be counted: %v", countErr)
	}
	c.Results, c.Aggregates = rep.Results, &rep.Aggregates
	if stated != nil {
		c.Differences = responseTimesDifferences(stated, rep)
		if len(c.Differences) > 0 {
			reason := fmt.Sprintf("%d stated figure(s) differ from the recount: %s", len(c.Differences), strings.Join(c.Differences, "; "))
			c.Reason = reason
			return c
		}
	}
	if claims := headClaims(rep.Results); len(claims) > 0 && c.Feed.headAgeErr != nil {
		return fail("the report states %s as of the head of the feed, and the head statement: %v", strings.Join(claims, ", "), c.Feed.headAgeErr)
	}
	c.OK = true
	return c
}

func targetText(t *int64) string {
	if t == nil {
		return "none"
	}
	return fmt.Sprintf("%d seconds", *t)
}

// responseTimesDifferences lists, in plain words, every figure the report
// states that the recount does not reach.
func responseTimesDifferences(stated *responseTimesPack, rep *feedcount.Report) []string {
	var out []string
	if len(stated.Results) != len(rep.Results) {
		out = append(out, fmt.Sprintf("the report lists %d result(s), and the feed holds %d in the period", len(stated.Results), len(rep.Results)))
	}
	for i := 0; i < len(stated.Results) && i < len(rep.Results); i++ {
		for _, d := range fieldDifferences(stated.Results[i], rep.Results[i]) {
			out = append(out, fmt.Sprintf("result %d (run %d): %s", i+1, rep.Results[i].RunID, d))
		}
	}
	for _, d := range fieldDifferences(stated.Aggregates, rep.Aggregates) {
		out = append(out, "aggregates: "+d)
	}
	return out
}

// fieldDifferences compares two values by their JSON fields and says each
// field that differs: stated, then recounted.
func fieldDifferences(stated, recounted any) []string {
	flat := func(v any) map[string]string {
		raw, _ := json.Marshal(v)
		var doc any
		_ = json.Unmarshal(raw, &doc)
		out := map[string]string{}
		var walk func(prefix string, v any)
		walk = func(prefix string, v any) {
			if m, isMap := v.(map[string]any); isMap {
				for k, child := range m {
					name := k
					if prefix != "" {
						name = prefix + "." + k
					}
					walk(name, child)
				}
				return
			}
			text, _ := json.Marshal(v)
			out[prefix] = string(text)
		}
		walk("", doc)
		return out
	}
	a, b := flat(stated), flat(recounted)
	if reflect.DeepEqual(a, b) {
		return nil
	}
	var names []string
	for k := range a {
		names = append(names, k)
	}
	for k := range b {
		if _, both := a[k]; !both {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	var out []string
	for _, k := range names {
		if a[k] != b[k] {
			out = append(out, fmt.Sprintf("%s stated %s, recounted %s", k, orNone(a[k]), orNone(b[k])))
		}
	}
	return out
}

// runResponseTimesMode is --signals with --response-times.
func runResponseTimesMode(path, after, ownerKeyFiles, policyFiles, target, fromFlag, toFlag string, asJSON, allowPartial bool) int {
	point, pointErr := parseSignalPoint(after)
	request, targetErr := parseTargetFlag(target)
	from, fromErr := parseInstantFlag("from", fromFlag)
	to, toErr := parseInstantFlag("to", toFlag)
	documents, documentsErr := readFeedPolicies(policyFiles)
	ownerKeys, keysErr := readOwnerKeys(ownerKeyFiles)
	for _, flagErr := range []error{pointErr, targetErr, fromErr, toErr, documentsErr, keysErr} {
		if flagErr != nil {
			fmt.Fprintln(os.Stderr, "verdifax-verify:", flagErr)
			return 2
		}
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify: read --signals:", readErr)
		return 2
	}
	c := checkResponseTimes(data, point, ownerKeys, documents, request, from, to)
	if asJSON {
		encoded, _ := json.MarshalIndent(c, "", "  ")
		fmt.Println(string(encoded))
	} else {
		printResponseTimes(&c)
	}
	switch {
	case !c.OK:
		return 1
	case c.Feed.CommittedLater > 0 && !allowPartial:
		return 3
	}
	return 0
}

// readOwnerKeys reads --owner-request-key: files of base64 Ed25519 public
// keys, separated by commas.
func readOwnerKeys(files string) ([]string, error) {
	var out []string
	if files == "" {
		return nil, nil
	}
	for _, file := range strings.Split(files, ",") {
		raw, readErr := os.ReadFile(strings.TrimSpace(file))
		if readErr != nil {
			return nil, fmt.Errorf("read --owner-request-key: %w", readErr)
		}
		key := strings.TrimSpace(string(raw))
		if decoded, decodeErr := base64.StdEncoding.DecodeString(key); decodeErr != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("--owner-request-key: %s does not hold a base64 Ed25519 public key", strings.TrimSpace(file))
		}
		out = append(out, key)
	}
	return out, nil
}

// seconds says a measured wait, as measured.
func seconds(n int64) string {
	if n < 0 {
		return fmt.Sprintf("%d s (the later entry reached the public log first; stated as measured)", n)
	}
	return fmt.Sprintf("%d s", n)
}

// standingWords says a result's standing in plain words, never judging it.
func standingWords(s string) string {
	switch s {
	case feedcount.StandingWithinTarget:
		return "within the target"
	case feedcount.StandingLongerSignedAfter:
		return "longer than the target; signed after it"
	case feedcount.StandingUnsignedWithinAsOfHead:
		return "unsigned as of the head, within the target so far"
	case feedcount.StandingUnsignedLongerAsOfHead:
		return "unsigned as of the head, longer than the target"
	case feedcount.StandingSignedNoTarget:
		return "signed; no target applies"
	case feedcount.StandingUnsignedNoTargetAsOfHead:
		return "unsigned as of the head; no target applies"
	}
	return s
}

// endWords says one end point of a result's wait.
func endWords(name string, p *feedcount.EndPoint) string {
	if p == nil {
		return name + " none as of the head"
	}
	text := fmt.Sprintf("%s event %d (%s): record times %s", name, p.Sequence, p.Decision, seconds(p.RecordSeconds))
	if p.LogSeconds != nil {
		text = fmt.Sprintf("%s event %d (%s): %s on the public log, record times %s", name, p.Sequence, p.Decision, seconds(*p.LogSeconds), seconds(p.RecordSeconds))
	}
	return text
}

// spreadWords says one end point's spread on one clock.
func spreadWords(clock string, s *feedcount.Spread) string {
	if s == nil {
		return clock + ": none"
	}
	return fmt.Sprintf("%s: %d result(s), median (lower middle) %s, 90th percentile %s, longest %s (run %d)", clock, s.Count,
		seconds(s.MedianSeconds), seconds(s.P90Seconds), seconds(s.LongestSeconds), s.LongestRunID)
}

// printResponseTimes renders the human report.
func printResponseTimes(c *ResponseTimesCheck) {
	fmt.Println("Verdifax response-time report")
	if !c.OK {
		fmt.Printf("  %-18s✗ FAILED · %s\n", "Response times:", c.Reason)
		for _, d := range c.Differences {
			fmt.Printf("  %-18s%s\n", "Differs:", d)
		}
		return
	}
	what := "measured from the feed alone"
	if c.Recounted {
		what = "every stated figure recounted the same from the report's own feed"
	}
	fmt.Printf("  %-18s✓ %s, %s to %s, up to event %d, complete as of %s (%s)\n", "Response times:", what, c.From, c.To, c.HeadSequence, c.CompleteAsOf, c.CompleteAge)
	if c.RequestTarget != nil {
		fmt.Printf("  %-18s%d seconds, applied to each result that seals no target of its own, compared with its first sign-off\n", "Request target:", *c.RequestTarget)
	}
	for _, r := range c.Results {
		start := "sealed " + r.RecordedAt
		if r.LoggedAt != "" {
			start = "on the public log " + r.LoggedAt + ", sealed " + r.RecordedAt
		}
		target := "no target"
		if r.Target != nil {
			target = fmt.Sprintf("target %d s (%s, compared with %s)", r.Target.Within, r.Target.Source, r.Target.Compare)
		}
		fmt.Printf("    run %d %s (event %d), %s; %s; %s; %s; %s; compared %s on the %s: %s\n", r.RunID, r.ResultKind, r.Sequence, start,
			endWords("first sign-off", r.FirstSignOff), endWords("first approval", r.FirstApproval), endWords("decision in force", r.DecisionInForce),
			target, seconds(r.ComparedSeconds), strings.ReplaceAll(r.ComparedOn, "_", " "), standingWords(r.Standing))
	}
	if a := c.Aggregates; a != nil {
		fmt.Printf("  %-18s%d result(s), %d deleted, %d with a target; %d unsigned as of the head; longer than the target: %d signed after it, %d unsigned as of the head\n",
			"Figures:", a.Results, a.ResultsDeleted, a.WithTarget, a.UnsignedAsOfHead, a.LongerThanTargetSignedAfter, a.LongerThanTargetUnsigned)
		for _, e := range []struct {
			name string
			a    feedcount.EndAggregate
		}{{"first sign-off", a.FirstSignOff}, {"first approval", a.FirstApproval}, {"decision in force", a.DecisionInForce}} {
			fmt.Printf("  %-18s%s reached by %d; %s; %s\n", "Waits:", e.name, e.a.Reached, spreadWords("public log", e.a.PublicLog), spreadWords("record times", e.a.RecordTime))
		}
	}
	for _, n := range append(c.Notes, c.Feed.Notes...) {
		fmt.Printf("  %-18s%s\n", "Note:", n)
	}
	fmt.Println("                    A sign-off shows a registered approver key signed; the times are stated as measured, beside the customer's own target, and judge nothing")
}
